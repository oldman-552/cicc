import base64
import os
import pytest
import pyotp
from sqlalchemy import select
from backend.app import accounts,main,mfa
from backend.app.models import Audit,Session,User,UserMfa
from backend.tests.test_api import env

SECRET='JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
PASSWORD='synthetic-password-123456'


def test_totp_encryption_authentication_and_window(monkeypatch):
    monkeypatch.setenv('CICC_MFA_KEY',base64.urlsafe_b64encode(b'a'*32).decode())
    encrypted=mfa.encrypt_secret(1,SECRET)
    assert SECRET.encode() not in encrypted and mfa.decrypt_secret(1,encrypted)==SECRET
    with pytest.raises(mfa.MfaUnavailable):mfa.decrypt_secret(2,encrypted)
    with pytest.raises(mfa.MfaUnavailable):mfa.decrypt_secret(1,encrypted[:-1]+bytes([encrypted[-1]^1]))
    code=pyotp.TOTP(SECRET).generate_otp(100)
    assert mfa.match_counter(SECRET,code,now=3000)==100
    assert mfa.match_counter(SECRET,code,now=3030)==100
    assert mfa.match_counter(SECRET,code,now=3060) is None
    for bad in ('12345','１２３４５６','x'*6,None):assert mfa.match_counter(SECRET,bad,now=3000) is None
    for value in ('','bad',base64.urlsafe_b64encode(b'short').decode()):
        monkeypatch.setenv('CICC_MFA_KEY',value)
        with pytest.raises(mfa.MfaUnavailable):mfa.decrypt_secret(1,encrypted)


def test_mfa_enrollment_login_replay_reset_and_fail_closed(env,monkeypatch,capsys):
    client,factory=env;monkeypatch.setattr(main,'DEMO',False)
    key=base64.urlsafe_b64encode(b'a'*32).decode();monkeypatch.setenv('CICC_MFA_KEY',key)
    clock=[3000];real_match=mfa.match_counter
    monkeypatch.setattr(mfa,'match_counter',lambda secret,code:real_match(secret,code,now=clock[0]))
    with factory.begin() as db:accounts.configure_account(db,'user1',PASSWORD,'admin',1)
    assert client.post('/api/auth/login',json={'username':'user1','password':PASSWORD}).status_code==200
    monkeypatch.setattr(mfa,'SessionLocal',factory)
    monkeypatch.setattr('sys.argv',['mfa','enroll','user1'])
    monkeypatch.setattr(mfa.pyotp,'random_base32',lambda:SECRET)
    monkeypatch.setattr(mfa.getpass,'getpass',lambda prompt:pyotp.TOTP(SECRET).generate_otp(100))
    mfa.main()
    output=capsys.readouterr().out
    assert 'otpauth://' in output and 'MFA enabled' in output
    assert client.get('/api/auth/session').status_code==401
    with factory() as db:
        record=db.scalar(select(UserMfa));assert SECRET.encode() not in record.encrypted_secret and record.last_counter==100
        audits=db.scalars(select(Audit).where(Audit.action=='account.mfa_enabled')).all()
        assert len(audits)==1 and SECRET not in audits[0].detail
    for code in (None,'wrong!',pyotp.TOTP(SECRET).generate_otp(100)):
        assert client.post('/api/auth/login',json={'username':'user1','password':PASSWORD,'otp':code}).status_code==401
    clock[0]=3030;code=pyotp.TOTP(SECRET).generate_otp(101)
    assert client.post('/api/auth/login',json={'username':'user1','password':'incorrect-password','otp':code}).status_code==401
    monkeypatch.setenv('CICC_MFA_KEY',base64.urlsafe_b64encode(b'b'*32).decode())
    assert client.post('/api/auth/login',json={'username':'user1','password':PASSWORD,'otp':code}).status_code==503
    monkeypatch.setenv('CICC_MFA_KEY',key)
    result=client.post('/api/auth/login',json={'username':'user1','password':PASSWORD,'otp':code})
    assert result.status_code==200 and result.json()['mfa_enabled'] is True
    assert client.get('/api/auth/session').json()['mfa_enabled'] is True
    assert client.post('/api/auth/logout',headers={'X-CSRF-Token':client.cookies.get('cicc_csrf')}).status_code==200
    assert client.post('/api/auth/login',json={'username':'user1','password':PASSWORD,'otp':code}).status_code==401
    clock[0]=3060;assert client.post('/api/auth/login',json={'username':'user1','password':PASSWORD,'otp':pyotp.TOTP(SECRET).generate_otp(102)}).status_code==200
    monkeypatch.setattr('sys.argv',['mfa','reset','user1','--confirm-reset']);mfa.main()
    assert client.get('/api/auth/session').status_code==401
    assert client.post('/api/auth/login',json={'username':'user1','password':PASSWORD}).json()['mfa_enabled'] is False
    with factory() as db:
        assert not db.scalar(select(UserMfa))
        assert db.scalar(select(Audit).where(Audit.action=='account.mfa_reset')).workspace_id==1


def test_totp_counter_transaction_rollback_and_lockout(env,monkeypatch):
    client,factory=env;monkeypatch.setattr(main,'DEMO',False)
    monkeypatch.setenv('CICC_MFA_KEY',base64.urlsafe_b64encode(b'a'*32).decode())
    real=mfa.match_counter;clock=[3000];monkeypatch.setattr(mfa,'match_counter',lambda secret,code:real(secret,code,now=clock[0]))
    with factory.begin() as db:
        user=accounts.configure_account(db,'user1',PASSWORD,'admin',1)
        mfa.enroll(db,user,SECRET,pyotp.TOTP(SECRET).generate_otp(100));user_id=user.id
    clock[0]=3030;code=pyotp.TOTP(SECRET).generate_otp(101)
    with pytest.raises(RuntimeError):
        with factory.begin() as db:
            assert mfa.consume_code(db,user_id,db.get(UserMfa,user_id),code)
            raise RuntimeError('synthetic transaction failure')
    with factory() as db:assert db.get(UserMfa,user_id).last_counter==100
    assert client.post('/api/auth/login',json={'username':'user1','password':PASSWORD,'otp':code}).status_code==200
    for _ in range(5):assert client.post('/api/auth/login',json={'username':'user1','password':PASSWORD,'otp':'000000'}).status_code==401
    assert client.post('/api/auth/login',json={'username':'user1','password':PASSWORD,'otp':'000000'}).status_code==429


def test_password_reset_and_disable_reenable_do_not_remove_mfa(env,monkeypatch):
    client,factory=env;monkeypatch.setattr(main,'DEMO',False)
    monkeypatch.setenv('CICC_MFA_KEY',base64.urlsafe_b64encode(b'a'*32).decode())
    real=mfa.match_counter;clock=[3000];monkeypatch.setattr(mfa,'match_counter',lambda secret,code:real(secret,code,now=clock[0]))
    with factory.begin() as db:
        user=accounts.configure_account(db,'user1',PASSWORD,'admin',1)
        mfa.enroll(db,user,SECRET,pyotp.TOTP(SECRET).generate_otp(100))
    with factory.begin() as db:accounts.disable_account(db,'user1',1)
    with factory.begin() as db:accounts.configure_account(db,'user1','replacement-password-123','viewer',1)
    assert client.post('/api/auth/login',json={'username':'user1','password':'replacement-password-123'}).status_code==401
    clock[0]=3030
    response=client.post('/api/auth/login',json={'username':'user1','password':'replacement-password-123','otp':pyotp.TOTP(SECRET).generate_otp(101)})
    assert response.status_code==200 and response.json()['role']=='viewer' and response.json()['mfa_enabled'] is True


def test_failed_enrollment_never_persists_or_revokes_session(env,monkeypatch,capsys):
    client,factory=env;monkeypatch.setattr(main,'DEMO',False)
    monkeypatch.setenv('CICC_MFA_KEY',base64.urlsafe_b64encode(b'a'*32).decode())
    with factory.begin() as db:accounts.configure_account(db,'user1',PASSWORD,'admin',1)
    assert client.post('/api/auth/login',json={'username':'user1','password':PASSWORD}).status_code==200
    monkeypatch.setattr(mfa,'SessionLocal',factory)
    monkeypatch.setattr('sys.argv',['mfa','enroll','user1'])
    monkeypatch.setattr(mfa.pyotp,'random_base32',lambda:SECRET)
    monkeypatch.setattr(mfa.getpass,'getpass',lambda _: 'not-a-code')
    with pytest.raises(SystemExit,match='Invalid authenticator code'):mfa.main()
    capsys.readouterr()
    assert client.get('/api/auth/session').status_code==200
    with factory() as db:
        assert not db.scalar(select(UserMfa))
        assert not db.scalar(select(Audit).where(Audit.action=='account.mfa_enabled'))
    monkeypatch.delenv('CICC_MFA_KEY')
    with pytest.raises(SystemExit,match='key is not configured'):mfa.main()
    assert 'otpauth://' not in capsys.readouterr().out


def test_enforced_mfa_blocks_password_only_and_preexisting_sessions(env,monkeypatch):
    client,factory=env;monkeypatch.setattr(main,'DEMO',False);monkeypatch.setattr(main,'REQUIRE_MFA',False)
    monkeypatch.setenv('CICC_MFA_KEY',base64.urlsafe_b64encode(b'a'*32).decode())
    real=mfa.match_counter;clock=[3000];monkeypatch.setattr(mfa,'match_counter',lambda secret,code:real(secret,code,now=clock[0]))
    with factory.begin() as db:accounts.configure_account(db,'user1',PASSWORD,'admin',1)
    assert client.post('/api/auth/login',json={'username':'user1','password':PASSWORD}).status_code==200
    assert client.get('/api/investigations').status_code==200
    monkeypatch.setattr(main,'REQUIRE_MFA',True)
    assert client.get('/api/auth/session').status_code==401
    assert client.get('/api/investigations').status_code==401
    assert client.post('/api/auth/login',json={'username':'user1','password':PASSWORD}).status_code==401
    with factory.begin() as db:
        user=db.scalar(select(User).where(User.username=='user1'))
        mfa.enroll(db,user,SECRET,pyotp.TOTP(SECRET).generate_otp(100))
    clock[0]=3030
    assert client.post('/api/auth/login',json={'username':'user1','password':PASSWORD,'otp':pyotp.TOTP(SECRET).generate_otp(101)}).status_code==200
    identity=client.get('/api/auth/session').json()
    assert identity['mfa_enabled'] is True and identity['mfa_required'] is True
    with factory.begin() as db:
        user=db.scalar(select(User).where(User.username=='user1'))
        mfa.reset(db,user)
    assert client.get('/api/auth/session').status_code==401
    assert client.post('/api/auth/login',json={'username':'user1','password':PASSWORD}).status_code==401


def test_enrolled_account_rejects_unverified_session_even_without_enforced_policy(env,monkeypatch):
    from backend.app import security
    client,factory=env;monkeypatch.setattr(main,'DEMO',False);monkeypatch.setattr(main,'REQUIRE_MFA',False)
    monkeypatch.setenv('CICC_MFA_KEY',base64.urlsafe_b64encode(b'a'*32).decode())
    real=mfa.match_counter;monkeypatch.setattr(mfa,'match_counter',lambda secret,code:real(secret,code,now=3000))
    with factory.begin() as db:
        user=accounts.configure_account(db,'user1',PASSWORD,'admin',1)
        mfa.enroll(db,user,SECRET,pyotp.TOTP(SECRET).generate_otp(100))
        # Simulate a stale/racing session created without the second factor.
        token,_=security.create_session(db,user.id,mfa_verified=False)
    assert client.get('/api/auth/session',headers={'Cookie':f'cicc_session={token}'}).status_code==401
    assert client.get('/api/investigations',headers={'Cookie':f'cicc_session={token}'}).status_code==401


def test_invalid_mfa_policy_fails_startup(tmp_path):
    import subprocess,sys
    environment={**os.environ,'CICC_REQUIRE_MFA':'true','DATABASE_URL':f'sqlite:///{tmp_path}/invalid.db'}
    result=subprocess.run([sys.executable,'-c','import backend.app.main'],env=environment,capture_output=True,text=True)
    assert result.returncode!=0 and 'CICC_REQUIRE_MFA must be 0 or 1' in result.stderr
