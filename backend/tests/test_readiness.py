from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.app import main
from backend.tests.test_api import env


def test_readiness_checks_connectivity_and_identity_schema_without_auth(env,monkeypatch,tmp_path):
    client,_=env;monkeypatch.setattr(main,'DEMO',False)
    assert client.get('/api/health').status_code==200
    assert client.get('/api/ready').json()=={'status':'ready'}
    assert client.get('/api/investigations').status_code==401
    old_engine=create_engine(f'sqlite:///{tmp_path}/old.db')
    old=sessionmaker(bind=old_engine)
    monkeypatch.setattr(main,'SessionLocal',old)
    response=client.get('/api/ready')
    assert response.status_code==503 and response.json()=={'status':'not_ready'}
    assert response.headers['cache-control']=='no-store'
    old_engine.dispose()


def test_readiness_does_not_return_database_error_details(env,monkeypatch):
    client,_=env
    class Broken:
        def __enter__(self):
            from sqlalchemy.exc import OperationalError
            raise OperationalError('secret connection string',{},Exception('secret'))
        def __exit__(self,*args):pass
    monkeypatch.setattr(main,'SessionLocal',lambda:Broken())
    response=client.get('/api/ready')
    assert response.status_code==503 and 'secret' not in response.text


def test_readiness_fails_closed_for_missing_or_wrong_mfa_key(env,monkeypatch):
    import base64
    import pyotp
    from backend.app import accounts,mfa
    client,factory=env;monkeypatch.setattr(main,'DEMO',False);monkeypatch.setattr(main,'REQUIRE_MFA',True)
    monkeypatch.delenv('CICC_MFA_KEY',raising=False)
    assert client.get('/api/ready').status_code==503
    key=base64.urlsafe_b64encode(b'a'*32).decode();monkeypatch.setenv('CICC_MFA_KEY',key)
    assert client.get('/api/ready').status_code==200
    secret='JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
    with factory.begin() as db:
        user=accounts.configure_account(db,'readyuser','synthetic-password-123456','viewer',1)
        mfa.enroll(db,user,secret,pyotp.TOTP(secret).now())
    assert client.get('/api/ready').status_code==200
    monkeypatch.setenv('CICC_MFA_KEY',base64.urlsafe_b64encode(b'b'*32).decode())
    assert client.get('/api/ready').status_code==503
    monkeypatch.setattr(main,'REQUIRE_MFA',False)
    assert client.get('/api/ready').status_code==503
    monkeypatch.setattr(main,'DEMO',True)
    assert client.get('/api/ready').status_code==200
