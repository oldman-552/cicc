"""Run only against a disposable, pre-migrated PostgreSQL database.

The CI job provides both explicit opt-ins and a temporary service. Tests make
committed writes and must never be pointed at shared or production databases.
"""
import os
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from backend.app import main

URL=os.environ.get('CICC_TEST_POSTGRES_URL','')
ENABLED=(os.environ.get('CICC_TEST_DISPOSABLE_DB')=='1' and URL.startswith('postgresql+') and URL==os.environ.get('DATABASE_URL'))
pytestmark=pytest.mark.skipif(not ENABLED,reason='requires explicitly configured disposable PostgreSQL database')


def test_postgres_transactional_asset_and_sbom_flow(monkeypatch):
    monkeypatch.setattr(main,'DEMO',True)
    unique=uuid4().hex
    with TestClient(main.app,base_url='https://testserver') as client:
        assert client.get('/api/ready').json()=={'status':'ready'}
        asset=client.post('/api/assets',json={'name':'CI '+unique,'asset_type':'application','identifier':unique+'.example.test','owner':'CI','scope_basis':'Disposable CI data only','authorized':True})
        assert asset.status_code==201
        sbom=client.post('/api/sboms',json={'name':'CI '+unique,'document':{'bomFormat':'CycloneDX','components':[{'name':'synthetic','purl':'pkg:pypi/synthetic@1.0'}]}})
        assert sbom.status_code==201
        case=client.post('/api/investigations',json={'title':'CI '+unique})
        assert case.status_code==201
        asset_id,sbom_id,case_id=asset.json()['id'],sbom.json()['id'],case.json()['id']
        assert client.post(f'/api/assets/{asset_id}/sboms',json={'sbom_id':sbom_id,'attested':True}).status_code==201
        assert client.post(f'/api/assets/{asset_id}/sboms',json={'sbom_id':sbom_id,'attested':True}).status_code==409
        assert client.post(f'/api/investigations/{case_id}/assets',json={'asset_id':asset_id}).status_code==201
        result=client.get(f'/api/investigations/{case_id}').json()
        assert result['assets'][0]['snapshot']['verification_status']=='UNVERIFIED'
        assert client.get(f'/api/assets/{asset_id}/sboms').json()['items'][0]['snapshot']['id']==sbom_id


def test_postgres_authenticated_workspace_scope_and_downgrade_guard(monkeypatch):
    """Committed, destructive if misconfigured: the module requires a disposable DB opt-in."""
    import subprocess
    import sys
    from sqlalchemy import select
    from backend.app import security
    from backend.app.db import SessionLocal
    from backend.app.models import Workspace
    from backend.app.workspaces import create_workspace

    monkeypatch.setattr(main,'DEMO',False)
    suffix=uuid4().hex[:16]
    password='synthetic-password-123456'
    with SessionLocal.begin() as db:
        first=create_workspace(db,'ci-a-'+suffix,'CI workspace A')
        second=create_workspace(db,'ci-b-'+suffix,'CI workspace B')
        # These inserts also check that PostgreSQL's workspace sequence was advanced
        # past the default workspace inserted by migration.
        assert first.id!=1 and second.id!=1 and first.id!=second.id
        security.upsert_user(db,'cia'+suffix,password,'admin',workspace_id=first.id)
        security.upsert_user(db,'cib'+suffix,password,'admin',workspace_id=second.id)
    with TestClient(main.app,base_url='https://testserver') as a, TestClient(main.app,base_url='https://testserver') as b:
        for client,username in ((a,'cia'+suffix),(b,'cib'+suffix)):
            result=client.post('/api/auth/login',json={'username':username,'password':password})
            assert result.status_code==200
        ah={'X-CSRF-Token':a.cookies.get('cicc_csrf')};bh={'X-CSRF-Token':b.cookies.get('cicc_csrf')}
        case=a.post('/api/investigations',json={'title':'CI workspace A '+suffix},headers=ah)
        asset=a.post('/api/assets',json={'name':'CI '+suffix,'asset_type':'application','identifier':suffix+'.example.test','owner':'CI','scope_basis':'Disposable test','authorized':True},headers=ah)
        assert case.status_code==201 and asset.status_code==201
        case_id=case.json()['id'];asset_id=asset.json()['id']
        other=b.post('/api/investigations',json={'title':'CI workspace B '+suffix},headers=bh)
        assert other.status_code==201
        assert b.get(f'/api/investigations/{case_id}').status_code==404
        assert b.get(f'/api/assets/{asset_id}').status_code==404
        assert b.post(f"/api/investigations/{other.json()['id']}/assets",json={'asset_id':asset_id},headers=bh).status_code==404
        assert all(x['id']!=case_id for x in b.get('/api/investigations').json())
        assert b.get('/api/audit/events').status_code==200
        assert all(x['actor']!='cia'+suffix for x in b.get('/api/audit/events').json()['items'])
    result=subprocess.run([sys.executable,'-m','alembic','-c','backend/alembic.ini','downgrade','d98dbca43b80'],capture_output=True,text=True,env=os.environ.copy())
    assert result.returncode!=0 and 'Cannot downgrade while additional workspaces' in result.stderr
    with SessionLocal() as db:
        assert db.scalar(select(Workspace).where(Workspace.slug=='ci-a-'+suffix)) is not None


def test_postgres_database_workspace_guards_direct_sql():
    """Exercise migrated constraints, not just ORM checks, on disposable PostgreSQL."""
    from sqlalchemy import inspect, text
    from sqlalchemy.exc import IntegrityError
    from backend.app.db import SessionLocal, engine
    from backend.app.models import Investigation, Asset, Sbom
    from backend.app.workspaces import create_workspace
    suffix=uuid4().hex[:16]
    with SessionLocal.begin() as db:
        a=create_workspace(db,'guard-a-'+suffix,'Guard A')
        b=create_workspace(db,'guard-b-'+suffix,'Guard B')
        case=Investigation(workspace_id=a.id,title='Guard test',status='open')
        asset_a=Asset(workspace_id=a.id,name='A',asset_type='application',identifier='a-'+suffix,owner='test',scope_basis='test',status='active',created_by='test')
        asset_b=Asset(workspace_id=b.id,name='B',asset_type='application',identifier='b-'+suffix,owner='test',scope_basis='test',status='active',created_by='test')
        bom_a=Sbom(workspace_id=a.id,name='A',format='CycloneDX',component_count=0)
        bom_b=Sbom(workspace_id=b.id,name='B',format='CycloneDX',component_count=0)
        db.add_all([case,asset_a,asset_b,bom_a,bom_b]);db.flush()
        ids={'workspace_a':a.id,'workspace_b':b.id,'case':case.id,'asset_a':asset_a.id,'asset_b':asset_b.id,'bom_a':bom_a.id,'bom_b':bom_b.id}
    for table in ('users','investigations','assets','sboms','audit'):
        assert any(x['name']==f'cicc_{table}_workspace_fk' for x in inspect(engine).get_foreign_keys(table))
    with engine.begin() as db:
        db.execute(text("INSERT INTO investigation_assets (investigation_id,asset_id,snapshot,linked_by,linked_at) VALUES (:case,:asset_a,'{}','test',now())"),ids)
        db.execute(text("INSERT INTO asset_sboms (asset_id,sbom_id,snapshot,linked_by,linked_at) VALUES (:asset_a,:bom_a,'{}','test',now())"),ids)
    invalid=[
        "UPDATE investigations SET workspace_id=:workspace_b WHERE id=:case",
        "UPDATE assets SET workspace_id=:workspace_b WHERE id=:asset_a",
        "INSERT INTO investigation_assets (investigation_id,asset_id,snapshot,linked_by,linked_at) VALUES (:case,:asset_b,'{}','test',now())",
        "UPDATE investigation_assets SET asset_id=:asset_b WHERE investigation_id=:case",
        "INSERT INTO asset_sboms (asset_id,sbom_id,snapshot,linked_by,linked_at) VALUES (:asset_a,:bom_b,'{}','test',now())",
        "UPDATE asset_sboms SET sbom_id=:bom_b WHERE asset_id=:asset_a",
        "DELETE FROM workspaces WHERE id=:workspace_a",
    ]
    for sql in invalid:
        with pytest.raises(IntegrityError):
            with engine.begin() as db:db.execute(text(sql),ids)
    with engine.connect() as db:
        assert db.scalar(text('SELECT workspace_id FROM investigations WHERE id=:case'),ids)==ids['workspace_a']
        assert db.scalar(text('SELECT asset_id FROM investigation_assets WHERE investigation_id=:case'),ids)==ids['asset_a']


def test_postgres_local_account_disable_and_audit(monkeypatch):
    from sqlalchemy import select
    from backend.app import accounts
    from backend.app.db import SessionLocal
    from backend.app.models import Audit
    from backend.app.workspaces import create_workspace
    monkeypatch.setattr(main,'DEMO',False)
    suffix=uuid4().hex[:16];username='user'+suffix;password='synthetic-password-123456'
    with SessionLocal.begin() as db:
        workspace=create_workspace(db,'acct-'+suffix,'Account test');workspace_id=workspace.id
        accounts.configure_account(db,username,password,'admin',workspace_id)
    with TestClient(main.app,base_url='https://testserver') as client:
        assert client.post('/api/auth/login',json={'username':username,'password':password}).status_code==200
        with SessionLocal.begin() as db:accounts.disable_account(db,username,workspace_id)
        assert client.get('/api/auth/session').status_code==401
        assert client.post('/api/auth/login',json={'username':username,'password':password}).status_code==401
    with SessionLocal() as db:
        actions=db.scalars(select(Audit.action).where(Audit.workspace_id==workspace_id,Audit.actor=='local-cli').order_by(Audit.id)).all()
        assert actions==['account.configured','account.disabled']


def test_postgres_totp_replay_race_is_rejected(monkeypatch):
    import base64
    from concurrent.futures import ThreadPoolExecutor
    import pyotp
    from backend.app import accounts, mfa
    from backend.app.db import SessionLocal
    from backend.app.workspaces import create_workspace
    monkeypatch.setattr(main,'DEMO',False)
    monkeypatch.setenv('CICC_MFA_KEY',base64.urlsafe_b64encode(b't'*32).decode())
    suffix=uuid4().hex[:16];username='totp'+suffix;password='synthetic-password-123456'
    secret='JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
    real=mfa.match_counter;clock=[6000]
    monkeypatch.setattr(mfa,'match_counter',lambda s,c:real(s,c,now=clock[0]))
    with SessionLocal.begin() as db:
        workspace=create_workspace(db,'totp-'+suffix,'TOTP test')
        user=accounts.configure_account(db,username,password,'admin',workspace.id)
        mfa.enroll(db,user,secret,pyotp.TOTP(secret).generate_otp(200))
    clock[0]=6030;code=pyotp.TOTP(secret).generate_otp(201)
    def login():
        with TestClient(main.app,base_url='https://testserver') as client:
            return client.post('/api/auth/login',json={'username':username,'password':password,'otp':code}).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda _:login(),range(2)))
    assert sorted(results)==[200,401]


def test_postgres_mfa_policy_invalidates_unverified_sessions(monkeypatch):
    import base64
    import pyotp
    from sqlalchemy import select
    from backend.app import accounts, mfa
    from backend.app.db import SessionLocal
    from backend.app.models import Session,User
    from backend.app.workspaces import create_workspace
    monkeypatch.setattr(main,'DEMO',False);monkeypatch.setattr(main,'REQUIRE_MFA',False)
    monkeypatch.setenv('CICC_MFA_KEY',base64.urlsafe_b64encode(b't'*32).decode())
    suffix=uuid4().hex[:16];username='policy'+suffix;password='synthetic-password-123456'
    secret='JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';real=mfa.match_counter;clock=[6000]
    monkeypatch.setattr(mfa,'match_counter',lambda s,c:real(s,c,now=clock[0]))
    with SessionLocal.begin() as db:
        workspace=create_workspace(db,'policy-'+suffix,'Policy test')
        accounts.configure_account(db,username,password,'admin',workspace.id)
    with TestClient(main.app,base_url='https://testserver') as client:
        assert client.post('/api/auth/login',json={'username':username,'password':password}).status_code==200
        monkeypatch.setattr(main,'REQUIRE_MFA',True)
        assert client.get('/api/auth/session').status_code==401
        assert client.post('/api/auth/login',json={'username':username,'password':password}).status_code==401
        with SessionLocal.begin() as db:
            user=db.scalar(select(User).where(User.username==username).with_for_update())
            mfa.enroll(db,user,secret,pyotp.TOTP(secret).generate_otp(200));user_id=user.id
        clock[0]=6030
        assert client.post('/api/auth/login',json={'username':username,'password':password,'otp':pyotp.TOTP(secret).generate_otp(201)}).status_code==200
        assert client.get('/api/auth/session').json()['mfa_enabled'] is True
        with SessionLocal() as db:
            assert db.scalar(select(Session.mfa_verified).where(Session.user_id==user_id)) is True


def test_postgres_revoke_other_sessions_only(monkeypatch):
    from backend.app import accounts
    from backend.app.db import SessionLocal
    from backend.app.workspaces import create_workspace
    monkeypatch.setattr(main,'DEMO',False);monkeypatch.setattr(main,'REQUIRE_MFA',False)
    suffix=uuid4().hex[:16];username='sess'+suffix;othername='other'+suffix;password='synthetic-password-123456'
    with SessionLocal.begin() as db:
        workspace=create_workspace(db,'session-'+suffix,'Session test')
        accounts.configure_account(db,username,password,'viewer',workspace.id)
        accounts.configure_account(db,othername,password,'admin',workspace.id)
    with TestClient(main.app,base_url='https://testserver') as a,TestClient(main.app,base_url='https://testserver') as b,TestClient(main.app,base_url='https://testserver') as c:
        for client,name in ((a,username),(b,username),(c,othername)):
            assert client.post('/api/auth/login',json={'username':name,'password':password}).status_code==200
        response=a.post('/api/auth/sessions/revoke-others',headers={'X-CSRF-Token':a.cookies.get('cicc_csrf')})
        assert response.status_code==200 and response.json()['revoked']==1
        assert a.get('/api/auth/session').status_code==200
        assert b.get('/api/auth/session').status_code==401
        assert c.get('/api/auth/session').status_code==200


def test_postgres_offline_totp_key_rotation(monkeypatch):
    import base64
    import pyotp
    from sqlalchemy import select
    from backend.app import accounts,mfa,security
    from backend.app.db import SessionLocal
    from backend.app.models import Session,UserMfa
    from backend.app.workspaces import create_workspace
    monkeypatch.setattr(main,'DEMO',False);monkeypatch.setattr(main,'REQUIRE_MFA',False)
    old=b't'*32;new=b'n'*32;monkeypatch.setenv('CICC_MFA_KEY',base64.urlsafe_b64encode(old).decode())
    suffix=uuid4().hex[:16];username='rotate'+suffix;password='synthetic-password-123456';secret='JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
    real=mfa.match_counter;clock=[6000];monkeypatch.setattr(mfa,'match_counter',lambda s,c:real(s,c,now=clock[0]))
    with SessionLocal.begin() as db:
        workspace=create_workspace(db,'rotate-'+suffix,'Rotation test')
        user=accounts.configure_account(db,username,password,'admin',workspace.id)
        mfa.enroll(db,user,secret,pyotp.TOTP(secret).generate_otp(200));user_id=user.id
        security.create_session(db,user_id,mfa_verified=True)
    with SessionLocal.begin() as db:assert mfa.rotate_key(db,old,new)>=1
    with SessionLocal() as db:
        record=db.get(UserMfa,user_id)
        assert mfa.decrypt_secret(user_id,record.encrypted_secret,new)==secret
        assert not db.scalars(select(Session).where(Session.user_id==user_id)).all()
    monkeypatch.setenv('CICC_MFA_KEY',base64.urlsafe_b64encode(new).decode());clock[0]=6030
    with TestClient(main.app,base_url='https://testserver') as client:
        assert client.post('/api/auth/login',json={'username':username,'password':password,'otp':pyotp.TOTP(secret).generate_otp(201)}).status_code==200


def test_postgres_login_and_disable_are_serialized(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from sqlalchemy import select
    from backend.app import accounts,security
    from backend.app.db import SessionLocal
    from backend.app.models import Session
    from backend.app.workspaces import create_workspace
    monkeypatch.setattr(main,'DEMO',False);monkeypatch.setattr(main,'REQUIRE_MFA',False)
    suffix=uuid4().hex[:16];username='race'+suffix;password='synthetic-password-123456'
    with SessionLocal.begin() as db:
        workspace=create_workspace(db,'disable-race-'+suffix,'Disable race')
        user=accounts.configure_account(db,username,password,'admin',workspace.id);workspace_id=workspace.id;user_id=user.id
    in_check=Event();release=Event();started_disable=Event();original=security.check_password
    def held_check(value,encoded):
        in_check.set()
        if not release.wait(10):raise RuntimeError('test timeout')
        return original(value,encoded)
    monkeypatch.setattr(security,'check_password',held_check)
    def login():
        with TestClient(main.app,base_url='https://testserver') as client:
            response=client.post('/api/auth/login',json={'username':username,'password':password})
            return response.status_code,client.cookies.get('cicc_session')
    def disable():
        started_disable.set()
        with SessionLocal.begin() as db:accounts.disable_account(db,username,workspace_id)
    with ThreadPoolExecutor(max_workers=2) as pool:
        a=pool.submit(login)
        assert in_check.wait(10)
        b=pool.submit(disable);assert started_disable.wait(10)
        release.set();status,token=a.result(timeout=15);b.result(timeout=15)
    assert status==200 and token
    with SessionLocal() as db:
        assert not db.scalars(select(Session).where(Session.user_id==user_id)).all()
        assert security.get_session(db,token) is None

    # Reverse order: the committed disable wins even if a login is initiated while it is held.
    with SessionLocal.begin() as db:accounts.configure_account(db,username,password,'admin',workspace_id)
    monkeypatch.setattr(security,'check_password',original)
    disabled=Event();release_disable=Event();started_login=Event()
    def hold_disable():
        with SessionLocal.begin() as db:
            accounts.disable_account(db,username,workspace_id);disabled.set()
            if not release_disable.wait(10):raise RuntimeError('test timeout')
    def later_login():
        started_login.set()
        return login()
    with ThreadPoolExecutor(max_workers=2) as pool:
        a=pool.submit(hold_disable);assert disabled.wait(10)
        b=pool.submit(later_login);assert started_login.wait(10)
        release_disable.set();a.result(timeout=15);status,_=b.result(timeout=15)
    assert status==401
    with SessionLocal() as db:assert not db.scalars(select(Session).where(Session.user_id==user_id)).all()


def test_postgres_workspace_deactivation_serializes_with_login(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from sqlalchemy import select
    from backend.app import accounts,security,workspaces
    from backend.app.db import SessionLocal
    from backend.app.models import Session
    monkeypatch.setattr(main,'DEMO',False);monkeypatch.setattr(main,'REQUIRE_MFA',False)
    suffix=uuid4().hex[:16];slug='workspace-race-'+suffix;username='workrace'+suffix;password='synthetic-password-123456'
    with SessionLocal.begin() as db:
        workspace=workspaces.create_workspace(db,slug,'Workspace race')
        user=accounts.configure_account(db,username,password,'admin',workspace.id);user_id=user.id
    in_check=Event();release=Event();started_disable=Event();original=security.check_password
    def held_check(value,encoded):
        in_check.set()
        if not release.wait(10):raise RuntimeError('test timeout')
        return original(value,encoded)
    monkeypatch.setattr(security,'check_password',held_check)
    def login():
        with TestClient(main.app,base_url='https://testserver') as client:
            r=client.post('/api/auth/login',json={'username':username,'password':password})
            return r.status_code,client.cookies.get('cicc_session')
    def disable():
        started_disable.set()
        with SessionLocal.begin() as db:workspaces.set_workspace_active(db,slug,False)
    with ThreadPoolExecutor(max_workers=2) as pool:
        a=pool.submit(login);assert in_check.wait(10)
        b=pool.submit(disable);assert started_disable.wait(10)
        release.set();status,token=a.result(timeout=15);b.result(timeout=15)
    assert status==200 and token
    with SessionLocal.begin() as db:workspaces.set_workspace_active(db,slug,True)
    with SessionLocal() as db:
        assert not db.scalars(select(Session).where(Session.user_id==user_id)).all()
        assert security.get_session(db,token) is None
    monkeypatch.setattr(security,'check_password',original)
    disabled=Event();release_disable=Event();started_login=Event()
    def hold_disable():
        with SessionLocal.begin() as db:
            workspaces.set_workspace_active(db,slug,False);disabled.set()
            if not release_disable.wait(10):raise RuntimeError('test timeout')
    def later_login():started_login.set();return login()
    with ThreadPoolExecutor(max_workers=2) as pool:
        a=pool.submit(hold_disable);assert disabled.wait(10)
        b=pool.submit(later_login);assert started_login.wait(10)
        release_disable.set();a.result(timeout=15);status,_=b.result(timeout=15)
    assert status==401
    with SessionLocal.begin() as db:workspaces.set_workspace_active(db,slug,True)
    with SessionLocal() as db:assert not db.scalars(select(Session).where(Session.user_id==user_id)).all()


def test_postgres_scoped_link_insert_races_parent_delete():
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError
    from backend.app.db import SessionLocal
    from backend.app.models import Asset,Investigation
    from backend.app.workspaces import create_workspace
    suffix=uuid4().hex[:16]
    with SessionLocal.begin() as db:
        workspace=create_workspace(db,'link-race-'+suffix,'Link race')
        case=Investigation(workspace_id=workspace.id,title='Link race',status='open')
        first=Asset(workspace_id=workspace.id,name='First',asset_type='application',identifier='first-'+suffix,owner='test',scope_basis='test',status='active',created_by='test')
        second=Asset(workspace_id=workspace.id,name='Second',asset_type='application',identifier='second-'+suffix,owner='test',scope_basis='test',status='active',created_by='test')
        db.add_all([case,first,second]);db.flush();case_id=case.id;first_id=first.id;second_id=second.id
    inserted=Event();delete_started=Event();release=Event()
    def insert_first():
        with SessionLocal.begin() as db:
            db.execute(text("INSERT INTO investigation_assets(investigation_id,asset_id,snapshot,linked_by,linked_at) VALUES (:case,:asset,'{}','test',NOW())"),{'case':case_id,'asset':first_id})
            inserted.set()
            if not release.wait(10):raise RuntimeError('test timeout')
    def delete_first():
        delete_started.set()
        try:
            with SessionLocal.begin() as db:db.execute(text('DELETE FROM assets WHERE id=:asset'),{'asset':first_id})
        except IntegrityError:return False
        return True
    with ThreadPoolExecutor(max_workers=2) as pool:
        a=pool.submit(insert_first);assert inserted.wait(10)
        b=pool.submit(delete_first);assert delete_started.wait(10);release.set()
        a.result(timeout=15);deleted=b.result(timeout=15)
    assert not deleted
    deleted=Event();insert_started=Event();release_delete=Event()
    def delete_second():
        with SessionLocal.begin() as db:
            db.execute(text('DELETE FROM assets WHERE id=:asset'),{'asset':second_id});deleted.set()
            if not release_delete.wait(10):raise RuntimeError('test timeout')
    def insert_second():
        insert_started.set()
        try:
            with SessionLocal.begin() as db:
                db.execute(text("INSERT INTO investigation_assets(investigation_id,asset_id,snapshot,linked_by,linked_at) VALUES (:case,:asset,'{}','test',NOW())"),{'case':case_id,'asset':second_id})
        except IntegrityError:return False
        return True
    with ThreadPoolExecutor(max_workers=2) as pool:
        a=pool.submit(delete_second);assert deleted.wait(10)
        b=pool.submit(insert_second);assert insert_started.wait(10);release_delete.set()
        a.result(timeout=15);linked=b.result(timeout=15)
    assert not linked
    with SessionLocal() as db:
        assert db.scalar(text('SELECT count(*) FROM investigation_assets WHERE investigation_id=:case AND asset_id=:asset'),{'case':case_id,'asset':first_id})==1
        assert db.scalar(text('SELECT count(*) FROM investigation_assets WHERE investigation_id=:case AND asset_id=:asset'),{'case':case_id,'asset':second_id})==0
