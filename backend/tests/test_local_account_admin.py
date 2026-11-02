import pytest
from sqlalchemy import select
from backend.app import accounts, main
from backend.app.models import Audit, Session, Workspace
from backend.tests.test_api import env


def test_account_disabling_revokes_sessions_and_audits_without_password(env,monkeypatch):
    client,factory=env;monkeypatch.setattr(main,'DEMO',False)
    password='synthetic-password-123456'
    with factory.begin() as db:
        db.add(Workspace(id=2,slug='other',name='Other',active=True));db.flush()
        accounts.configure_account(db,'user1',password,'analyst',1)
    result=client.post('/api/auth/login',json={'username':'user1','password':password});assert result.status_code==200
    with pytest.raises(ValueError,match='not found in workspace'):
        with factory.begin() as db:accounts.disable_account(db,'user1',2)
    assert client.get('/api/auth/session').status_code==200
    with factory.begin() as db:accounts.disable_account(db,'user1',1)
    assert client.get('/api/auth/session').status_code==401
    assert client.post('/api/auth/login',json={'username':'user1','password':password}).status_code==401
    with factory() as db:
        assert not db.scalars(select(Session)).all()
        records=db.scalars(select(Audit).where(Audit.action.in_(['account.configured','account.disabled'])).order_by(Audit.id)).all()
        assert [x.action for x in records]==['account.configured','account.disabled']
        assert all(x.workspace_id==1 and x.actor=='local-cli' and password not in x.detail for x in records)


def test_account_changes_and_audit_roll_back_together(env):
    _,factory=env
    with pytest.raises(RuntimeError):
        with factory.begin() as db:
            accounts.configure_account(db,'rollback','synthetic-password-123456','viewer',1)
            raise RuntimeError('synthetic failure')
    with factory() as db:
        assert not db.scalars(select(Audit).where(Audit.action=='account.configured')).all()
        from backend.app.models import User
        assert not db.scalar(select(User).where(User.username=='rollback'))


def test_cli_disable_does_not_prompt_for_password_and_logs(env,monkeypatch,capsys):
    client,factory=env;monkeypatch.setattr(main,'DEMO',False)
    with factory.begin() as db:accounts.configure_account(db,'user1','synthetic-password-123456','analyst',1)
    monkeypatch.setattr(accounts,'SessionLocal',factory)
    monkeypatch.setattr('sys.argv',['accounts','user1','--disable'])
    def forbidden(*args):raise AssertionError('password prompt on disable')
    monkeypatch.setattr(accounts.getpass,'getpass',forbidden)
    accounts.main()
    assert 'sessions revoked' in capsys.readouterr().out
    assert client.post('/api/auth/login',json={'username':'user1','password':'synthetic-password-123456'}).status_code==401


def test_cli_configure_prompts_and_revokes_old_sessions(env,monkeypatch,capsys):
    client,factory=env;monkeypatch.setattr(main,'DEMO',False)
    with factory.begin() as db:accounts.configure_account(db,'user1','synthetic-password-123456','analyst',1)
    assert client.post('/api/auth/login',json={'username':'user1','password':'synthetic-password-123456'}).status_code==200
    monkeypatch.setattr(accounts,'SessionLocal',factory)
    monkeypatch.setattr('sys.argv',['accounts','user1','--role','viewer'])
    monkeypatch.setattr(accounts.getpass,'getpass',lambda prompt:'replacement-password-123')
    accounts.main()
    assert 'replacement-password-123' not in capsys.readouterr().out
    assert client.get('/api/auth/session').status_code==401
    assert client.post('/api/auth/login',json={'username':'user1','password':'replacement-password-123'}).json()['role']=='viewer'


def test_workspace_cli_audits_creation_after_commit(env,monkeypatch,capsys):
    from backend.app import workspaces
    _,factory=env
    monkeypatch.setattr(workspaces,'SessionLocal',factory)
    monkeypatch.setattr('sys.argv',['workspaces','research','Research'])
    workspaces.main()
    assert 'Created workspace research' in capsys.readouterr().out
    with factory() as db:
        workspace=db.scalar(select(Workspace).where(Workspace.slug=='research'))
        audit=db.scalar(select(Audit).where(Audit.action=='workspace.created'))
        assert audit.workspace_id==workspace.id and audit.actor=='local-cli' and audit.detail=='research'


@pytest.mark.parametrize('unknown_role',['unexpected','','ADMIN','admin '])
def test_invalid_database_role_fails_closed_for_login_and_existing_session(env,monkeypatch,unknown_role):
    from sqlalchemy import update
    from backend.app.models import User
    client,factory=env;monkeypatch.setattr(main,'DEMO',False)
    password='synthetic-password-123456'
    with factory.begin() as db:accounts.configure_account(db,'badrole',password,'viewer',1)
    assert client.post('/api/auth/login',json={'username':'badrole','password':password}).status_code==200
    with factory.begin() as db:db.execute(update(User).where(User.username=='badrole').values(role=unknown_role))
    assert client.get('/api/auth/session').status_code==401
    assert client.get('/api/investigations').status_code==401
    assert client.post('/api/investigations',json={'title':'Forbidden'},headers={'X-CSRF-Token':client.cookies.get('cicc_csrf')}).status_code==401
    assert client.post('/api/auth/login',json={'username':'badrole','password':password}).status_code==401
    # Trusted account administration repairs the role and revokes prior sessions.
    with factory.begin() as db:accounts.configure_account(db,'badrole',password,'viewer',1)
    assert client.get('/api/auth/session').status_code==401
