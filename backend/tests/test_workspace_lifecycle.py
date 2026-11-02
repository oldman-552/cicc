import pytest
from sqlalchemy import select
from backend.tests.test_api import env
from backend.app import accounts,main,security,workspaces
from backend.app.models import Audit,Session,Workspace


def test_workspace_lifecycle_revokes_only_its_sessions_and_does_not_revive(env,monkeypatch):
    client,factory=env;monkeypatch.setattr(main,'DEMO',False)
    password='synthetic-password-123456'
    with factory.begin() as db:
        other=workspaces.create_workspace(db,'other','Other')
        first=accounts.configure_account(db,'oneuser',password,'admin',1)
        second=accounts.configure_account(db,'twouser',password,'admin',other.id)
        first_id,second_id=first.id,second.id
        security.create_session(db,second_id)
    assert client.post('/api/auth/login',json={'username':'oneuser','password':password}).status_code==200
    with factory.begin() as db:workspaces.set_workspace_active(db,'default',False)
    assert client.get('/api/auth/session').status_code==401
    with factory() as db:
        assert not db.scalars(select(Session).where(Session.user_id==first_id)).all()
        assert len(db.scalars(select(Session).where(Session.user_id==second_id)).all())==1
    with factory.begin() as db:workspaces.set_workspace_active(db,'default',True)
    assert client.get('/api/auth/session').status_code==401
    assert client.post('/api/auth/login',json={'username':'oneuser','password':password}).status_code==200
    with factory() as db:
        assert list(db.scalars(select(Audit.action).where(Audit.action.in_(['workspace.disabled','workspace.enabled'])).order_by(Audit.id)))==['workspace.disabled','workspace.enabled']


def test_workspace_lifecycle_transaction_rolls_back(env):
    _,factory=env
    with factory.begin() as db:
        user=accounts.configure_account(db,'rolluser','synthetic-password-123456','admin',1)
        security.create_session(db,user.id);user_id=user.id
    with pytest.raises(RuntimeError):
        with factory.begin() as db:
            workspaces.set_workspace_active(db,'default',False)
            raise RuntimeError('synthetic failure')
    with factory() as db:
        assert db.get(Workspace,1).active
        assert len(db.scalars(select(Session).where(Session.user_id==user_id)).all())==1
        assert not db.scalar(select(Audit).where(Audit.action=='workspace.disabled'))
