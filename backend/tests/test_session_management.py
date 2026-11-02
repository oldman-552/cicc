from fastapi.testclient import TestClient
from backend.app import main,security
from backend.tests.test_api import env

PASSWORD='synthetic-password-123456'


def test_users_can_revoke_only_their_other_sessions_with_csrf(env,monkeypatch):
    first,factory=env;monkeypatch.setattr(main,'DEMO',False);monkeypatch.setattr(main,'REQUIRE_MFA',False)
    with factory.begin() as db:
        security.upsert_user(db,'viewer',PASSWORD,'viewer',1)
        security.upsert_user(db,'other',PASSWORD,'admin',1)
    with TestClient(main.app,base_url='https://testserver') as second,TestClient(main.app,base_url='https://testserver') as other:
        for client,name in ((first,'viewer'),(second,'viewer'),(other,'other')):
            assert client.post('/api/auth/login',json={'username':name,'password':PASSWORD}).status_code==200
        assert first.post('/api/auth/sessions/revoke-others').status_code==403
        csrf={'X-CSRF-Token':first.cookies.get('cicc_csrf')}
        response=first.post('/api/auth/sessions/revoke-others',headers=csrf)
        assert response.status_code==200 and response.json()['revoked']==1
        assert first.get('/api/auth/session').status_code==200
        assert second.get('/api/auth/session').status_code==401
        assert other.get('/api/auth/session').status_code==200
        records=other.get('/api/audit/events?action=auth.sessions_revoked').json()['items']
        assert len(records)==1 and records[0]['actor']=='viewer' and records[0]['detail']=='1 other sessions'
        assert first.post('/api/auth/sessions/revoke-others',headers=csrf).json()['revoked']==0


def test_session_management_is_unavailable_in_demo(env):
    client,_=env
    assert client.post('/api/auth/sessions/revoke-others').status_code==400
