"""Adversarial application-level scope checks; these do not certify tenant isolation."""
import pytest
from fastapi.testclient import TestClient
from backend.app import main,security
from backend.app.models import Workspace
from backend.tests.test_api import env  # reuse the isolated SQLite app fixture


def login(client,name):
    result=client.post('/api/auth/login',json={'username':name,'password':'test-password-long-123'})
    assert result.status_code==200
    return {'X-CSRF-Token':client.cookies.get('cicc_csrf')},result.json()


def test_cross_workspace_access_and_association_are_denied(env,monkeypatch):
    first,factory=env;monkeypatch.setattr(main,'DEMO',False)
    with factory.begin() as db:
        db.add(Workspace(id=2,slug='other',name='Other workspace',active=True));db.flush()
        security.upsert_user(db,'alpha','test-password-long-123','admin',workspace_id=1)
        security.upsert_user(db,'bravo','test-password-long-123','admin',workspace_id=2)
    with TestClient(main.app,base_url='https://testserver') as second:
        ah,ai=login(first,'alpha');bh,bi=login(second,'bravo')
        assert ai['workspace']['slug']=='default' and bi['workspace']['slug']=='other'
        case=first.post('/api/investigations',json={'title':'Alpha confidential case'},headers=ah).json()
        asset=first.post('/api/assets',json={'name':'Alpha private asset','asset_type':'domain','identifier':'alpha.example.test','owner':'Alpha','scope_basis':'Test scope','authorized':True},headers=ah).json()
        bom=first.post('/api/sboms',json={'name':'Alpha private SBOM','document':{'bomFormat':'CycloneDX','components':[]}},headers=ah).json()
        first.post(f"/api/investigations/{case['id']}/assets",json={'asset_id':asset['id']},headers=ah)
        second_case=second.post('/api/investigations',json={'title':'Bravo confidential case'},headers=bh).json()
        second_asset=second.post('/api/assets',json={'name':'Bravo private asset','asset_type':'domain','identifier':'bravo.example.test','owner':'Bravo','scope_basis':'Test scope','authorized':True},headers=bh).json()
        second_bom=second.post('/api/sboms',json={'name':'Bravo private SBOM','document':{'bomFormat':'CycloneDX','components':[]}},headers=bh).json()
        assert [x['id'] for x in first.get('/api/investigations').json()]==[case['id']]
        assert [x['id'] for x in second.get('/api/investigations').json()]==[second_case['id']]
        assert first.get('/api/overview').json()['open_investigations']==1
        assert second.get('/api/overview').json()['open_investigations']==1
        assert first.get('/api/assets').json()['total']==second.get('/api/assets').json()['total']==1
        assert [x['id'] for x in first.get('/api/sboms').json()]==[bom['id']]
        assert [x['id'] for x in second.get('/api/sboms').json()]==[second_bom['id']]
        for url in (f"/api/investigations/{case['id']}",f"/api/investigations/{case['id']}/report",f"/api/investigations/{case['id']}/timeline",f"/api/assets/{asset['id']}",f"/api/assets/{asset['id']}/sboms",f"/api/sboms/{bom['id']}"):
            assert second.get(url).status_code==404,url
        assert second.patch(f"/api/investigations/{case['id']}",json={'status':'closed'},headers=bh).status_code==404
        assert second.post(f"/api/investigations/{case['id']}/notes",json={'content':'No access','classification':'UNKNOWN'},headers=bh).status_code==404
        assert second.patch(f"/api/assets/{asset['id']}",json={'status':'retired'},headers=bh).status_code==404
        assert second.post(f"/api/investigations/{second_case['id']}/assets",json={'asset_id':asset['id']},headers=bh).status_code==404
        assert first.post(f"/api/investigations/{case['id']}/assets",json={'asset_id':second_asset['id']},headers=ah).status_code==404
        assert second.post(f"/api/assets/{second_asset['id']}/sboms",json={'sbom_id':bom['id'],'attested':True},headers=bh).status_code==404
        assert first.post(f"/api/assets/{asset['id']}/sboms",json={'sbom_id':second_bom['id'],'attested':True},headers=ah).status_code==404
        assert 'Alpha confidential case' not in str(second.get('/api/graph').json())
        assert 'bravo' not in str(first.get('/api/audit').json())
        assert 'alpha' not in str(second.get('/api/audit').json())
        assert second.get('/api/auth/session').json()['workspace']['slug']=='other'
        with factory.begin() as db: db.get(Workspace,2).active=False
        assert second.get('/api/auth/session').status_code==401
        assert second.get('/api/investigations').status_code==401
        assert second.post('/api/auth/login',json={'username':'bravo','password':'test-password-long-123'}).status_code==401


def test_account_workspace_moves_are_rejected(env):
    _,factory=env
    with factory.begin() as db:
        db.add(Workspace(id=2,slug='other',name='Other workspace',active=True));db.flush()
        security.upsert_user(db,'alpha','test-password-long-123','analyst',workspace_id=1)
        with pytest.raises(ValueError,match='Moving'):security.upsert_user(db,'alpha','new-password-long-123','analyst',workspace_id=2)


def test_orm_rejects_unscoped_inserts_and_workspace_moves(env):
    from backend.app.models import Investigation
    _,factory=env
    with pytest.raises(ValueError,match='Explicit workspace_id'):
        with factory.begin() as db: db.add(Investigation(title='Unscoped test',status='open'))
    with factory.begin() as db:
        case=Investigation(title='Scoped test',status='open',workspace_id=1);db.add(case);db.flush();case_id=case.id
    with pytest.raises(ValueError,match='Moving records'):
        with factory.begin() as db: db.get(Investigation,case_id).workspace_id=2


def test_workspace_slug_validation_and_duplicates(env):
    from backend.app.workspaces import create_workspace
    _,factory=env
    with factory.begin() as db:
        assert create_workspace(db,' A-1 ',' Team ').slug=='a-1'
        for slug in ('','-bad','bad-','two--hyphens','x'*41,'bad space'):
            with pytest.raises(ValueError,match='slug'): create_workspace(db,slug,'Test')
        with pytest.raises(ValueError,match='already exists'): create_workspace(db,'A-1','Duplicate')


def test_audit_pagination_filter_and_permissions(env,monkeypatch):
    from backend.app.models import Audit
    client,factory=env;monkeypatch.setattr(main,'DEMO',False)
    with factory.begin() as db:
        db.add(Workspace(id=2,slug='other',name='Other',active=True));db.flush()
        security.upsert_user(db,'alpha','test-password-long-123','admin',workspace_id=1)
        security.upsert_user(db,'viewer','test-password-long-123','viewer',workspace_id=1)
        db.add_all([Audit(actor='alpha',action='source.refresh',detail=str(i),workspace_id=1) for i in range(5)])
        db.add(Audit(actor='foreign',action='source.refresh',detail='private',workspace_id=2))
        db.add(Audit(actor='unknown',action='auth.login_failed',detail='',workspace_id=None))
    login(client,'alpha')
    first=client.get('/api/audit/events?limit=2&action=source.refresh').json()
    second=client.get(f"/api/audit/events?limit=2&action=source.refresh&before={first['next_before']}").json()
    third=client.get(f"/api/audit/events?limit=2&action=source.refresh&before={second['next_before']}").json()
    events=first['items']+second['items']+third['items']
    assert len(events)==5 and len({x['id'] for x in events})==5 and third['next_before'] is None
    assert all(x['actor']=='alpha' for x in events) and first['limitations']
    assert client.get('/api/audit/events?limit=101').status_code==422
    login(client,'viewer')
    assert client.get('/api/audit').status_code==403
    assert client.get('/api/audit/events').status_code==403
