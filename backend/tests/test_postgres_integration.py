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
