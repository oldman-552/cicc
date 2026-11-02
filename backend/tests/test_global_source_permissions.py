import os
import subprocess
import sys
import pytest
from fastapi.testclient import TestClient
from backend.tests.test_api import env
from backend.app import accounts,main
from backend.app.models import Workspace


def test_global_refresh_requires_explicit_operator_and_admin(env,monkeypatch):
    first,factory=env;monkeypatch.setattr(main,'DEMO',False)
    monkeypatch.setattr(main,'SOURCE_OPERATORS',frozenset({'alpha','charlie'}))
    with factory.begin() as db:
        db.add(Workspace(id=2,slug='other',name='Other',active=True));db.flush()
        for username,role,ws in [('alpha','admin',1),('bravo','admin',2),('charlie','analyst',2)]:
            accounts.configure_account(db,username,'synthetic-password-123456',role,ws)
    calls=[]
    def sample():
        calls.append(1)
        return [{'id':'GHSA-test-test-test','cve':'CVE-2025-1234','summary':'Synthetic','severity':'high','url':'https://github.com/advisories/GHSA-test-test-test','published_at':'2025-01-01','raw':{}}]
    monkeypatch.setattr(main.sources,'github_advisories',sample)
    with TestClient(main.app,base_url='https://testserver') as second,TestClient(main.app,base_url='https://testserver') as third:
        for client,name,allowed in ((first,'alpha',True),(second,'bravo',False),(third,'charlie',False)):
            response=client.post('/api/auth/login',json={'username':name,'password':'synthetic-password-123456'})
            assert response.status_code==200 and response.json()['can_refresh_global_sources']==allowed
            assert client.get('/api/auth/session').json()['can_refresh_global_sources']==allowed
        for client in (second,third):
            assert client.post('/api/sources/github/refresh',headers={'X-CSRF-Token':client.cookies.get('cicc_csrf')}).status_code==403
        assert calls==[]
        assert first.post('/api/sources/github/refresh').status_code==403
        assert first.post('/api/sources/github/refresh',headers={'X-CSRF-Token':first.cookies.get('cicc_csrf')}).status_code==200
        assert calls==[1]
        assert second.get('/api/advisories').json()['total']==1  # the cache remains global
        monkeypatch.setattr(main,'SOURCE_OPERATORS',frozenset())
        assert first.get('/api/auth/session').json()['can_refresh_global_sources'] is False
        assert first.post('/api/sources/github/refresh',headers={'X-CSRF-Token':first.cookies.get('cicc_csrf')}).status_code==403


def test_global_operator_config_is_bounded_and_fail_closed(tmp_path):
    assert main.parse_source_operators('  Alice,BOB ') == frozenset({'alice','bob'})
    assert main.parse_source_operators('')==frozenset()
    for value in (',bob','alice,','   ','@invalid',','.join(['abc']*101),'a'*4097):
        with pytest.raises(RuntimeError):main.parse_source_operators(value)
    envvars={**os.environ,'CICC_GLOBAL_SOURCE_OPERATORS':'broken,', 'DATABASE_URL':f'sqlite:///{tmp_path}/none.db'}
    result=subprocess.run([sys.executable,'-c','import backend.app.main'],env=envvars,capture_output=True,text=True)
    assert result.returncode!=0 and 'Invalid CICC_GLOBAL_SOURCE_OPERATORS' in result.stderr
