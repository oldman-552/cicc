from concurrent.futures import ThreadPoolExecutor
from threading import Event,Lock
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from backend.tests.test_api import env
from backend.app import main
from backend.app.models import Advisory,Audit,Source


def row(id):return {'id':id,'cve':'CVE-2025-1234','summary':'Synthetic','severity':'high','url':'https://github.com/advisories/'+id,'published_at':'2025-01-01','raw':{}}


@pytest.mark.parametrize('old_fails,new_fails',[(False,False),(True,False),(False,True)])
def test_older_refresh_cannot_overwrite_newer_result(env,monkeypatch,old_fails,new_fails):
    client,factory=env
    first_entered,release=Event(),Event();mutex=Lock();calls=[]
    def collect():
        with mutex:calls.append(1);number=len(calls)
        if number==1:
            first_entered.set()
            if not release.wait(10):raise RuntimeError('test timeout')
            if old_fails:raise ValueError('old failure')
            return [row('old-test')]
        if new_fails:raise ValueError('new failure')
        return [row('new-test')]
    monkeypatch.setattr(main.sources,'github_advisories',collect)
    def refresh():
        with TestClient(main.app,base_url='https://testserver') as c:return c.post('/api/sources/github/refresh')
    with ThreadPoolExecutor(max_workers=2) as pool:
        first=pool.submit(refresh)
        try:
            assert first_entered.wait(10)
            second=pool.submit(refresh);new_response=second.result(timeout=15)
        finally:release.set()
        old_response=first.result(timeout=15)
    assert new_response.status_code==(502 if new_fails else 200)
    assert old_response.status_code==409
    with factory() as db:
        assert db.get(Advisory,'old-test') is None
        assert (db.get(Advisory,'new-test') is None)==new_fails
        source=db.get(Source,'github')
        assert source and (source.error=='new failure' if new_fails else source.error is None)
        assert db.scalar(select(Audit).where(Audit.action=='source.refresh_superseded'))
