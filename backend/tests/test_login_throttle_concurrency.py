from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from fastapi.testclient import TestClient
from backend.app import main,security
from backend.app.models import LoginAttempt
from backend.tests.test_api import env
from sqlalchemy import func,select


def test_concurrent_login_limits_are_serialized_on_sqlite(env,monkeypatch):
    _,factory=env;monkeypatch.setattr(main,'DEMO',False)
    monkeypatch.setattr(security,'check_password',lambda *_:False)
    def run(n,username,host):
        barrier=Barrier(n)
        def login(i):
            barrier.wait(timeout=15)
            with TestClient(main.app,base_url='https://testserver',client=(host(i),50000)) as client:
                return client.post('/api/auth/login',json={'username':username(i),'password':'wrong'}).status_code
        with ThreadPoolExecutor(max_workers=n) as pool:return list(pool.map(login,range(n)))
    account='parallel-account'
    statuses=run(10,lambda _:account,lambda i:f'198.51.100.{i+1}')
    assert statuses.count(401)==5 and statuses.count(429)==5
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(LoginAttempt).where(LoginAttempt.account_hash==security.digest(account)))==5
    statuses=run(31,lambda i:f'unknown-{i}',lambda _:'203.0.113.123')
    assert statuses.count(401)==30 and statuses.count(429)==1
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(LoginAttempt).where(LoginAttempt.client_hash==security.digest('203.0.113.123')))==30


def test_login_fails_closed_if_throttle_lock_unavailable(env,monkeypatch):
    client,factory=env;monkeypatch.setattr(main,'DEMO',False)
    def unavailable(*args):raise ValueError('unsupported database')
    monkeypatch.setattr(security,'lock_login_limits',unavailable)
    assert client.post('/api/auth/login',json={'username':'test','password':'wrong'}).status_code==503
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(LoginAttempt))==0
