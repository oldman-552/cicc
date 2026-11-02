import httpx
import pytest
from fastapi.testclient import TestClient
from backend.app import main

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'DB', str(tmp_path / 'test.db'))
    with TestClient(main.app) as c:
        yield c

def test_health_and_empty_source(client):
    assert client.get('/api/health').json()['authentication'] == 'not configured'
    assert client.get('/api/advisories').json() == []
    assert client.get('/api/sources').json()[0]['status'] == 'not_connected'

def test_investigation_lifecycle_and_audit(client):
    assert client.post('/api/investigations', json={'title':'  '}).status_code == 422
    created = client.post('/api/investigations', json={'title':' Test investigation '})
    assert created.status_code == 201
    item = created.json()
    assert item['title'] == 'Test investigation' and item['status'] == 'open'
    assert client.patch(f"/api/investigations/{item['id']}", json={'status':'closed'}).json()['status'] == 'closed'
    assert client.patch('/api/investigations/999', json={'status':'closed'}).status_code == 404
    assert client.patch(f"/api/investigations/{item['id']}", json={'status':'invalid'}).status_code == 422
    assert len(client.get('/api/audit').json()) == 2

def test_source_refresh_search_and_failure_retains_cache(client, monkeypatch):
    def good(*args, **kwargs):
        return httpx.Response(200, request=httpx.Request('GET','https://api.github.com/advisories'), json=[{'ghsa_id':'GHSA-test-test-test', 'html_url':'https://github.com/advisories/GHSA-test-test-test','summary':'Example advisory','severity':'high','published_at':'2025-01-01T00:00:00Z','identifiers':[{'type':'CVE','value':'CVE-2025-1234'}]}])
    monkeypatch.setattr(main.httpx, 'get', good)
    assert client.post('/api/sources/github/refresh').json()['imported'] == 1
    item = client.get('/api/advisories',params={'q':'CVE-2025'}).json()[0]
    assert item['classification'] == 'SOURCE-REPORTED' and item['data_state'] == 'CACHED'
    assert client.get('/api/advisories',params={'q':'missing'}).json() == []
    assert client.get('/api/sources').json()[0]['status'] == 'cached'
    def fail(*args, **kwargs):
        raise httpx.ConnectError('offline')
    monkeypatch.setattr(main.httpx, 'get', fail)
    assert client.post('/api/sources/github/refresh').status_code == 502
    status = client.get('/api/sources').json()[0]
    assert status['status'] == 'error' and status['last_success'] and status['count'] == 1
    assert len(client.get('/api/advisories').json()) == 1
