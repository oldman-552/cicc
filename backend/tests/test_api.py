import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.app import main, security
from backend.app.db import Base, get_db
from backend.app.models import Source, Workspace

@pytest.fixture
def env(tmp_path,monkeypatch):
    engine=create_engine(f'sqlite:///{tmp_path}/test.db',connect_args={'check_same_thread':False})
    Base.metadata.create_all(engine)
    factory=sessionmaker(bind=engine,expire_on_commit=False)
    with factory.begin() as db: db.add(Workspace(id=1,slug='default',name='Default test workspace',active=True))
    def override():
        with factory() as db: yield db
    main.app.dependency_overrides[get_db]=override
    monkeypatch.setattr(main,'SessionLocal',factory)
    monkeypatch.setattr(main,'DEMO',True)
    with TestClient(main.app,base_url='https://testserver') as client:
        yield client,factory
    main.app.dependency_overrides.clear(); engine.dispose()

def test_investigation_evidence_and_reports(env,monkeypatch):
    client,_=env
    data=[{'id':'GHSA-test-test-test','cve':'CVE-2025-1234','summary':'Original source','severity':'high','url':'https://github.com/advisories/GHSA-test-test-test','published_at':'2025-01-01','raw':{}}]
    monkeypatch.setattr(main.sources,'github_advisories',lambda:data)
    assert client.post('/api/sources/github/refresh').json()['imported']==1
    assert client.get('/api/advisories?q=CVE-2025').json()['items'][0]['kev_status']=='UNKNOWN'
    i=client.post('/api/investigations',json={'title':'Test investigation'}).json(); path=f"/api/investigations/{i['id']}"
    assert client.post(path+'/evidence',json={'advisory_id':data[0]['id']}).status_code==201
    assert client.post(path+'/evidence',json={'advisory_id':data[0]['id']}).status_code==409
    assert client.post(path+'/notes',json={'content':'Potential issue','classification':'HYPOTHESIS'}).status_code==201
    assert client.post(path+'/notes',json={'content':'abc','classification':'VERIFIED'}).status_code==422
    data[0]['summary']='Changed source'; client.post('/api/sources/github/refresh')
    assert client.get(path).json()['evidence'][0]['snapshot']['summary']=='Original source'
    assert client.get(path+'/report').json()['limitations']
    graph=client.get('/api/graph').json(); assert len(graph['edges'])==1 and graph['edges'][0]['type']=='REFERENCES'
    assert client.patch(path,json={'status':'closed'}).json()['status']=='closed'
    assert client.get('/api/investigations/999').status_code==404

def test_kev_snapshot_refresh_and_failure(env,monkeypatch):
    client,_=env
    data={'items':[{'cve':'CVE-2025-1234','vendor':'Vendor','product':'Product','title':'Example','date_added':'2025-01-01','description':'Description','action':'Update','due_date':'2025-02-01','ransomware':'Unknown'}],'version':'v1','released_at':'2025-01-01','reference':'a'*40}
    monkeypatch.setattr(main.sources,'cisa_kev',lambda:data)
    assert client.post('/api/sources/cisa/refresh').json()['imported']==1
    assert client.get('/api/kev?q=Vendor').json()['total']==1
    def fail(): raise ValueError('offline')
    monkeypatch.setattr(main.sources,'cisa_kev',fail)
    assert client.post('/api/sources/cisa/refresh').status_code==502
    assert client.get('/api/kev').json()['total']==1
    assert client.get('/api/sources').json()[1]['status']=='error'

def test_auth_roles_csrf_and_session_revocation(env,monkeypatch):
    client,factory=env; monkeypatch.setattr(main,'DEMO',False)
    with factory.begin() as db:
        security.upsert_user(db,'admin','long-password-test-123','admin')
        security.upsert_user(db,'viewer','long-password-test-123','viewer')
    assert client.get('/api/advisories').status_code==401
    assert client.post('/api/auth/login',json={'username':'admin','password':'wrong'}).status_code==401
    r=client.post('/api/auth/login',json={'username':'admin','password':'long-password-test-123'}); assert r.status_code==200
    assert any('HttpOnly' in x and 'Secure' in x for x in r.headers.get_list('set-cookie'))
    assert client.post('/api/investigations',json={'title':'Test title'}).status_code==403
    csrf={'X-CSRF-Token':client.cookies.get('cicc_csrf')}
    assert client.post('/api/investigations',json={'title':'Test title'},headers=csrf).status_code==201
    assert client.post('/api/auth/logout',headers=csrf).status_code==200
    assert client.post('/api/auth/login',json={'username':'viewer','password':'long-password-test-123'}).status_code==200
    csrf={'X-CSRF-Token':client.cookies.get('cicc_csrf')}
    assert client.get('/api/advisories').status_code==200
    assert client.get('/api/audit').status_code==403
    assert client.post('/api/investigations',json={'title':'No access'},headers=csrf).status_code==403
    with factory.begin() as db: security.upsert_user(db,'viewer','replacement-password-123','analyst')
    assert client.get('/api/auth/session').status_code==401

def test_sbom_candidates_not_confused_with_affected_versions(env,monkeypatch):
    client,_=env
    data=[{'id':'GHSA-test-test-test','cve':'CVE-2025-1234','summary':'Advisory','severity':'high','url':'https://github.com/advisories/GHSA-test-test-test','published_at':'2025-01-01','raw':{'vulnerabilities':[{'package':{'ecosystem':'pip','name':'example_package'},'vulnerable_version_range':'< 2.0'}]}}]
    monkeypatch.setattr(main.sources,'github_advisories',lambda:data);client.post('/api/sources/github/refresh')
    doc={'bomFormat':'CycloneDX','components':[{'name':'example-package','purl':'pkg:pypi/example-package@10.0','version':'10.0'}]}
    result=client.post('/api/sboms',json={'name':'Example','document':doc});assert result.status_code==201 and result.json()['candidate_count']==1
    detail=client.get('/api/sboms/'+str(result.json()['id'])).json()
    assert detail['candidates'][0]['version_evaluated'] is True
    assert detail['candidates'][0]['snapshot']['version_assessment']['status']=='OUT_OF_RANGE'
    assert detail['candidates'][0]['snapshot']['vulnerable_version_ranges']==['< 2.0']
    assert detail['limitations'] and client.get('/api/sboms/999').status_code==404
    assert client.post('/api/sboms',json={'name':'Example','document':{'bomFormat':'CycloneDX','components':[{}]*501}}).status_code==422
    spdx={'spdxVersion':'SPDX-2.3','packages':[{'name':'foo','externalRefs':[{'referenceType':'purl','referenceLocator':'pkg:npm/%40scope/name@1.0'}]}]}
    result=client.post('/api/sboms',json={'name':'SPDX','document':spdx});assert result.json()['format']=='SPDX'
    assert client.get('/api/sboms/'+str(result.json()['id'])).json()['components'][0]['package_name']=='@scope/name'

def test_login_throttling_and_expiry(env,monkeypatch):
    from datetime import timedelta
    from sqlalchemy import select
    from backend.app.models import Session, utcnow
    client,factory=env; monkeypatch.setattr(main,'DEMO',False)
    with factory.begin() as db: security.upsert_user(db,'admin','long-password-test-123','admin')
    for _ in range(5): assert client.post('/api/auth/login',json={'username':'admin','password':'incorrect-password'}).status_code==401
    assert client.post('/api/auth/login',json={'username':'admin','password':'long-password-test-123'}).status_code==429
    with factory.begin() as db: security.upsert_user(db,'other','long-password-test-123','analyst')
    assert client.post('/api/auth/login',json={'username':'other','password':'long-password-test-123'}).status_code==200
    with factory.begin() as db:
        session=db.scalar(select(Session)); session.expires_at=utcnow()-timedelta(seconds=1)
    assert client.get('/api/auth/session').status_code==401
    assert client.get('/api/investigations').status_code==401

def test_response_timestamps_include_utc_offset(env):
    client,_=env
    created=client.post('/api/investigations',json={'title':'Timestamp test'}).json()
    listed=client.get('/api/investigations').json()[0]
    assert created['created_at'].endswith(('Z','+00:00'))
    assert listed['created_at'].endswith(('Z','+00:00'))

def test_sbom_http_body_is_bounded_before_json_parsing(env):
    client,_=env
    result=client.post('/api/sboms',content=b'{' + b'x'*1100001,headers={'Content-Type':'application/json'})
    assert result.status_code==413
    assert result.json()['detail']=='SBOM request too large'


def test_mitre_cached_cves_and_failed_refresh_retains_data(env,monkeypatch):
    client,_=env
    advisory={'id':'GHSA-test-test-test','cve':'CVE-2025-12345','summary':'Test','severity':'high','url':'https://github.com/advisories/GHSA-test-test-test','published_at':'2025-01-01','raw':{}}
    monkeypatch.setattr(main.sources,'github_advisories',lambda:[advisory])
    client.post('/api/sources/github/refresh')
    record={'cve':'CVE-2025-12345','state':'PUBLISHED','description':'A source claim','assigner':'Example','date_published':'2025-01-01','date_updated':'2025-01-02','source_sha':'a'*40}
    monkeypatch.setattr(main.sources,'mitre_cve',lambda cve:record)
    assert client.post('/api/sources/mitre/refresh').json()['imported']==1
    page=client.get('/api/cves?q=12345').json(); assert page['total']==1
    assert page['items'][0]['verification_status']=='UNVERIFIED'
    assert page['items'][0]['url'].endswith('/cves/2025/12xxx/CVE-2025-12345.json')
    def fail(cve): raise ValueError('offline')
    monkeypatch.setattr(main.sources,'mitre_cve',fail)
    assert client.post('/api/sources/mitre/refresh').status_code==502
    assert client.get('/api/cves').json()['items'][0]['description']=='A source claim'
    assert client.get('/api/sources').json()[2]['status']=='error'


def test_sbom_multiple_alternative_ranges_and_ambiguous_version(env,monkeypatch):
    client,_=env
    package={'ecosystem':'pip','name':'example'}
    advisory={'id':'GHSA-test-test-test','cve':None,'summary':'Test','severity':'high','url':'https://github.com/advisories/GHSA-test-test-test','published_at':'2025-01-01','raw':{'vulnerabilities':[{'package':package,'vulnerable_version_range':'< 1.0'},{'package':package,'vulnerable_version_range':'>= 2.0, < 3.0'}]}}
    monkeypatch.setattr(main.sources,'github_advisories',lambda:[advisory]); client.post('/api/sources/github/refresh')
    doc={'bomFormat':'CycloneDX','components':[{'name':'example','purl':'pkg:pypi/example@2.1','version':'2.1'},{'name':'example','purl':'pkg:pypi/example@2.1','version':'1.0'}]}
    ident=client.post('/api/sboms',json={'name':'multiple','document':doc}).json()['id']
    data=client.get('/api/sboms/'+str(ident)).json()
    assessments=[x['snapshot']['version_assessment'] for x in data['candidates']]
    assert assessments[0]['status']=='IN_RANGE'
    assert assessments[1]['status']=='UNKNOWN' and assessments[1]['reason']=='version_conflict'
    assert data['candidates'][0]['snapshot']['vulnerable_version_ranges']==['< 1.0','>= 2.0, < 3.0']


def test_mitre_batch_is_atomic_on_partial_failure(env,monkeypatch):
    client,_=env
    def advisory(cve,id):
        return {'id':id,'cve':cve,'summary':'Test','severity':'high','url':'https://github.com/advisories/'+id,'published_at':'2025-01-01','raw':{}}
    advisories=[advisory('CVE-2025-12345','GHSA-test-test-test')]
    monkeypatch.setattr(main.sources,'github_advisories',lambda:advisories); client.post('/api/sources/github/refresh')
    def record(cve):
        return {'cve':cve,'state':'PUBLISHED','description':'Original','description_language':'en','assigner':'Example','date_published':None,'date_updated':None,'source_sha':'a'*40}
    monkeypatch.setattr(main.sources,'mitre_cve',record); assert client.post('/api/sources/mitre/refresh').status_code==200
    advisories.append(advisory('CVE-2025-12346','GHSA-next-next-next')); client.post('/api/sources/github/refresh')
    def fail_second(cve):
        if cve=='CVE-2025-12346': raise ValueError('source failure')
        return {**record(cve),'description':'Changed'}
    monkeypatch.setattr(main.sources,'mitre_cve',fail_second)
    assert client.post('/api/sources/mitre/refresh').status_code==502
    page=client.get('/api/cves').json(); assert page['total']==1 and page['items'][0]['description']=='Original'


def test_viewer_cannot_refresh_mitre_source(env,monkeypatch):
    client,factory=env;monkeypatch.setattr(main,'DEMO',False)
    with factory.begin() as db: security.upsert_user(db,'viewer','long-password-test-123','viewer')
    assert client.post('/api/auth/login',json={'username':'viewer','password':'long-password-test-123'}).status_code==200
    assert client.get('/api/cves').status_code==200
    assert client.post('/api/sources/mitre/refresh',headers={'X-CSRF-Token':client.cookies.get('cicc_csrf')}).status_code==403


def test_asset_attestation_inventory_and_investigation_snapshot(env,monkeypatch):
    client,_=env
    def no_network(*args,**kwargs): raise AssertionError('Asset inventory must not access external services')
    monkeypatch.setattr(main.sources,'get',no_network)
    body={'name':'Example application','asset_type':'application','identifier':'application.example.test','owner':'Defensive team','scope_basis':'Documented owner authorization','authorized':True}
    assert client.post('/api/assets',json={**body,'authorized':False}).status_code==422
    assert client.post('/api/assets',json={**body,'authorized':'true'}).status_code==422
    assert client.post('/api/assets',json={**body,'identifier':'bad\nidentifier'}).status_code==422
    result=client.post('/api/assets',json=body); assert result.status_code==201
    asset=result.json(); assert asset['classification']=='USER-ATTESTED' and asset['verification_status']=='UNVERIFIED'
    assert client.get('/api/assets?q=application.example.test').json()['total']==1
    assert client.get('/api/assets?status=retired').json()['total']==0
    case=client.post('/api/investigations',json={'title':'Defensive investigation'}).json(); path=f"/api/investigations/{case['id']}"
    link=client.post(path+'/assets',json={'asset_id':asset['id']}); assert link.status_code==201
    assert client.post(path+'/assets',json={'asset_id':asset['id']}).status_code==409
    assert client.patch('/api/assets/'+str(asset['id']),json={'status':'retired'}).json()['status']=='retired'
    detail=client.get(path).json(); assert detail['assets'][0]['snapshot']['status']=='active'
    assert detail['assets'][0]['snapshot']['scope_basis']=='Documented owner authorization'
    assert any(x.startswith('Asset authorization is user-attested') for x in client.get(path+'/report').json()['limitations'])
    edge=client.get('/api/graph').json()['edges'][0]
    assert edge['type']=='SCOPES_ASSET' and edge['classification']=='USER-ATTESTED' and edge['confidence']=='NOT ASSESSED'
    second=client.post('/api/investigations',json={'title':'Second case'}).json()
    assert client.post(f"/api/investigations/{second['id']}/assets",json={'asset_id':asset['id']}).status_code==409
    assert client.patch('/api/assets/'+str(asset['id']),json={'status':'active'}).status_code==422
    assert client.patch('/api/assets/'+str(asset['id']),json={'status':'active','authorized':True}).json()['status']=='active'
    assert client.get('/api/assets/999').status_code==404
    assert client.post(path+'/assets',json={'asset_id':999}).status_code==404


def test_asset_roles_and_csrf(env,monkeypatch):
    client,factory=env; monkeypatch.setattr(main,'DEMO',False)
    with factory.begin() as db:
        security.upsert_user(db,'viewer','long-password-test-123','viewer')
        security.upsert_user(db,'analyst','long-password-test-123','analyst')
    body={'name':'Example','asset_type':'domain','identifier':'example.test','owner':'Team','scope_basis':'Authorized assessment','authorized':True}
    assert client.post('/api/auth/login',json={'username':'viewer','password':'long-password-test-123'}).status_code==200
    csrf={'X-CSRF-Token':client.cookies.get('cicc_csrf')}
    assert client.get('/api/assets').status_code==200
    assert client.post('/api/assets',json=body,headers=csrf).status_code==403
    assert client.post('/api/auth/logout',headers=csrf).status_code==200
    assert client.post('/api/auth/login',json={'username':'analyst','password':'long-password-test-123'}).status_code==200
    assert client.post('/api/assets',json=body).status_code==403
    csrf={'X-CSRF-Token':client.cookies.get('cicc_csrf')}
    assert client.post('/api/assets',json=body,headers=csrf).status_code==201


def test_manual_sbom_asset_association_is_attested_and_unverified(env):
    client,_=env
    body={'name':'Synthetic asset','asset_type':'application','identifier':'example.test','owner':'Team','scope_basis':'Test scope','authorized':True}
    asset=client.post('/api/assets',json=body).json()
    doc={'bomFormat':'CycloneDX','components':[{'name':'synthetic','purl':'pkg:pypi/synthetic@1.0'}]}
    sbom=client.post('/api/sboms',json={'name':'Synthetic inventory','document':doc}).json()
    path=f"/api/assets/{asset['id']}/sboms"
    assert client.post(path,json={'sbom_id':sbom['id'],'attested':False}).status_code==422
    assert client.post(path,json={'sbom_id':999,'attested':True}).status_code==404
    linked=client.post(path,json={'sbom_id':sbom['id'],'attested':True}); assert linked.status_code==201
    assert linked.json()['snapshot']['classification']=='USER-ATTESTED'
    assert linked.json()['snapshot']['verification_status']=='UNVERIFIED'
    assert client.post(path,json={'sbom_id':sbom['id'],'attested':True}).status_code==409
    page=client.get(path).json();assert len(page['items'])==1 and 'not proof' in page['limitations'][0]
    client.patch(f"/api/assets/{asset['id']}",json={'status':'retired'})
    assert client.post(path,json={'sbom_id':sbom['id'],'attested':True}).status_code==409
    assert client.get(path).json()['items'][0]['snapshot']['name']=='Synthetic inventory'


def test_asset_edits_require_fresh_attestation_and_preserve_link_snapshots(env):
    client,_=env
    body={'name':'Original','asset_type':'application','identifier':'old.example.test','owner':'Team','scope_basis':'Authorized scope','authorized':True}
    asset=client.post('/api/assets',json=body).json()
    case=client.post('/api/investigations',json={'title':'Synthetic case'}).json()
    path=f"/api/investigations/{case['id']}/assets"
    assert client.post(path,json={'asset_id':asset['id']}).status_code==201
    edit=f"/api/assets/{asset['id']}/metadata"
    assert client.put(edit,json={**body,'identifier':'new.example.test','authorized':False}).status_code==422
    assert client.put(edit,json={**body,'identifier':'new.example.test','authorized':True}).status_code==409
    assert client.put(edit,json={**body,'name':'Updated','authorized':True}).json()['name']=='Updated'
    assert client.get(f"/api/investigations/{case['id']}").json()['assets'][0]['snapshot']['identifier']=='old.example.test'
    assert client.patch(f"/api/assets/{asset['id']}",json={'status':'retired'}).status_code==200
    assert client.put(edit,json=body).status_code==409


def test_attack_reference_investigation_snapshot_and_source_failure(env,monkeypatch):
    client,_=env
    record={'id':'T1234','stix_id':'attack-pattern--00000000-0000-4000-8000-000000000001','name':'Reference technique','description':'Source-reported reference','tactics':['execution'],'version':'1.0','modified':'2025-01-01','revoked':False,'deprecated':False,'source_sha':'a'*40}
    monkeypatch.setattr(main.sources,'attack_sample',lambda:[record])
    assert client.post('/api/sources/attack/refresh').json()['imported']==1
    page=client.get('/api/techniques?q=T1234').json();assert page['total']==1 and page['items'][0]['verification_status']=='UNVERIFIED'
    case=client.post('/api/investigations',json={'title':'Synthetic research'}).json();path=f"/api/investigations/{case['id']}"
    assert client.post(path+'/techniques',json={'technique_id':'T1234'}).status_code==201
    assert client.post(path+'/techniques',json={'technique_id':'T1234'}).status_code==409
    record['name']='Updated reference';record['deprecated']=True
    assert client.post('/api/sources/attack/refresh').status_code==200
    assert client.get(path).json()['techniques'][0]['snapshot']['name']=='Reference technique'
    second=client.post('/api/investigations',json={'title':'Another research'}).json()
    assert client.post(f"/api/investigations/{second['id']}/techniques",json={'technique_id':'T1234'}).status_code==409
    graph=client.get('/api/graph').json();assert graph['edges'][0]['type']=='REFERENCES_TECHNIQUE'
    assert any('not evidence of activity' in x for x in client.get(path+'/report').json()['limitations'])
    def fail(): raise ValueError('source unavailable')
    monkeypatch.setattr(main.sources,'attack_sample',fail)
    assert client.post('/api/sources/attack/refresh').status_code==502
    assert client.get('/api/techniques').json()['total']==1 and client.get('/api/sources').json()[3]['status']=='error'


def test_investigation_timeline_pagination_and_transactional_events(env,monkeypatch):
    client,_=env
    advisory={'id':'GHSA-test-test-test','cve':None,'summary':'Example','severity':'high','url':'https://github.com/advisories/GHSA-test-test-test','published_at':'2025-01-01','raw':{}}
    monkeypatch.setattr(main.sources,'github_advisories',lambda:[advisory]);client.post('/api/sources/github/refresh')
    case=client.post('/api/investigations',json={'title':'Timeline test'}).json();path=f"/api/investigations/{case['id']}"
    client.post(path+'/evidence',json={'advisory_id':advisory['id']})
    assert client.post(path+'/evidence',json={'advisory_id':advisory['id']}).status_code==409
    client.post(path+'/notes',json={'content':'Test hypothesis','classification':'HYPOTHESIS'})
    client.patch(path,json={'status':'closed'})
    first=client.get(path+'/timeline?limit=2').json(); assert [x['event_type'] for x in first['items']]==['STATUS_CHANGED','NOTE_ADDED']
    assert first['next_before'] is not None
    second=client.get(path+'/timeline',params={'limit':2,'before':first['next_before']}).json()
    assert [x['event_type'] for x in second['items']]==['EVIDENCE_LINKED','CASE_CREATED'] and second['next_before'] is None
    assert all('Test hypothesis' not in str(x) for x in first['items'])
    assert client.get(path+'/report').json()['timeline']['items'][0]['event_type']=='STATUS_CHANGED'
    assert client.get('/api/investigations/999/timeline').status_code==404
    other=client.post('/api/investigations',json={'title':'Other timeline'}).json()
    assert len(client.get(f"/api/investigations/{other['id']}/timeline").json()['items'])==1


def test_non_sbom_api_write_bodies_are_bounded_before_parsing(env):
    client,_=env
    oversized=b'{' + b'x'*65537
    result=client.post('/api/investigations',content=oversized,headers={'Content-Type':'application/json'})
    assert result.status_code==413 and result.json()['detail']=='Request too large'
    result=client.put('/api/assets/1/metadata',content=oversized,headers={'Content-Type':'application/json'})
    assert result.status_code==413
    result=client.post('/api/auth/login',content=oversized,headers={'Content-Type':'application/json'})
    assert result.status_code==413


def test_write_body_limit_handles_multiple_asgi_chunks():
    import asyncio
    messages=iter([{'type':'http.request','body':b'a'*40000,'more_body':True}, {'type':'http.request','body':b'b'*40000,'more_body':False}])
    sent=[]
    async def receive():return next(messages)
    async def send(message):sent.append(message)
    async def downstream(scope,receive,send):raise AssertionError('Oversized content reached application')
    scope={'type':'http','path':'/api/investigations','method':'POST','headers':[]}
    asyncio.run(main.ApiBodyLimitMiddleware(downstream)(scope,receive,send))
    assert sent[0]['status']==413


def test_advisory_snapshot_checksums_detect_changes_and_legacy_is_unknown(env,monkeypatch):
    from backend.app.models import Evidence
    client,factory=env
    advisory={'id':'GHSA-test-test-test','cve':None,'summary':'Original','severity':'high','url':'https://github.com/advisories/GHSA-test-test-test','published_at':'2025-01-01','raw':{}}
    monkeypatch.setattr(main.sources,'github_advisories',lambda:[advisory]);client.post('/api/sources/github/refresh')
    case=client.post('/api/investigations',json={'title':'Checksum test'}).json();path=f"/api/investigations/{case['id']}"
    entry=client.post(path+'/evidence',json={'advisory_id':advisory['id']}).json();assert entry['integrity']['status']=='MATCH'
    assert len(entry['integrity']['sha256'])==64
    with factory.begin() as db:
        obj=db.get(Evidence,entry['id']);obj.snapshot={**obj.snapshot,'summary':'Changed'}
    assert client.get(path).json()['evidence'][0]['integrity']['status']=='MISMATCH'
    with factory.begin() as db:
        obj=db.get(Evidence,entry['id']);obj.snapshot_sha256=None
    assert client.get(path).json()['evidence'][0]['integrity']['status']=='NOT_RECORDED'


def test_snapshot_checksum_is_canonical_for_json_key_order():
    assert main.snapshot_checksum({'b':'عربي','a':[2,1]})==main.snapshot_checksum({'a':[2,1],'b':'عربي'})
    assert main.snapshot_checksum({'a':[1,2],'b':'عربي'})!=main.snapshot_checksum({'a':[2,1],'b':'عربي'})


def test_epss_refresh_enriches_cached_advisory_and_preserves_on_failure(env,monkeypatch):
    client,_=env
    advisory={'id':'GHSA-test-test-test','cve':'CVE-2025-1234','summary':'Synthetic advisory','severity':'high','url':'https://github.com/advisories/GHSA-test-test-test','published_at':'2025-01-01','raw':{}}
    monkeypatch.setattr(main.sources,'github_advisories',lambda:[advisory])
    assert client.post('/api/sources/epss/refresh').status_code==502
    assert client.post('/api/sources/github/refresh').status_code==200
    def collect(cves):
        assert cves==['CVE-2025-1234']
        return [{'cve':cves[0],'score':'0.012340000','percentile':'0.710000000','score_date':'2025-04-01'}]
    monkeypatch.setattr(main.sources,'epss_scores',collect)
    assert client.post('/api/sources/epss/refresh').json()['imported']==1
    item=client.get('/api/advisories').json()['items'][0]
    assert item['epss']['score']=='0.012340000' and item['epss']['score_date']=='2025-04-01'
    assert item['epss']['classification']=='MODEL ESTIMATE' and item['epss']['collected_at'].endswith(('Z','+00:00'))
    record={'cve':'CVE-2025-1234','state':'PUBLISHED','description':'Synthetic CVE','assigner':'Example','date_published':'2025-01-01','date_updated':'2025-01-02','source_sha':'a'*40}
    monkeypatch.setattr(main.sources,'mitre_cve',lambda cve:record)
    assert client.post('/api/sources/mitre/refresh').status_code==200
    assert client.get('/api/cves').json()['items'][0]['epss']['score']=='0.012340000'
    def fail(cves): raise ValueError('Synthetic source error')
    monkeypatch.setattr(main.sources,'epss_scores',fail)
    assert client.post('/api/sources/epss/refresh').status_code==502
    assert client.get('/api/advisories').json()['items'][0]['epss']['score']=='0.012340000'
    source=next(s for s in client.get('/api/sources').json() if s['id']=='epss')
    assert source['status']=='error' and source['count']==1 and source['last_success']
    monkeypatch.setattr(main.sources,'epss_scores',lambda cves:[])
    assert client.post('/api/sources/epss/refresh').json()['imported']==0
    assert client.get('/api/advisories').json()['items'][0]['epss'] is None
    assert client.get('/api/cves').json()['items'][0]['epss'] is None
