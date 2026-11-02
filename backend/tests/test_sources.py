import base64
import hashlib
import json
import pytest
from backend.app import sources


def catalog_blob():
    entry={'cveID':'CVE-2025-1234','vendorProject':'Vendor','product':'Product','vulnerabilityName':'Example','dateAdded':'2025-01-01','shortDescription':'Description','requiredAction':'Update','dueDate':'2025-02-01','knownRansomwareCampaignUse':'Unknown'}
    raw=json.dumps({'vulnerabilities':[entry],'count':1,'catalogVersion':'v1','dateReleased':'2025-01-01'}).encode()
    sha=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    return raw,sha


def test_cisa_catalog_integrity_and_validation(monkeypatch):
    raw,sha=catalog_blob()
    def get(url,params=None):
        if '/contents/' in url:return {'sha':sha,'size':len(raw)}
        return {'sha':sha,'encoding':'base64','content':base64.b64encode(raw).decode()}
    monkeypatch.setattr(sources,'get',get)
    result=sources.cisa_kev()
    assert result['reference']==sha and result['items'][0]['cve']=='CVE-2025-1234'
    def tampered(url,params=None):
        data=get(url,params)
        if '/git/blobs/' in url:data['content']=base64.b64encode(b'altered').decode()
        return data
    monkeypatch.setattr(sources,'get',tampered)
    with pytest.raises(ValueError,match='integrity'): sources.cisa_kev()


def test_source_rejects_empty_or_bad_advisories(monkeypatch):
    monkeypatch.setattr(sources,'get',lambda *args,**kwargs:[{'ghsa_id':'bad','summary':'ignored'}])
    with pytest.raises(ValueError,match='No valid'): sources.github_advisories()


def test_mitre_specific_cve_blob_integrity_and_identity(monkeypatch):
    doc={'dataType':'CVE_RECORD','dataVersion':'5.1','cveMetadata':{'cveId':'CVE-2025-12345','state':'PUBLISHED','assignerShortName':'Example'},'containers':{'cna':{'descriptions':[{'lang':'en','value':'Source-reported example'}]}}}
    raw=json.dumps(doc).encode(); sha=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    def get(url,params):
        assert url.endswith('/cves/2025/12xxx/CVE-2025-12345.json') and params=={'ref':'main'}
        return {'type':'file','path':'cves/2025/12xxx/CVE-2025-12345.json','encoding':'base64','sha':sha,'size':len(raw),'content':base64.b64encode(raw).decode()}
    monkeypatch.setattr(sources,'get',get)
    result=sources.mitre_cve('CVE-2025-12345')
    assert result['description']=='Source-reported example' and result['source_sha']==sha
    with pytest.raises(ValueError,match='identifier'): sources.mitre_cve('../foo')
    def bad(url,params):
        data=get(url,params); data['sha']='a'*40; return data
    monkeypatch.setattr(sources,'get',bad)
    with pytest.raises(ValueError,match='integrity'): sources.mitre_cve('CVE-2025-12345')


def test_attack_sample_validates_fixed_paths_and_blob_hashes(monkeypatch):
    files=[]; blobs={}
    for i in range(10):
        stix=f'attack-pattern--00000000-0000-4000-8000-{i:012x}'
        name=stix+'.json';path=sources.ATTACK_PATH+'/'+name
        obj={'type':'attack-pattern','id':stix,'name':'Reference '+str(i),'description':'Source description','external_references':[{'source_name':'mitre-attack','external_id':f'T{i:04d}'}],'kill_chain_phases':[{'kill_chain_name':'mitre-attack','phase_name':'execution'}]}
        raw=json.dumps({'type':'bundle','objects':[obj]}).encode();sha=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        files.append({'type':'file','name':name,'sha':sha})
        blobs[path]={'type':'file','path':path,'sha':sha,'encoding':'base64','size':len(raw),'content':base64.b64encode(raw).decode()}
    def get(url,params):
        assert params=={'ref':'master'}
        path=url.split('/contents/')[1]
        return files if path==sources.ATTACK_PATH else blobs[path].copy()
    monkeypatch.setattr(sources,'get',get)
    records=sources.attack_sample();assert len(records)==10 and records[0]['tactics']==['execution']
    def tampered(url,params):
        result=get(url,params)
        if isinstance(result,dict):result['content']=base64.b64encode(b'tampered').decode()
        return result
    monkeypatch.setattr(sources,'get',tampered)
    with pytest.raises(ValueError,match='integrity'):sources.attack_sample()


def test_source_response_size_limit_enforced_without_content_length(monkeypatch):
    from contextlib import contextmanager
    class Response:
        headers={}
        def raise_for_status(self): pass
        def iter_bytes(self,chunk_size):
            yield b'1234567890'
            yield b'abcdefghij'
    @contextmanager
    def stream(*args,**kwargs):
        assert kwargs['follow_redirects'] is False
        yield Response()
    monkeypatch.setattr(sources.httpx,'stream',stream)
    monkeypatch.setattr(sources,'MAX_SOURCE_RESPONSE_BYTES',16)
    with pytest.raises(ValueError,match='too large'):sources.get('https://api.github.com/example')


def test_epss_validates_identity_range_date_and_pagination(monkeypatch):
    from copy import deepcopy
    doc={'status':'OK','status-code':200,'total':1,'offset':0,'data':[{'cve':'CVE-2025-1234','epss':'0.972240000','percentile':'1.000000000','date':'2025-04-01'}]}
    def get(url,params):
        assert url==sources.EPSS_URL and params=={'cve':'CVE-2025-1234,CVE-2025-5678','limit':2}
        return deepcopy(doc)
    monkeypatch.setattr(sources,'get',get)
    result=sources.epss_scores(['CVE-2025-1234','CVE-2025-5678'])
    assert result==[{'cve':'CVE-2025-1234','score':'0.972240000','percentile':'1.000000000','score_date':'2025-04-01'}]
    for field,value in [('epss','NaN'),('epss','1.00001'),('epss','-0.1'),('percentile',0.5),('date','2025-02-30'),('cve','CVE-2025-9999')]:
        original=doc['data'][0][field];doc['data'][0][field]=value
        with pytest.raises(ValueError):sources.epss_scores(['CVE-2025-1234','CVE-2025-5678'])
        doc['data'][0][field]=original
    doc['total']=2
    with pytest.raises(ValueError,match='truncated'):sources.epss_scores(['CVE-2025-1234','CVE-2025-5678'])
    doc['total']=0;doc['data']=[]
    assert sources.epss_scores(['CVE-2025-1234','CVE-2025-5678'])==[]
    for bad in ([],['CVE-2025-1234']*2,['../invalid'],[['not hashable']]):
        with pytest.raises(ValueError): sources.epss_scores(bad)
