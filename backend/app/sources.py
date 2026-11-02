"""Fixed public endpoints. No code, downloaded files, or URLs from records are executed."""
import base64, binascii, hashlib, json, re, ssl
import httpx
HEADERS={'Accept':'application/vnd.github+json','User-Agent':'CICC-development'}
GITHUB='https://api.github.com'
EPSS_URL='https://api.first.org/data/v1/epss'
KEV_REPO=GITHUB+'/repos/cisagov/kev-data'
KEV_URL='https://github.com/cisagov/kev-data/blob/develop/known_exploited_vulnerabilities.json'

MAX_SOURCE_RESPONSE_BYTES=16*1024*1024

def get(url,params=None):
    # Limit decoded bytes while streaming, regardless of Content-Length.
    with httpx.stream('GET',url,params=params,headers=({'Accept':'application/json','User-Agent':'CICC-development'} if url==EPSS_URL else HEADERS),timeout=30,follow_redirects=False,verify=ssl.create_default_context()) as response:
        response.raise_for_status()
        declared=response.headers.get('content-length','')
        if declared.isdigit() and int(declared)>MAX_SOURCE_RESPONSE_BYTES: raise ValueError('Source response too large')
        chunks=[];size=0
        for chunk in response.iter_bytes(chunk_size=65536):
            size+=len(chunk)
            if size>MAX_SOURCE_RESPONSE_BYTES: raise ValueError('Source response too large')
            chunks.append(chunk)
    try: return json.loads(b''.join(chunks))
    except (UnicodeDecodeError,json.JSONDecodeError) as exc: raise ValueError('Invalid source JSON') from exc

def github_advisories():
    data=get(GITHUB+'/advisories',{'per_page':30,'sort':'published','direction':'desc'})
    if not isinstance(data,list): raise ValueError('Unexpected advisory response')
    result=[]
    for x in data:
        if not isinstance(x,dict) or not isinstance(x.get('ghsa_id'),str) or not re.fullmatch(r'GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}',x['ghsa_id']): continue
        if not isinstance(x.get('summary'),str): continue
        ids=x.get('identifiers') if isinstance(x.get('identifiers'),list) else []
        cve=next((i.get('value') for i in ids if isinstance(i,dict) and i.get('type')=='CVE' and isinstance(i.get('value'),str)),None)
        severity=x.get('severity') if x.get('severity') in ('critical','high','moderate','low') else 'unknown'
        result.append({'id':x['ghsa_id'],'cve':cve,'summary':x['summary'][:10000],'severity':severity,'url':'https://github.com/advisories/'+x['ghsa_id'],'published_at':x.get('published_at') if isinstance(x.get('published_at'),str) else None,'raw':x})
    if not result: raise ValueError('No valid advisories received')
    return result

def cisa_kev():
    info=get(KEV_REPO+'/contents/known_exploited_vulnerabilities.json',{'ref':'develop'})
    sha=info.get('sha') if isinstance(info,dict) else None
    if not isinstance(sha,str) or not re.fullmatch(r'[0-9a-f]{40}',sha) or not isinstance(info.get('size'),int) or not 0<info['size']<=8*1024*1024: raise ValueError('Invalid catalog metadata')
    blob=get(KEV_REPO+'/git/blobs/'+sha)
    if not isinstance(blob,dict) or blob.get('sha')!=sha or blob.get('encoding')!='base64' or not isinstance(blob.get('content'),str) or len(blob['content'])>16*1024*1024: raise ValueError('Invalid catalog blob')
    try:
        raw=base64.b64decode(''.join(blob['content'].split()),validate=True)
        if len(raw)!=info['size'] or hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()!=sha: raise ValueError('Catalog integrity mismatch')
        doc=json.loads(raw)
    except (binascii.Error,UnicodeDecodeError,json.JSONDecodeError) as exc: raise ValueError('Invalid catalog data') from exc
    if not isinstance(doc,dict) or not isinstance(doc.get('vulnerabilities'),list) or not doc['vulnerabilities'] or type(doc.get('count')) is not int or doc['count']!=len(doc['vulnerabilities']) or not isinstance(doc.get('catalogVersion'),str) or not isinstance(doc.get('dateReleased'),str): raise ValueError('Invalid catalog structure')
    items=[]; seen=set(); fields=('vendorProject','product','vulnerabilityName','dateAdded','shortDescription','requiredAction','dueDate','knownRansomwareCampaignUse')
    for x in doc['vulnerabilities']:
        if not isinstance(x,dict) or not isinstance(x.get('cveID'),str) or not re.fullmatch(r'CVE-\d{4}-\d{4,}',x['cveID']) or x['cveID'] in seen or any(not isinstance(x.get(f),str) or len(x[f])>10000 for f in fields): raise ValueError('Invalid catalog entry')
        seen.add(x['cveID']); items.append(dict(zip(('cve','vendor','product','title','date_added','description','action','due_date','ransomware'),(x['cveID'],*(x[f] for f in fields)))))
    return {'items':items,'version':doc['catalogVersion'],'released_at':doc['dateReleased'],'reference':sha}

MITRE_REPO=GITHUB+'/repos/CVEProject/cvelistV5'
MITRE_URL='https://github.com/CVEProject/cvelistV5'

def mitre_cve(cve):
    """Get a specific official CVE record via a fixed repository; validate blob and identity."""
    match=re.fullmatch(r'CVE-(\d{4})-(\d{4,12})',cve or '')
    if not match: raise ValueError('Invalid CVE identifier')
    year,number=match.groups()
    path=f'cves/{year}/{number[:-3]}xxx/{cve}.json'
    info=get(MITRE_REPO+'/contents/'+path,{'ref':'main'})
    if not isinstance(info,dict) or info.get('type')!='file' or info.get('path')!=path or info.get('encoding')!='base64': raise ValueError('Invalid CVE file metadata')
    sha,size,content=info.get('sha'),info.get('size'),info.get('content')
    if not isinstance(sha,str) or not re.fullmatch(r'[0-9a-f]{40}',sha) or type(size) is not int or not 0<size<=1024*1024 or not isinstance(content,str) or len(content)>2*1024*1024: raise ValueError('Invalid CVE file size or hash')
    try:
        raw=base64.b64decode(''.join(content.split()),validate=True)
        if len(raw)!=size or hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()!=sha: raise ValueError('CVE blob integrity mismatch')
        doc=json.loads(raw)
    except (binascii.Error,UnicodeDecodeError,json.JSONDecodeError) as exc: raise ValueError('Invalid CVE document') from exc
    if not isinstance(doc,dict) or doc.get('dataType')!='CVE_RECORD' or not str(doc.get('dataVersion','')).startswith('5.'): raise ValueError('Unsupported CVE record')
    meta=doc.get('cveMetadata'); containers=doc.get('containers')
    if not isinstance(meta,dict) or meta.get('cveId')!=cve or meta.get('state') not in ('PUBLISHED','REJECTED') or not isinstance(containers,dict) or not isinstance(containers.get('cna'),dict): raise ValueError('Invalid CVE record identity')
    cna=containers['cna']
    descriptions=cna.get('rejectedReasons' if meta['state']=='REJECTED' else 'descriptions',[])
    if not isinstance(descriptions,list): raise ValueError('Invalid CVE descriptions')
    entries=[x for x in descriptions if isinstance(x,dict) and isinstance(x.get('value'),str) and x['value'].strip()]
    selected=next((x for x in entries if x.get('lang')=='en'),entries[0] if entries else None)
    if not selected or len(selected['value'])>100000: raise ValueError('Missing or oversized CVE description')
    def optional(key,limit):
        value=meta.get(key)
        if value is not None and (not isinstance(value,str) or len(value)>limit): raise ValueError('Invalid CVE metadata')
        return value
    language=selected.get('lang')
    if language is not None and (not isinstance(language,str) or len(language)>30): raise ValueError('Invalid CVE description language')
    return {'cve':cve,'state':meta['state'],'description':selected['value'],'description_language':language,'assigner':optional('assignerShortName',200),'date_published':optional('datePublished',100),'date_updated':optional('dateUpdated',100),'source_sha':sha}

ATTACK_REPO=GITHUB+'/repos/mitre/cti'
ATTACK_URL='https://github.com/mitre/cti/tree/master/enterprise-attack/attack-pattern'
ATTACK_PATH='enterprise-attack/attack-pattern'
ATTACK_FILE=re.compile(r'attack-pattern--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json')

def attack_sample():
    """Collect a clearly limited lexicographic sample from MITRE's STIX 2.0 repository."""
    listing=get(ATTACK_REPO+'/contents/'+ATTACK_PATH,{'ref':'master'})
    if not isinstance(listing,list) or len(listing)>=1000: raise ValueError('Invalid or truncated ATT&CK directory')
    files=[x for x in listing if isinstance(x,dict) and x.get('type')=='file' and isinstance(x.get('name'),str) and ATTACK_FILE.fullmatch(x['name'])]
    files.sort(key=lambda x:x['name'])
    if len(files)<10: raise ValueError('Incomplete ATT&CK directory')
    items=[]; seen=set()
    for file in files[:10]:
        name=file['name'];path=ATTACK_PATH+'/'+name;expected=file.get('sha')
        if not isinstance(expected,str) or not re.fullmatch(r'[0-9a-f]{40}',expected): raise ValueError('Invalid ATT&CK file hash')
        info=get(ATTACK_REPO+'/contents/'+path,{'ref':'master'})
        if not isinstance(info,dict) or info.get('type')!='file' or info.get('path')!=path or info.get('sha')!=expected or info.get('encoding')!='base64': raise ValueError('Invalid ATT&CK file metadata')
        size,content=info.get('size'),info.get('content')
        if type(size) is not int or not 0<size<=1024*1024 or not isinstance(content,str) or len(content)>2*1024*1024: raise ValueError('Invalid ATT&CK file size')
        try:
            raw=base64.b64decode(''.join(content.split()),validate=True)
            if len(raw)!=size or hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()!=expected: raise ValueError('ATT&CK blob integrity mismatch')
            doc=json.loads(raw)
        except (binascii.Error,UnicodeDecodeError,json.JSONDecodeError) as exc: raise ValueError('Invalid ATT&CK STIX') from exc
        if not isinstance(doc,dict) or doc.get('type')!='bundle' or not isinstance(doc.get('objects'),list) or len(doc['objects'])!=1: raise ValueError('Invalid ATT&CK bundle')
        obj=doc['objects'][0]
        if not isinstance(obj,dict) or obj.get('type')!='attack-pattern' or obj.get('id')!=name[:-5]: raise ValueError('ATT&CK identity mismatch')
        refs=obj.get('external_references',[])
        if not isinstance(refs,list): raise ValueError('Invalid ATT&CK references')
        ids=[x['external_id'] for x in refs if isinstance(x,dict) and x.get('source_name')=='mitre-attack' and isinstance(x.get('external_id'),str) and re.fullmatch(r'T\d{4}(?:\.\d{3})?',x['external_id'])]
        if len(ids)!=1 or ids[0] in seen: raise ValueError('Invalid ATT&CK technique identifier')
        seen.add(ids[0]);title=obj.get('name');description=obj.get('description');phases=obj.get('kill_chain_phases',[])
        if not isinstance(title,str) or not title.strip() or len(title)>300 or not isinstance(description,str) or len(description)>100000 or not isinstance(phases,list): raise ValueError('Invalid ATT&CK content')
        tactics=[]
        for phase in phases:
            if isinstance(phase,dict) and phase.get('kill_chain_name')=='mitre-attack':
                value=phase.get('phase_name')
                if not isinstance(value,str) or not re.fullmatch(r'[a-z0-9-]{1,60}',value): raise ValueError('Invalid ATT&CK tactic')
                if value not in tactics:tactics.append(value)
        if len(tactics)>32: raise ValueError('Too many ATT&CK tactics')
        version=obj.get('x_mitre_version');modified=obj.get('modified')
        if version is not None and (not isinstance(version,str) or len(version)>30): raise ValueError('Invalid ATT&CK version')
        if modified is not None and (not isinstance(modified,str) or len(modified)>60): raise ValueError('Invalid ATT&CK timestamp')
        if type(obj.get('revoked',False)) is not bool or type(obj.get('x_mitre_deprecated',False)) is not bool: raise ValueError('Invalid ATT&CK status')
        items.append({'id':ids[0],'stix_id':obj['id'],'name':title,'description':description,'tactics':tactics,'version':version,'modified':modified,'revoked':obj.get('revoked',False),'deprecated':obj.get('x_mitre_deprecated',False),'source_sha':expected})
    return items


def epss_scores(cves):
    """FIRST daily model estimates for a bounded list; missing records stay unknown."""
    from datetime import date
    if not isinstance(cves,list) or not 1<=len(cves)<=30: raise ValueError('Invalid EPSS request')
    if any(not isinstance(cve,str) or not re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,12}',cve) for cve in cves): raise ValueError('Invalid EPSS CVE')
    if len(set(cves))!=len(cves): raise ValueError('Invalid EPSS request')
    data=get(EPSS_URL,{'cve':','.join(cves),'limit':len(cves)})
    if not isinstance(data,dict) or data.get('status')!='OK' or data.get('status-code')!=200 or type(data.get('total')) is not int or data.get('offset')!=0 or not isinstance(data.get('data'),list) or data['total']!=len(data['data']) or data['total']>len(cves): raise ValueError('Invalid or truncated EPSS response')
    items=[];seen=set()
    for row in data['data']:
        if not isinstance(row,dict) or row.get('cve') not in cves or row['cve'] in seen: raise ValueError('Invalid EPSS CVE identity')
        for field in ('epss','percentile'):
            value=row.get(field)
            if not isinstance(value,str) or len(value)>16 or not re.fullmatch(r'(?:0(?:\.[0-9]{1,12})?|1(?:\.0{1,12})?)',value): raise ValueError('Invalid EPSS score')
        score_date=row.get('date')
        try:
            if not isinstance(score_date,str) or len(score_date)!=10 or date.fromisoformat(score_date).isoformat()!=score_date: raise ValueError()
        except ValueError as exc: raise ValueError('Invalid EPSS date') from exc
        seen.add(row['cve']);items.append({'cve':row['cve'],'score':row['epss'],'percentile':row['percentile'],'score_date':score_date})
    return items
