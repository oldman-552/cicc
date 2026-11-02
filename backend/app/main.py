"""CICC development API: experimental workspace scope; not production tenant isolation."""
import hmac, os, json, hashlib
from datetime import timedelta, timezone
from typing import Literal
import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, StrictBool
from sqlalchemy import select, delete, func, or_, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session as DbSession
from .db import SessionLocal, get_db
from .models import Workspace, User, UserMfa, Session, LoginAttempt, Source, Advisory, KevEntry, Investigation, Evidence, Note, Audit, Sbom, SbomComponent, SbomCandidate, MitreCve, EpssScore, Asset, InvestigationAsset, AssetSbom, AttackTechnique, InvestigationTechnique, InvestigationEvent, utcnow
from . import security, sources, sbom, version_assessment, mfa

app=FastAPI(title='CICC Development API',version='0.1.0',description='Development foundation: not production-ready or multi-tenant.')
class ApiBodyLimitMiddleware:
    """Bound write request envelopes before FastAPI parses JSON; not a complete DoS defense."""
    def __init__(self, app): self.app=app
    async def __call__(self, scope, receive, send):
        if scope['type']!='http' or not scope.get('path','').startswith('/api/') or scope.get('method') not in ('POST','PUT','PATCH'):
            return await self.app(scope,receive,send)
        is_sbom=scope.get('path')=='/api/sboms' and scope.get('method')=='POST'
        limit=1100000 if is_sbom else 65536
        chunks=[]; size=0
        while True:
            event=await receive()
            if event['type']=='http.disconnect': return
            if event['type']!='http.request': continue
            part=event.get('body',b''); size+=len(part)
            if size>limit:
                return await JSONResponse({'detail':'SBOM request too large' if is_sbom else 'Request too large'},status_code=413,headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})(scope,receive,send)
            chunks.append(part)
            if not event.get('more_body',False): break
        body=b''.join(chunks); delivered=False
        async def replay():
            nonlocal delivered
            if not delivered:
                delivered=True
                return {'type':'http.request','body':body,'more_body':False}
            return await receive()
        return await self.app(scope,replay,send)

app.add_middleware(ApiBodyLimitMiddleware)

DEMO=os.getenv('CICC_DEMO_MODE','0')=='1'
_require_mfa=os.getenv('CICC_REQUIRE_MFA','0')
if _require_mfa not in ('0','1'): raise RuntimeError('CICC_REQUIRE_MFA must be 0 or 1')
REQUIRE_MFA=_require_mfa=='1'
COOKIE_SECURE=os.getenv('CICC_INSECURE_COOKIES','0')!='1'

def parse_source_operators(value):
    if not value:return frozenset()
    if len(value)>4096:raise RuntimeError('CICC_GLOBAL_SOURCE_OPERATORS is too long')
    try:
        names=value.split(',')
        if len(names)>100 or any(not name.strip() for name in names):raise ValueError()
        return frozenset(security.username_normalize(name) for name in names)
    except ValueError as exc:raise RuntimeError('Invalid CICC_GLOBAL_SOURCE_OPERATORS') from exc

SOURCE_OPERATORS=parse_source_operators(os.getenv('CICC_GLOBAL_SOURCE_OPERATORS',''))

def can_refresh_sources(user):
    return user.role=='admin' and user.username in SOURCE_OPERATORS

def as_utc(value):
    return value.replace(tzinfo=timezone.utc) if value is not None and value.tzinfo is None else value

def write_audit(db,actor,action,detail='',workspace_id=None):
    if isinstance(actor,Request):
        workspace_id=actor.state.workspace_id;actor=actor.state.actor
    db.add(Audit(actor=actor,action=action,detail=detail,workspace_id=workspace_id))

def scoped(db,model,id,request,lock=False):
    query=select(model).where(model.id==id,model.workspace_id==request.state.workspace_id)
    return db.scalar(query.with_for_update() if lock else query)

def snapshot_checksum(snapshot):
    canonical=json.dumps(snapshot,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')
    return hashlib.sha256(canonical).hexdigest()

def evidence_integrity(evidence):
    stored=evidence.snapshot_sha256
    if not stored: return {'status':'NOT_RECORDED','sha256':None,'algorithm':None}
    try: matches=hmac.compare_digest(stored,snapshot_checksum(evidence.snapshot))
    except (TypeError,ValueError,UnicodeError): matches=False
    return {'status':'MATCH' if matches else 'MISMATCH','sha256':stored,'algorithm':'cicc-json-sha256-v1'}

def investigation_event(db,investigation_id,actor,event_type,details):
    db.add(InvestigationEvent(investigation_id=investigation_id,actor=actor,event_type=event_type,details=details))

def source_dict(source_id, row):
    names={'github':('GitHub Security Advisories','https://github.com/advisories'),'cisa':('CISA KEV · GitHub mirror',sources.KEV_URL),'mitre':('CVE Program · official repository',sources.MITRE_URL),'attack':('MITRE ATT&CK · STIX reference',sources.ATTACK_URL),'epss':('FIRST EPSS · limited CVE sample',sources.EPSS_URL)}
    name,url=names[source_id]
    return {'id':source_id,'name':name,'url':url,'status':'error' if row and row.error else 'cached' if row and row.last_success else 'not_connected','last_success':as_utc(row.last_success) if row else None,'last_attempt':as_utc(row.last_attempt) if row else None,'error':row.error if row else None,'count':row.count if row else 0,'version':row.version if row else None,'released_at':row.released_at if row else None,'reference':row.reference if row else None}

def epss_dict(epss):
    return {'score':epss.score,'percentile':epss.percentile,'score_date':epss.score_date,'collected_at':as_utc(epss.collected_at),'source':'FIRST EPSS','classification':'MODEL ESTIMATE'} if epss else None

def advisory_dict(a, kev=None, catalog=None, epss=None):
    return {'id':a.id,'cve':a.cve,'summary':a.summary,'severity':a.severity,'url':a.url,'published_at':a.published_at,'collected_at':as_utc(a.collected_at),'source':'GitHub Security Advisories','classification':'SOURCE-REPORTED','verification_status':'UNVERIFIED','data_state':'CACHED','kev_status':'UNKNOWN' if not catalog or not a.cve else 'LISTED' if kev else 'NOT_LISTED_IN_CACHE','kev_collected_at':as_utc(catalog.last_success) if catalog else None,'kev_version':catalog.version if catalog else None,'epss':epss_dict(epss)}

@app.middleware('http')
async def access_control(request:Request,call_next):
    path=request.url.path
    if path.startswith('/api/') and path not in ('/api/health','/api/ready','/api/auth/session','/api/auth/login'):
        if DEMO: request.state.actor='demo'; request.state.role='admin'; request.state.workspace_id=1
        else:
            with SessionLocal() as db: row=security.get_session(db,request.cookies.get('cicc_session',''),require_mfa=REQUIRE_MFA)
            if not row: return JSONResponse({'detail':'Authentication required'},status_code=401,headers={'Cache-Control':'no-store'})
            session,user=row; request.state.actor=user.username; request.state.role=user.role; request.state.workspace_id=user.workspace_id; request.state.user_id=user.id
            if request.method not in ('GET','HEAD','OPTIONS'):
                csrf=request.headers.get('X-CSRF-Token','')
                if not csrf or len(csrf)>256 or not hmac.compare_digest(session.csrf_hash,security.digest(csrf)): return JSONResponse({'detail':'Invalid CSRF token'},status_code=403,headers={'Cache-Control':'no-store'})
                if path not in ('/api/auth/logout','/api/auth/sessions/revoke-others') and user.role=='viewer': return JSONResponse({'detail':'Insufficient permission'},status_code=403,headers={'Cache-Control':'no-store'})
                if path.startswith('/api/sources/') and not can_refresh_sources(user): return JSONResponse({'detail':'Global source operator permission required'},status_code=403,headers={'Cache-Control':'no-store'})
            if (path=='/api/audit' or path.startswith('/api/audit/')) and user.role!='admin': return JSONResponse({'detail':'Insufficient permission'},status_code=403,headers={'Cache-Control':'no-store'})
    response=await call_next(request)
    if path.startswith('/api/'):
        response.headers['Cache-Control']='no-store'; response.headers['X-Content-Type-Options']='nosniff'
    return response

class LoginBody(BaseModel):
    username:str=Field(min_length=1,max_length=64)
    password:str=Field(min_length=1,max_length=256)
    otp:str|None=Field(default=None,max_length=20)
class InvestigationBody(BaseModel):
    title:str=Field(min_length=3,max_length=160)
class StatusBody(BaseModel):
    status:Literal['open','closed']
class AssetBody(BaseModel):
    name:str=Field(min_length=1,max_length=160)
    asset_type:Literal['domain','ip','application','cloud_resource','other']
    identifier:str=Field(min_length=1,max_length=512)
    owner:str=Field(min_length=1,max_length=160)
    scope_basis:str=Field(min_length=3,max_length=2000)
    authorized:StrictBool
class AssetStatusBody(BaseModel):
    status:Literal['active','retired']
    authorized:StrictBool=False
class AssetLinkBody(BaseModel):
    asset_id:int=Field(gt=0)
class TechniqueLinkBody(BaseModel):
    technique_id:str=Field(min_length=5,max_length=16)
class SbomLinkBody(BaseModel):
    sbom_id:int=Field(gt=0)
    attested:StrictBool
class SbomBody(BaseModel):
    name:str=Field(min_length=1,max_length=160)
    document:dict
class EvidenceBody(BaseModel):
    advisory_id:str=Field(min_length=1,max_length=40)
class NoteBody(BaseModel):
    content:str=Field(min_length=3,max_length=5000)
    classification:Literal['ANALYST ASSESSMENT','HYPOTHESIS','UNKNOWN']

@app.get('/api/health')
def health(): return {'status':'ok','mode':'demo' if DEMO else 'authentication-required','production_ready':False}

@app.get('/api/ready')
def ready():
    # Database connectivity and a minimal identity-schema check, not full readiness certification.
    try:
        with SessionLocal() as db:
            sample=db.execute(select(UserMfa.user_id,UserMfa.encrypted_secret).limit(1)).first()
            db.execute(select(Session.mfa_verified).limit(1)).first()
            if not DEMO and (REQUIRE_MFA or sample):
                mfa.key_from_env()
                if sample:mfa.decrypt_secret(sample.user_id,sample.encrypted_secret)
    except (SQLAlchemyError,mfa.MfaUnavailable):
        return JSONResponse({'status':'not_ready'},status_code=503)
    return {'status':'ready'}

@app.get('/api/auth/session')
def current_session(request:Request):
    if DEMO: return {'mode':'demo','role':'admin','authenticated':False,'can_refresh_global_sources':True,'workspace':{'slug':'default','name':'Default development workspace'}}
    with SessionLocal() as db:
        row=security.get_session(db,request.cookies.get('cicc_session',''),require_mfa=REQUIRE_MFA)
        if not row: raise HTTPException(401,'Authentication required')
        workspace=db.get(Workspace,row.User.workspace_id)
        return {'mode':'authenticated','role':row.User.role,'username':row.User.username,'authenticated':True,'mfa_enabled':db.get(UserMfa,row.User.id) is not None,'mfa_required':REQUIRE_MFA,'can_refresh_global_sources':can_refresh_sources(row.User),'workspace':{'slug':workspace.slug,'name':workspace.name}}

@app.post('/api/auth/login')
def login(body:LoginBody,request:Request,response:Response,db:DbSession=Depends(get_db)):
    if DEMO: raise HTTPException(400,'Login unavailable in demo mode')
    try: username=security.username_normalize(body.username)
    except ValueError: username=''
    timestamp=utcnow(); account=security.digest(username); client=security.digest(request.client.host if request.client else 'unknown')
    failures=db.scalar(select(func.count()).select_from(LoginAttempt).where(LoginAttempt.account_hash==account,LoginAttempt.success.is_(False),LoginAttempt.created_at>timestamp-timedelta(minutes=15)))
    recent=db.scalar(select(func.count()).select_from(LoginAttempt).where(LoginAttempt.client_hash==client,LoginAttempt.created_at>timestamp-timedelta(minutes=1)))
    if failures>=5 or recent>=30: raise HTTPException(429,'Too many attempts')
    # PostgreSQL serializes login with supported workspace lifecycle changes. SQLite
    # has no equivalent row locks and remains development-only.
    workspace=db.scalar(select(Workspace).join(User,User.workspace_id==Workspace.id).where(User.username==username,User.active.is_(True),User.role.in_(security.VALID_ROLES),Workspace.active.is_(True)).with_for_update(of=Workspace,key_share=True))
    user=db.scalar(select(User).where(User.username==username,User.workspace_id==workspace.id,User.active.is_(True),User.role.in_(security.VALID_ROLES)).with_for_update(of=User)) if workspace else None
    dummy='scrypt$16384$8$1$'+'00'*16+'$'+'00'*32
    valid=security.check_password(body.password,user.password_hash if user else dummy)
    record=db.get(UserMfa,user.id) if user and valid else None
    if user and valid and REQUIRE_MFA and not record:valid=False
    if record:
        try:valid=mfa.consume_code(db,user.id,record,body.otp)
        except mfa.MfaUnavailable as exc:
            db.rollback();raise HTTPException(503,'Authentication temporarily unavailable') from exc
    db.add(LoginAttempt(account_hash=account,client_hash=client,success=bool(user and valid)))
    if not user or not valid:
        write_audit(db,'unknown','auth.login_failed',workspace_id=user.workspace_id if user else None); db.commit(); raise HTTPException(401,'Invalid credentials')
    db.execute(delete(LoginAttempt).where(LoginAttempt.account_hash==account,LoginAttempt.success.is_(False)))
    previous=request.cookies.get('cicc_session','')
    if previous: db.execute(delete(Session).where(Session.token_hash==security.digest(previous)))
    token,csrf=security.create_session(db,user.id,mfa_verified=record is not None); write_audit(db,user.username,'auth.login',workspace_id=user.workspace_id); db.commit()
    response.set_cookie('cicc_session',token,secure=COOKIE_SECURE,httponly=True,samesite='strict',path='/',max_age=43200)
    response.set_cookie('cicc_csrf',csrf,secure=COOKIE_SECURE,httponly=False,samesite='strict',path='/',max_age=43200)
    workspace=db.get(Workspace,user.workspace_id)
    return {'mode':'authenticated','role':user.role,'username':user.username,'authenticated':True,'mfa_enabled':record is not None,'mfa_required':REQUIRE_MFA,'can_refresh_global_sources':can_refresh_sources(user),'workspace':{'slug':workspace.slug,'name':workspace.name}}

@app.post('/api/auth/logout')
def logout(request:Request,response:Response,db:DbSession=Depends(get_db)):
    if not DEMO:
        db.execute(delete(Session).where(Session.token_hash==security.digest(request.cookies.get('cicc_session','')))); write_audit(db,request,'auth.logout'); db.commit()
    response.delete_cookie('cicc_session',path='/',secure=COOKIE_SECURE,httponly=True,samesite='strict'); response.delete_cookie('cicc_csrf',path='/',secure=COOKIE_SECURE,samesite='strict')
    return {'ok':True}

@app.post('/api/auth/sessions/revoke-others')
def revoke_other_sessions(request:Request,db:DbSession=Depends(get_db)):
    if DEMO: raise HTTPException(400,'Session management unavailable in demo mode')
    current=security.digest(request.cookies.get('cicc_session',''))
    result=db.execute(delete(Session).where(Session.user_id==request.state.user_id,Session.token_hash!=current))
    count=result.rowcount
    write_audit(db,request,'auth.sessions_revoked',f'{count} other sessions')
    db.commit()
    return {'revoked':count}

@app.get('/api/sources')
def list_sources(db:DbSession=Depends(get_db)):
    return [source_dict(k,db.get(Source,k)) for k in ('github','cisa','mitre','attack','epss')]

def reserve_source_attempt(db,source_id):
    # One short transaction reserves a monotonic per-source ticket before I/O.
    db.execute(text('INSERT INTO sources(id,count) VALUES (:id,0) ON CONFLICT (id) DO NOTHING'),{'id':source_id})
    sequence=db.execute(text('UPDATE sources SET attempt_sequence=attempt_sequence+1 WHERE id=:id RETURNING attempt_sequence'),{'id':source_id}).scalar_one()
    db.commit()
    return sequence


def lock_source_record(db,source_id):
    return db.scalar(select(Source).where(Source.id==source_id).with_for_update())


def source_attempt_superseded(source,sequence):
    return source is None or source.completed_sequence>=sequence


def superseded_refresh(db,request,source_id):
    write_audit(db,request,'source.refresh_superseded',source_id);db.commit()
    return JSONResponse({'detail':'A newer source refresh has already completed'},status_code=409)


@app.post('/api/sources/{source_id}/refresh')
def refresh_source(source_id:str,request:Request,db:DbSession=Depends(get_db)):
    if source_id not in ('github','cisa','mitre','attack','epss'): raise HTTPException(404,'Source not found')
    attempted=utcnow(); sequence=reserve_source_attempt(db,source_id)
    try:
        if source_id=='github': data=sources.github_advisories()
        elif source_id=='cisa': data=sources.cisa_kev()
        elif source_id=='attack': data=sources.attack_sample()
        else:
            import re
            identifiers=[]
            max_ids=30 if source_id=='epss' else 10
            for cve in db.scalars(select(Advisory.cve).where(Advisory.cve.is_not(None)).order_by(Advisory.published_at.desc()).limit(100)).all():
                if cve and re.fullmatch(r'CVE-\d{4}-\d{4,12}',cve) and cve not in identifiers: identifiers.append(cve)
                if len(identifiers)==max_ids: break
            if not identifiers: raise ValueError('Collect GitHub advisories with CVE identifiers first')
            data=sources.epss_scores(identifiers) if source_id=='epss' else [sources.mitre_cve(cve) for cve in identifiers]
        timestamp=utcnow(); source=lock_source_record(db,source_id)
        if source_attempt_superseded(source,sequence):return superseded_refresh(db,request,source_id)
        if source_id=='github':
            for item in data:
                row=db.get(Advisory,item['id']) or Advisory(id=item['id'])
                for key,value in item.items(): setattr(row,key,value)
                row.collected_at=timestamp; db.add(row)
            count=len(data)
        elif source_id=='cisa':
            db.execute(delete(KevEntry)); db.add_all([KevEntry(**item) for item in data['items']]); count=len(data['items'])
            source.version=data['version']; source.released_at=data['released_at']; source.reference=data['reference']
        elif source_id=='epss':
            db.execute(delete(EpssScore));db.add_all([EpssScore(**item,collected_at=timestamp) for item in data]);count=len(data)
        elif source_id=='mitre':
            for item in data:
                row=db.get(MitreCve,item['cve']) or MitreCve(cve=item['cve'])
                for key,value in item.items(): setattr(row,key,value)
                row.collected_at=timestamp; db.add(row)
            db.flush(); count=db.scalar(select(func.count()).select_from(MitreCve))
        else:
            for item in data:
                row=db.get(AttackTechnique,item['id']) or AttackTechnique(id=item['id'])
                for key,value in item.items(): setattr(row,key,value)
                row.collected_at=timestamp;db.add(row)
            db.flush();count=db.scalar(select(func.count()).select_from(AttackTechnique))
        source.last_success=timestamp; source.last_attempt=attempted; source.error=None; source.count=count;source.completed_sequence=sequence
        write_audit(db,request,'source.refresh',f'{source_id}: {count}'); db.commit()
        return {'imported':len(data) if source_id in ('mitre','attack') else count,'collected_at':timestamp}
    except (httpx.HTTPError,ValueError,TypeError,IntegrityError) as exc:
        db.rollback(); source=lock_source_record(db,source_id)
        if source_attempt_superseded(source,sequence):return superseded_refresh(db,request,source_id)
        source.last_attempt=attempted;source.completed_sequence=sequence; source.error='Database integrity error' if isinstance(exc,IntegrityError) else str(exc)[:300]; write_audit(db,request,'source.refresh_failed',source_id); db.commit()
        raise HTTPException(502,'Collection failed; cached data was retained') from exc

@app.get('/api/advisories')
def advisories(q:str=Query('',max_length=100),limit:int=Query(30,ge=1,le=100),offset:int=Query(0,ge=0,le=100000),db:DbSession=Depends(get_db)):
    pattern=f'%{q}%'; criteria=or_(Advisory.id.ilike(pattern),Advisory.cve.ilike(pattern),Advisory.summary.ilike(pattern))
    total=db.scalar(select(func.count()).select_from(Advisory).where(criteria)); rows=db.scalars(select(Advisory).where(criteria).order_by(Advisory.published_at.desc()).limit(limit).offset(offset)).all()
    catalog=db.get(Source,'cisa'); catalog=catalog if catalog and catalog.last_success else None
    cves=[a.cve for a in rows if a.cve]; listed=set(db.scalars(select(KevEntry.cve).where(KevEntry.cve.in_(cves))).all()) if cves else set()
    scores={x.cve:x for x in db.scalars(select(EpssScore).where(EpssScore.cve.in_(cves))).all()} if cves else {}
    return {'items':[advisory_dict(a,a.cve in listed,catalog,scores.get(a.cve)) for a in rows],'total':total,'limit':limit,'offset':offset}

@app.get('/api/kev')
def kev(q:str=Query('',max_length=100),limit:int=Query(30,ge=1,le=100),offset:int=Query(0,ge=0,le=100000),db:DbSession=Depends(get_db)):
    pattern=f'%{q}%'; criteria=or_(KevEntry.cve.ilike(pattern),KevEntry.vendor.ilike(pattern),KevEntry.product.ilike(pattern),KevEntry.title.ilike(pattern))
    total=db.scalar(select(func.count()).select_from(KevEntry).where(criteria)); entries=db.scalars(select(KevEntry).where(criteria).order_by(KevEntry.date_added.desc(),KevEntry.cve).limit(limit).offset(offset)).all()
    return {'items':[{'cve':x.cve,'vendor':x.vendor,'product':x.product,'title':x.title,'date_added':x.date_added,'description':x.description,'action':x.action,'due_date':x.due_date,'ransomware':x.ransomware} for x in entries],'total':total,'limit':limit,'offset':offset,'source':source_dict('cisa',db.get(Source,'cisa')),'classification':'SOURCE-REPORTED','verification_status':'UNVERIFIED'}


@app.get('/api/cves')
def cves(q:str=Query('',max_length=100),limit:int=Query(30,ge=1,le=100),offset:int=Query(0,ge=0,le=100000),db:DbSession=Depends(get_db)):
    pattern=f'%{q}%'; criteria=or_(MitreCve.cve.ilike(pattern),MitreCve.description.ilike(pattern),MitreCve.assigner.ilike(pattern))
    total=db.scalar(select(func.count()).select_from(MitreCve).where(criteria))
    rows=db.scalars(select(MitreCve).where(criteria).order_by(MitreCve.date_updated.desc(),MitreCve.cve).limit(limit).offset(offset)).all()
    ids=[x.cve for x in rows]
    scores={x.cve:x for x in db.scalars(select(EpssScore).where(EpssScore.cve.in_(ids))).all()} if ids else {}
    items=[]
    for x in rows:
        parts=x.cve.split('-'); path=f'cves/{parts[1]}/{parts[2][:-3]}xxx/{x.cve}.json'
        items.append({'cve':x.cve,'state':x.state,'description':x.description,'description_language':x.description_language,'assigner':x.assigner,'date_published':x.date_published,'date_updated':x.date_updated,'collected_at':as_utc(x.collected_at),'source_sha':x.source_sha,'epss':epss_dict(scores.get(x.cve)),'url':sources.MITRE_URL+'/blob/main/'+path,'classification':'SOURCE-REPORTED','verification_status':'UNVERIFIED'})
    return {'items':items,'total':total,'limit':limit,'offset':offset,'source':source_dict('mitre',db.get(Source,'mitre'))}

def technique_dict(x):
    path=x.id.replace('.','/')
    return {'id':x.id,'stix_id':x.stix_id,'name':x.name,'description':x.description,'tactics':x.tactics,'version':x.version,'modified':x.modified,'revoked':x.revoked,'deprecated':x.deprecated,'source_sha':x.source_sha,'collected_at':as_utc(x.collected_at),'url':'https://attack.mitre.org/techniques/'+path+'/', 'classification':'SOURCE-REPORTED','verification_status':'UNVERIFIED'}

@app.get('/api/techniques')
def list_techniques(q:str=Query('',max_length=100),limit:int=Query(30,ge=1,le=100),offset:int=Query(0,ge=0,le=100000),db:DbSession=Depends(get_db)):
    pattern=f'%{q}%';criteria=or_(AttackTechnique.id.ilike(pattern),AttackTechnique.name.ilike(pattern),AttackTechnique.description.ilike(pattern))
    total=db.scalar(select(func.count()).select_from(AttackTechnique).where(criteria))
    rows=db.scalars(select(AttackTechnique).where(criteria).order_by(AttackTechnique.id).limit(limit).offset(offset)).all()
    return {'items':[technique_dict(x) for x in rows],'total':total,'limit':limit,'offset':offset,'source':source_dict('attack',db.get(Source,'attack')),'limitations':['Only 10 lexicographically selected STIX files are fetched per refresh, not the full ATT&CK catalog.','Technique descriptions are reference material, not evidence of activity or attribution.']}

@app.get('/api/overview')
def overview(request:Request,db:DbSession=Depends(get_db)):
    return {'open_investigations':db.scalar(select(func.count()).select_from(Investigation).where(Investigation.status=='open',Investigation.workspace_id==request.state.workspace_id)),
            'advisories':db.scalar(select(func.count()).select_from(Advisory)),
            'kev_entries':db.scalar(select(func.count()).select_from(KevEntry))}

def asset_dict(x):
    return {'id':x.id,'name':x.name,'asset_type':x.asset_type,'identifier':x.identifier,'owner':x.owner,
            'scope_basis':x.scope_basis,'status':x.status,'created_by':x.created_by,
            'created_at':as_utc(x.created_at),'updated_at':as_utc(x.updated_at),
            'classification':'USER-ATTESTED','verification_status':'UNVERIFIED'}

@app.get('/api/assets')
def list_assets(request:Request,q:str=Query('',max_length=100),status:Literal['active','retired']|None=None,limit:int=Query(30,ge=1,le=100),offset:int=Query(0,ge=0,le=100000),db:DbSession=Depends(get_db)):
    pattern=f'%{q}%'; filters=[Asset.workspace_id==request.state.workspace_id,or_(Asset.name.ilike(pattern),Asset.identifier.ilike(pattern),Asset.owner.ilike(pattern))]
    if status: filters.append(Asset.status==status)
    count=db.scalar(select(func.count()).select_from(Asset).where(*filters))
    rows=db.scalars(select(Asset).where(*filters).order_by(Asset.id.desc()).limit(limit).offset(offset)).all()
    return {'items':[asset_dict(x) for x in rows],'total':count,'limit':limit,'offset':offset,
            'limitations':['User-attested scope is not independently verified.','No scanning or exposure assessment is performed.']}

def validate_asset_metadata(body:AssetBody):
    if not body.authorized: raise HTTPException(422,'Authorization attestation is required')
    name,identifier,owner,basis=body.name.strip(),body.identifier.strip(),body.owner.strip(),body.scope_basis.strip()
    if not name or not identifier or not owner or len(basis)<3 or any(ord(c)<32 or ord(c)==127 for c in identifier):
        raise HTTPException(422,'Invalid asset metadata')
    return {'name':name,'asset_type':body.asset_type,'identifier':identifier,'owner':owner,'scope_basis':basis}

@app.post('/api/assets',status_code=201)
def create_asset(body:AssetBody,request:Request,db:DbSession=Depends(get_db)):
    values=validate_asset_metadata(body)
    obj=Asset(**values,status='active',created_by=request.state.actor,workspace_id=request.state.workspace_id)
    db.add(obj);db.flush();write_audit(db,request,'asset.created',str(obj.id));db.commit()
    return asset_dict(obj)

@app.get('/api/assets/{id}')
def asset_detail(id:int,request:Request,db:DbSession=Depends(get_db)):
    obj=scoped(db,Asset,id,request)
    if not obj: raise HTTPException(404,'Asset not found')
    return asset_dict(obj)

@app.put('/api/assets/{id}/metadata')
def update_asset_metadata(id:int,body:AssetBody,request:Request,db:DbSession=Depends(get_db)):
    obj=scoped(db,Asset,id,request,lock=True)
    if not obj: raise HTTPException(404,'Asset not found')
    if obj.status!='active': raise HTTPException(409,'Only active assets can be edited')
    values=validate_asset_metadata(body)
    if values['identifier']!=obj.identifier or values['asset_type']!=obj.asset_type:
        has_case=db.scalar(select(InvestigationAsset.id).where(InvestigationAsset.asset_id==id).limit(1))
        has_sbom=db.scalar(select(AssetSbom.id).where(AssetSbom.asset_id==id).limit(1))
        if has_case or has_sbom: raise HTTPException(409,'Linked asset identity cannot be changed; create a new asset')
    for key,value in values.items(): setattr(obj,key,value)
    obj.updated_at=utcnow();write_audit(db,request,'asset.metadata_updated',str(id));db.commit()
    return asset_dict(obj)

@app.patch('/api/assets/{id}')
def asset_status(id:int,body:AssetStatusBody,request:Request,db:DbSession=Depends(get_db)):
    obj=scoped(db,Asset,id,request,lock=True)
    if not obj: raise HTTPException(404,'Asset not found')
    if body.status=='active' and obj.status!='active' and not body.authorized: raise HTTPException(422,'Authorization attestation is required to reactivate')
    obj.status=body.status;obj.updated_at=utcnow();write_audit(db,request,'asset.status',f'{id}: {body.status}');db.commit()
    return asset_dict(obj)

@app.get('/api/assets/{id}/sboms')
def list_asset_sboms(id:int,request:Request,db:DbSession=Depends(get_db)):
    if not scoped(db,Asset,id,request): raise HTTPException(404,'Asset not found')
    links=db.scalars(select(AssetSbom).join(Sbom,AssetSbom.sbom_id==Sbom.id).where(AssetSbom.asset_id==id,Sbom.workspace_id==request.state.workspace_id).order_by(AssetSbom.id.desc()).limit(100)).all()
    return {'items':[{'id':x.id,'sbom_id':x.sbom_id,'snapshot':x.snapshot,'linked_by':x.linked_by,'linked_at':as_utc(x.linked_at)} for x in links],
            'limitations':['The association is user-attested, not proof that the SBOM is deployed on the asset.','Candidate advisories are not confirmed vulnerabilities.','Latest 100 links only.']}

@app.post('/api/assets/{id}/sboms',status_code=201)
def link_asset_sbom(id:int,body:SbomLinkBody,request:Request,db:DbSession=Depends(get_db)):
    if not body.attested: raise HTTPException(422,'Association attestation is required')
    asset=scoped(db,Asset,id,request,lock=True)
    if not asset: raise HTTPException(404,'Asset not found')
    if asset.status!='active': raise HTTPException(409,'Only active assets can be linked')
    obj=scoped(db,Sbom,body.sbom_id,request)
    if not obj: raise HTTPException(404,'SBOM not found')
    count=db.scalar(select(func.count()).select_from(SbomCandidate).join(SbomComponent,SbomCandidate.component_id==SbomComponent.id).where(SbomComponent.sbom_id==obj.id))
    snapshot={'id':obj.id,'name':obj.name,'format':obj.format,'component_count':obj.component_count,'candidate_count':count,'created_at':as_utc(obj.created_at).isoformat(),'classification':'USER-ATTESTED','verification_status':'UNVERIFIED'}
    link=AssetSbom(asset_id=id,sbom_id=obj.id,snapshot=snapshot,linked_by=request.state.actor);db.add(link)
    try:
        db.flush();write_audit(db,request,'asset.sbom_linked',f'{id}: {obj.id}');db.commit()
    except IntegrityError as exc:
        db.rollback();raise HTTPException(409,'SBOM already linked') from exc
    return {'id':link.id,'sbom_id':link.sbom_id,'snapshot':snapshot,'linked_by':link.linked_by,'linked_at':as_utc(link.linked_at)}

@app.get('/api/investigations')
def investigations(request:Request,db:DbSession=Depends(get_db)):
    rows=db.scalars(select(Investigation).where(Investigation.workspace_id==request.state.workspace_id).order_by(Investigation.id.desc()).limit(200)).all()
    return [{'id':r.id,'title':r.title,'status':r.status,'created_at':as_utc(r.created_at)} for r in rows]

@app.post('/api/investigations',status_code=201)
def create_investigation(body:InvestigationBody,request:Request,db:DbSession=Depends(get_db)):
    title=body.title.strip()
    if len(title)<3: raise HTTPException(422,'Title must contain at least three non-space characters')
    obj=Investigation(title=title,status='open',workspace_id=request.state.workspace_id); db.add(obj); db.flush(); investigation_event(db,obj.id,request.state.actor,'CASE_CREATED',{}); write_audit(db,request,'investigation.created',str(obj.id)); db.commit()
    return {'id':obj.id,'title':obj.title,'status':obj.status,'created_at':as_utc(obj.created_at)}

@app.patch('/api/investigations/{id}')
def set_investigation(id:int,body:StatusBody,request:Request,db:DbSession=Depends(get_db)):
    obj=scoped(db,Investigation,id,request)
    if not obj: raise HTTPException(404,'Investigation not found')
    previous=obj.status;obj.status=body.status
    if previous!=body.status: investigation_event(db,id,request.state.actor,'STATUS_CHANGED',{'from':previous,'to':body.status})
    write_audit(db,request,'investigation.status',f'{id}: {body.status}'); db.commit()
    return {'id':obj.id,'title':obj.title,'status':obj.status,'created_at':as_utc(obj.created_at)}

@app.get('/api/investigations/{id}')
def detail_investigation(id:int,request:Request,db:DbSession=Depends(get_db)):
    obj=scoped(db,Investigation,id,request)
    if not obj: raise HTTPException(404,'Investigation not found')
    evidence=db.scalars(select(Evidence).where(Evidence.investigation_id==id).order_by(Evidence.id.desc())).all(); notes=db.scalars(select(Note).where(Note.investigation_id==id).order_by(Note.id.desc())).all()
    assets=db.scalars(select(InvestigationAsset).join(Asset,InvestigationAsset.asset_id==Asset.id).where(InvestigationAsset.investigation_id==id,Asset.workspace_id==request.state.workspace_id).order_by(InvestigationAsset.id.desc())).all()
    techniques=db.scalars(select(InvestigationTechnique).where(InvestigationTechnique.investigation_id==id).order_by(InvestigationTechnique.id.desc())).all()
    return {'id':obj.id,'title':obj.title,'status':obj.status,'created_at':as_utc(obj.created_at),'evidence':[{'id':x.id,'snapshot':x.snapshot,'added_at':as_utc(x.added_at),'integrity':evidence_integrity(x)} for x in evidence],'notes':[{'id':x.id,'content':x.content,'classification':x.classification,'created_at':as_utc(x.created_at)} for x in notes],'assets':[{'id':x.id,'asset_id':x.asset_id,'snapshot':x.snapshot,'linked_by':x.linked_by,'linked_at':as_utc(x.linked_at)} for x in assets],'techniques':[{'id':x.id,'technique_id':x.technique_id,'snapshot':x.snapshot,'linked_by':x.linked_by,'linked_at':as_utc(x.linked_at)} for x in techniques]}

@app.post('/api/investigations/{id}/assets',status_code=201)
def link_investigation_asset(id:int,body:AssetLinkBody,request:Request,db:DbSession=Depends(get_db)):
    if not scoped(db,Investigation,id,request): raise HTTPException(404,'Investigation not found')
    asset=scoped(db,Asset,body.asset_id,request,lock=True)
    if not asset: raise HTTPException(404,'Asset not found')
    if asset.status!='active': raise HTTPException(409,'Only active assets can be linked')
    snapshot=asset_dict(asset)
    for key in ('created_at','updated_at'): snapshot[key]=snapshot[key].isoformat()
    link=InvestigationAsset(investigation_id=id,asset_id=asset.id,snapshot=snapshot,linked_by=request.state.actor);db.add(link)
    try:
        db.flush();investigation_event(db,id,request.state.actor,'ASSET_LINKED',{'asset_id':asset.id,'link_id':link.id});write_audit(db,request,'asset.linked',f'{id}: {asset.id}');db.commit()
    except IntegrityError as exc:
        db.rollback();raise HTTPException(409,'Asset already linked') from exc
    return {'id':link.id,'asset_id':asset.id,'snapshot':snapshot,'linked_by':link.linked_by,'linked_at':as_utc(link.linked_at)}

@app.post('/api/investigations/{id}/techniques',status_code=201)
def link_investigation_technique(id:int,body:TechniqueLinkBody,request:Request,db:DbSession=Depends(get_db)):
    if not scoped(db,Investigation,id,request): raise HTTPException(404,'Investigation not found')
    item=db.get(AttackTechnique,body.technique_id)
    if not item: raise HTTPException(404,'Technique not found')
    if item.revoked or item.deprecated: raise HTTPException(409,'Retired technique cannot be newly linked')
    snapshot=technique_dict(item);snapshot['collected_at']=snapshot['collected_at'].isoformat()
    link=InvestigationTechnique(investigation_id=id,technique_id=item.id,snapshot=snapshot,linked_by=request.state.actor);db.add(link)
    try:
        db.flush();investigation_event(db,id,request.state.actor,'TECHNIQUE_LINKED',{'technique_id':item.id,'link_id':link.id});write_audit(db,request,'technique.linked',f'{id}: {item.id}');db.commit()
    except IntegrityError as exc:
        db.rollback();raise HTTPException(409,'Technique already linked') from exc
    return {'id':link.id,'technique_id':item.id,'snapshot':snapshot,'linked_by':link.linked_by,'linked_at':as_utc(link.linked_at)}

@app.post('/api/investigations/{id}/evidence',status_code=201)
def link_evidence(id:int,body:EvidenceBody,request:Request,db:DbSession=Depends(get_db)):
    if not scoped(db,Investigation,id,request): raise HTTPException(404,'Investigation not found')
    advisory=db.get(Advisory,body.advisory_id)
    if not advisory: raise HTTPException(404,'Advisory not found')
    snapshot=advisory_dict(advisory); snapshot['collected_at']=as_utc(advisory.collected_at).isoformat()
    entry=Evidence(investigation_id=id,advisory_id=advisory.id,snapshot=snapshot,snapshot_sha256=snapshot_checksum(snapshot)); db.add(entry)
    try:
        db.flush(); investigation_event(db,id,request.state.actor,'EVIDENCE_LINKED',{'advisory_id':advisory.id,'evidence_id':entry.id}); write_audit(db,request,'evidence.linked',f'{id}: {advisory.id}'); db.commit()
    except IntegrityError as exc:
        db.rollback(); raise HTTPException(409,'Advisory already linked') from exc
    return {'id':entry.id,'snapshot':snapshot,'added_at':as_utc(entry.added_at),'integrity':evidence_integrity(entry)}

@app.post('/api/investigations/{id}/notes',status_code=201)
def add_note(id:int,body:NoteBody,request:Request,db:DbSession=Depends(get_db)):
    if not scoped(db,Investigation,id,request): raise HTTPException(404,'Investigation not found')
    content=body.content.strip()
    if len(content)<3: raise HTTPException(422,'Note too short')
    note=Note(investigation_id=id,content=content,classification=body.classification); db.add(note); db.flush(); investigation_event(db,id,request.state.actor,'NOTE_ADDED',{'note_id':note.id,'classification':note.classification}); write_audit(db,request,'note.created',str(id)); db.commit()
    return {'id':note.id,'content':note.content,'classification':note.classification,'created_at':as_utc(note.created_at)}

@app.get('/api/investigations/{id}/timeline')
def investigation_timeline(id:int,request:Request,limit:int=Query(50,ge=1,le=100),before:int|None=Query(None,gt=0),db:DbSession=Depends(get_db)):
    if not scoped(db,Investigation,id,request): raise HTTPException(404,'Investigation not found')
    filters=[InvestigationEvent.investigation_id==id]
    if before is not None:filters.append(InvestigationEvent.id<before)
    rows=db.scalars(select(InvestigationEvent).where(*filters).order_by(InvestigationEvent.id.desc()).limit(limit+1)).all()
    more=len(rows)>limit;rows=rows[:limit]
    return {'items':[{'id':x.id,'event_type':x.event_type,'actor':x.actor,'details':x.details,'created_at':as_utc(x.created_at)} for x in rows],
            'next_before':rows[-1].id if more else None,'limitations':['Events are local and not tamper-resistant.','Events are recorded only from feature activation; earlier history was not backfilled.']}

@app.get('/api/investigations/{id}/report')
def report(id:int,request:Request,db:DbSession=Depends(get_db)):
    item=detail_investigation(id,request,db); timeline=investigation_timeline(id,request,limit=100,before=None,db=db); write_audit(db,request,'report.exported',str(id)); db.commit()
    return {'generated_at':utcnow(),'methodology':'Local investigation notes and snapshots of cached advisories.','limitations':['Source-reported material is not independently verified.','This report is not a complete risk assessment.','Workspace scoping is a development prototype, not production isolation; audit is not tamper-resistant.','Asset authorization is user-attested, not independently verified; no scanning or exposure analysis was performed.','ATT&CK references are not evidence of activity or attribution.','Timeline contains up to 100 recent events and does not include history before this feature was enabled.','Snapshot checksums are stored in the same database; they are not tamper-evident or proof of authenticity.'],'investigation':item,'timeline':timeline}

@app.get('/api/graph')
def graph(request:Request,db:DbSession=Depends(get_db)):
    rows=db.execute(select(Evidence,Investigation).join(Investigation,Evidence.investigation_id==Investigation.id).where(Investigation.workspace_id==request.state.workspace_id).order_by(Evidence.id.desc()).limit(300)).all()
    nodes={}; edges=[]
    for e,i in rows:
        a=f'investigation:{i.id}'; b=f'evidence:{e.id}'
        nodes[a]={'id':a,'type':'INVESTIGATION','label':i.title}; nodes[b]={'id':b,'type':'SOURCE_SNAPSHOT','label':e.snapshot.get('cve') or e.advisory_id,'url':e.snapshot['url']}
        edges.append({'id':f'evidence:{e.id}','from':a,'to':b,'type':'REFERENCES','timestamp':as_utc(e.added_at),'confidence':'NOT ASSESSED','classification':'SOURCE-REPORTED'})
    links=db.execute(select(InvestigationAsset,Investigation).join(Investigation,InvestigationAsset.investigation_id==Investigation.id).join(Asset,InvestigationAsset.asset_id==Asset.id).where(Investigation.workspace_id==request.state.workspace_id,Asset.workspace_id==request.state.workspace_id).order_by(InvestigationAsset.id.desc()).limit(300)).all()
    for link,case in links:
        a=f'investigation:{case.id}';b=f'asset-link:{link.id}'
        nodes[a]={'id':a,'type':'INVESTIGATION','label':case.title}
        nodes[b]={'id':b,'type':'ASSET_SNAPSHOT','label':link.snapshot['name']+' · '+link.snapshot['identifier']}
        edges.append({'id':f'asset-link:{link.id}','from':a,'to':b,'type':'SCOPES_ASSET','timestamp':as_utc(link.linked_at),'confidence':'NOT ASSESSED','classification':'USER-ATTESTED'})
    techniques=db.execute(select(InvestigationTechnique,Investigation).join(Investigation,InvestigationTechnique.investigation_id==Investigation.id).where(Investigation.workspace_id==request.state.workspace_id).order_by(InvestigationTechnique.id.desc()).limit(300)).all()
    for link,case in techniques:
        a=f'investigation:{case.id}';b=f'technique-link:{link.id}'
        nodes[a]={'id':a,'type':'INVESTIGATION','label':case.title}
        nodes[b]={'id':b,'type':'TECHNIQUE_SNAPSHOT','label':link.snapshot['id']+' · '+link.snapshot['name'],'url':link.snapshot['url']}
        edges.append({'id':f'technique-link:{link.id}','from':a,'to':b,'type':'REFERENCES_TECHNIQUE','timestamp':as_utc(link.linked_at),'confidence':'NOT ASSESSED','classification':'SOURCE-REPORTED'})
    return {'nodes':list(nodes.values()),'edges':edges,'limitations':['Explicit references only; no attribution, activity or exposure inferred.','Asset authorization is user-attested and unverified.','Up to 300 latest references of each type.']}

@app.get('/api/audit')
def audit(request:Request,db:DbSession=Depends(get_db)):
    rows=db.scalars(select(Audit).where(Audit.workspace_id==request.state.workspace_id).order_by(Audit.id.desc()).limit(100)).all()
    return [{'id':x.id,'actor':x.actor,'action':x.action,'detail':x.detail,'created_at':as_utc(x.created_at)} for x in rows]


@app.get('/api/audit/events')
def audit_events(request:Request,limit:int=Query(50,ge=1,le=100),before:int|None=Query(None,ge=1),action:str=Query('',max_length=100),db:DbSession=Depends(get_db)):
    filters=[Audit.workspace_id==request.state.workspace_id]
    if before is not None: filters.append(Audit.id<before)
    if action: filters.append(Audit.action==action)
    rows=db.scalars(select(Audit).where(*filters).order_by(Audit.id.desc()).limit(limit+1)).all()
    more=len(rows)>limit;rows=rows[:limit]
    return {'items':[{'id':x.id,'actor':x.actor,'action':x.action,'detail':x.detail,'created_at':as_utc(x.created_at)} for x in rows],
            'next_before':rows[-1].id if more else None,
            'limitations':['Local records can be modified; this is not a tamper-evident audit trail.', 'Unscoped failed or unknown login events are not visible here.', 'Public source caches and refreshes are shared across workspaces.']}


@app.post('/api/sboms',status_code=201)
def import_sbom(body:SbomBody,request:Request,db:DbSession=Depends(get_db)):
    name=body.name.strip()
    if not name: raise HTTPException(422,'Name is required')
    if len(json.dumps(body.document,ensure_ascii=False).encode('utf-8'))>1024*1024: raise HTTPException(413,'SBOM exceeds 1 MiB')
    try: fmt,components=sbom.extract(body.document)
    except ValueError as exc: raise HTTPException(422,str(exc)) from exc
    obj=Sbom(name=name,format=fmt,component_count=len(components),workspace_id=request.state.workspace_id); db.add(obj); db.flush()
    index={}
    for advisory in db.scalars(select(Advisory)).all():
        entries=advisory.raw.get('vulnerabilities',[]) if isinstance(advisory.raw,dict) else []
        if not isinstance(entries,list): continue
        for v in entries:
            package=v.get('package',{}) if isinstance(v,dict) else {}
            if not isinstance(package,dict): continue
            eco,name_=package.get('ecosystem'),package.get('name')
            if not isinstance(eco,str) or not isinstance(name_,str): continue
            eco=sbom.ECOSYSTEMS.get(eco.lower())
            if not eco: continue
            records=index.setdefault((eco,sbom.normalize(eco,name_)),{})
            if advisory.id not in records:
                snapshot=advisory_dict(advisory); snapshot['collected_at']=as_utc(advisory.collected_at).isoformat(); snapshot['vulnerable_version_ranges']=[]
                records[advisory.id]=snapshot
            # Distinct entries for the same package/advisory are alternative ranges.
            records[advisory.id]['vulnerable_version_ranges'].append(v.get('vulnerable_version_range'))
    count=0
    for item in components:
        component=SbomComponent(sbom_id=obj.id,**item); db.add(component); db.flush()
        if component.ecosystem and component.package_name:
            for advisory_id,source_snapshot in index.get((component.ecosystem,sbom.normalize(component.ecosystem,component.package_name)),{}).items():
                snapshot=dict(source_snapshot)
                parsed=sbom.parse_purl(component.purl)
                snapshot['version_assessment']=version_assessment.compare(component.ecosystem,component.version,parsed['version'] if parsed else None,snapshot['vulnerable_version_ranges'])
                db.add(SbomCandidate(component_id=component.id,advisory_id=advisory_id,snapshot=snapshot));count+=1
    write_audit(db,request,'sbom.imported',f'{obj.id}: {len(components)} components');db.commit()
    return {'id':obj.id,'name':obj.name,'format':obj.format,'created_at':as_utc(obj.created_at),'component_count':len(components),'candidate_count':count}

@app.get('/api/sboms')
def list_sboms(request:Request,db:DbSession=Depends(get_db)):
    items=db.scalars(select(Sbom).where(Sbom.workspace_id==request.state.workspace_id).order_by(Sbom.id.desc()).limit(100)).all()
    return [{'id':x.id,'name':x.name,'format':x.format,'created_at':as_utc(x.created_at),'component_count':x.component_count} for x in items]

@app.get('/api/sboms/{id}')
def sbom_detail(id:int,request:Request,db:DbSession=Depends(get_db)):
    obj=scoped(db,Sbom,id,request)
    if not obj:raise HTTPException(404,'SBOM not found')
    components=db.scalars(select(SbomComponent).where(SbomComponent.sbom_id==id).order_by(SbomComponent.id)).all()
    ids=[x.id for x in components]
    candidates=db.scalars(select(SbomCandidate).where(SbomCandidate.component_id.in_(ids)).order_by(SbomCandidate.id)).all() if ids else []
    return {'id':obj.id,'name':obj.name,'format':obj.format,'created_at':as_utc(obj.created_at),'components':[{'id':x.id,'name':x.name,'version':x.version,'purl':x.purl,'ecosystem':x.ecosystem,'package_name':x.package_name} for x in components],
            'candidates':[{'id':x.id,'component_id':x.component_id,'advisory_id':x.advisory_id,'snapshot':x.snapshot,'match_type':'PACKAGE_IDENTITY','version_evaluated':x.snapshot.get('version_assessment',{}).get('status') in ('IN_RANGE','OUT_OF_RANGE')} for x in candidates],
            'limitations':['Version comparisons cover only a limited stable-release subset for npm and PyPI; unsupported or ambiguous cases are unknown.','A range match is not a confirmed vulnerability; manually verify applicability.','Only cached GitHub advisories were checked at import time.','No matches or an out-of-range result do not imply safety.','Only top-level components are imported.']}
