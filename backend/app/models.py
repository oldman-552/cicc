from datetime import datetime, timezone
from sqlalchemy import String, Text, DateTime, ForeignKey, Integer, BigInteger, LargeBinary, Boolean, JSON, UniqueConstraint, Index, event, inspect, false
from sqlalchemy.orm import Mapped, mapped_column, Session as OrmSession
from .db import Base

def utcnow(): return datetime.now(timezone.utc)

class Workspace(Base):
    __tablename__='workspaces'
    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(String(64),unique=True,index=True)
    name: Mapped[str] = mapped_column(String(160))
    active: Mapped[bool] = mapped_column(Boolean,default=True)

class User(Base):
    __tablename__='users'
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey('workspaces.id',name='cicc_users_workspace_fk'),index=True)
    username: Mapped[str] = mapped_column(String(64),unique=True,index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(20))
    active: Mapped[bool] = mapped_column(Boolean,default=True)

class Session(Base):
    __tablename__='sessions'
    token_hash: Mapped[str] = mapped_column(String(64),primary_key=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    mfa_verified: Mapped[bool] = mapped_column(Boolean,default=False,server_default=false())
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id',ondelete='CASCADE'),index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

class UserMfa(Base):
    __tablename__='user_mfa'
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id',ondelete='CASCADE'),primary_key=True)
    encrypted_secret: Mapped[bytes] = mapped_column(LargeBinary)
    last_counter: Mapped[int] = mapped_column(BigInteger)
    enabled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),default=utcnow)


class LoginAttempt(Base):
    __tablename__='login_attempts'
    id: Mapped[int] = mapped_column(primary_key=True)
    account_hash: Mapped[str] = mapped_column(String(64),index=True)
    client_hash: Mapped[str] = mapped_column(String(64),index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),default=utcnow,index=True)
    success: Mapped[bool] = mapped_column(Boolean)

class Source(Base):
    __tablename__='sources'
    id: Mapped[str] = mapped_column(String(50),primary_key=True)
    last_success: Mapped[datetime|None] = mapped_column(DateTime(timezone=True))
    last_attempt: Mapped[datetime|None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str|None] = mapped_column(Text)
    count: Mapped[int] = mapped_column(Integer,default=0)
    version: Mapped[str|None] = mapped_column(String(100))
    released_at: Mapped[str|None] = mapped_column(String(100))
    reference: Mapped[str|None] = mapped_column(String(128))

class Advisory(Base):
    __tablename__='advisories'
    id: Mapped[str] = mapped_column(String(40),primary_key=True)
    cve: Mapped[str|None] = mapped_column(String(32),index=True)
    summary: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20))
    url: Mapped[str] = mapped_column(String(512))
    published_at: Mapped[str|None] = mapped_column(String(50),index=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    raw: Mapped[dict] = mapped_column(JSON)

class KevEntry(Base):
    __tablename__='kev_entries'
    cve: Mapped[str] = mapped_column(String(32),primary_key=True)
    vendor: Mapped[str] = mapped_column(String(300),index=True)
    product: Mapped[str] = mapped_column(String(300),index=True)
    title: Mapped[str] = mapped_column(Text)
    date_added: Mapped[str] = mapped_column(String(20),index=True)
    description: Mapped[str] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text)
    due_date: Mapped[str] = mapped_column(String(20))
    ransomware: Mapped[str] = mapped_column(String(50))

class Investigation(Base):
    __tablename__='investigations'
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey('workspaces.id',name='cicc_investigations_workspace_fk'),index=True)
    title: Mapped[str] = mapped_column(String(160))
    status: Mapped[str] = mapped_column(String(20),default='open')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),default=utcnow)

class Evidence(Base):
    __tablename__='evidence'
    __table_args__=(UniqueConstraint('investigation_id','advisory_id',name='uq_evidence_link'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey('investigations.id'),index=True)
    advisory_id: Mapped[str] = mapped_column(String(40))
    snapshot: Mapped[dict] = mapped_column(JSON)
    snapshot_sha256: Mapped[str|None] = mapped_column(String(64))
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),default=utcnow)

class Note(Base):
    __tablename__='notes'
    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey('investigations.id'),index=True)
    content: Mapped[str] = mapped_column(Text)
    classification: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),default=utcnow)

class Audit(Base):
    __tablename__='audit'
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int|None] = mapped_column(ForeignKey('workspaces.id',name='cicc_audit_workspace_fk'),index=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(80))
    detail: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),default=utcnow,index=True)

class Sbom(Base):
    __tablename__='sboms'
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey('workspaces.id',name='cicc_sboms_workspace_fk'),index=True)
    name: Mapped[str] = mapped_column(String(160))
    format: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),default=utcnow)
    component_count: Mapped[int] = mapped_column(Integer)

class SbomComponent(Base):
    __tablename__='sbom_components'
    id: Mapped[int] = mapped_column(primary_key=True)
    sbom_id: Mapped[int] = mapped_column(ForeignKey('sboms.id'),index=True)
    name: Mapped[str] = mapped_column(String(512))
    version: Mapped[str|None] = mapped_column(String(512))
    purl: Mapped[str|None] = mapped_column(String(2048))
    ecosystem: Mapped[str|None] = mapped_column(String(30))
    package_name: Mapped[str|None] = mapped_column(String(512))

class SbomCandidate(Base):
    __tablename__='sbom_candidates'
    __table_args__=(UniqueConstraint('component_id','advisory_id',name='uq_sbom_candidate'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    component_id: Mapped[int] = mapped_column(ForeignKey('sbom_components.id'),index=True)
    advisory_id: Mapped[str] = mapped_column(String(40))
    snapshot: Mapped[dict] = mapped_column(JSON)

class EpssScore(Base):
    __tablename__='epss_scores'
    cve: Mapped[str] = mapped_column(String(32),primary_key=True)
    score: Mapped[str] = mapped_column(String(16))
    percentile: Mapped[str] = mapped_column(String(16))
    score_date: Mapped[str] = mapped_column(String(10))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class MitreCve(Base):
    __tablename__='mitre_cves'
    cve: Mapped[str] = mapped_column(String(32),primary_key=True)
    state: Mapped[str] = mapped_column(String(30))
    description: Mapped[str] = mapped_column(Text)
    description_language: Mapped[str|None] = mapped_column(String(30))
    assigner: Mapped[str|None] = mapped_column(String(200))
    date_published: Mapped[str|None] = mapped_column(String(100))
    date_updated: Mapped[str|None] = mapped_column(String(100))
    source_sha: Mapped[str] = mapped_column(String(40))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

class Asset(Base):
    __tablename__='assets'
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey('workspaces.id',name='cicc_assets_workspace_fk'),index=True)
    name: Mapped[str] = mapped_column(String(160))
    asset_type: Mapped[str] = mapped_column(String(30),index=True)
    identifier: Mapped[str] = mapped_column(String(512),index=True)
    owner: Mapped[str] = mapped_column(String(160))
    scope_basis: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20),default='active',index=True)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),default=utcnow)

class InvestigationAsset(Base):
    __tablename__='investigation_assets'
    __table_args__=(UniqueConstraint('investigation_id','asset_id',name='uq_investigation_asset'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey('investigations.id'),index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey('assets.id'),index=True)
    snapshot: Mapped[dict] = mapped_column(JSON)
    linked_by: Mapped[str] = mapped_column(String(64))
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),default=utcnow)

class AssetSbom(Base):
    __tablename__='asset_sboms'
    __table_args__=(UniqueConstraint('asset_id','sbom_id',name='uq_asset_sbom'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey('assets.id'),index=True)
    sbom_id: Mapped[int] = mapped_column(ForeignKey('sboms.id'),index=True)
    snapshot: Mapped[dict] = mapped_column(JSON)
    linked_by: Mapped[str] = mapped_column(String(64))
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),default=utcnow)

class AttackTechnique(Base):
    __tablename__='attack_techniques'
    id: Mapped[str] = mapped_column(String(16),primary_key=True)
    stix_id: Mapped[str] = mapped_column(String(64),unique=True)
    name: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text)
    tactics: Mapped[list] = mapped_column(JSON)
    version: Mapped[str|None] = mapped_column(String(30))
    modified: Mapped[str|None] = mapped_column(String(60))
    revoked: Mapped[bool] = mapped_column(Boolean,default=False)
    deprecated: Mapped[bool] = mapped_column(Boolean,default=False)
    source_sha: Mapped[str] = mapped_column(String(40))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

class InvestigationTechnique(Base):
    __tablename__='investigation_techniques'
    __table_args__=(UniqueConstraint('investigation_id','technique_id',name='uq_investigation_technique'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey('investigations.id'),index=True)
    technique_id: Mapped[str] = mapped_column(String(16),index=True)
    snapshot: Mapped[dict] = mapped_column(JSON)
    linked_by: Mapped[str] = mapped_column(String(64))
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),default=utcnow)

class InvestigationEvent(Base):
    __tablename__='investigation_events'
    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey('investigations.id'),index=True)
    event_type: Mapped[str] = mapped_column(String(40))
    actor: Mapped[str] = mapped_column(String(64))
    details: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),default=utcnow)

@event.listens_for(OrmSession,'before_flush')
def require_explicit_workspace(session, _flush_context, _instances):
    # Guard ORM writes; direct SQL and database administrators are outside this boundary.
    for obj in session.new:
        if isinstance(obj,(User,Investigation,Asset,Sbom)) and (type(obj.workspace_id) is not int or obj.workspace_id<1):
            raise ValueError('Explicit workspace_id is required')
    for obj in session.dirty:
        if isinstance(obj,(User,Investigation,Asset,Sbom)) and inspect(obj).attrs.workspace_id.history.has_changes():
            raise ValueError('Moving records between workspaces is not supported')
