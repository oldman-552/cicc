"""Development identity primitives; not a substitute for enterprise SSO/MFA."""
import hashlib, hmac, re, secrets
from datetime import datetime, timedelta, timezone
from sqlalchemy import select, delete, exists, or_
from .models import User, UserMfa, Session, Workspace

def digest(value: str) -> str: return hashlib.sha256(value.encode()).hexdigest()
def username_normalize(value: str) -> str:
    value=value.strip().lower()
    if not re.fullmatch(r'[a-z0-9][a-z0-9._-]{2,63}',value): raise ValueError('Invalid username')
    return value

def hash_password(password: str) -> str:
    if not 12 <= len(password) <= 256 or len(password.encode()) > 1024: raise ValueError('Password must be 12–256 characters')
    salt=secrets.token_bytes(16)
    value=hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1,dklen=32)
    return f'scrypt$16384$8$1${salt.hex()}${value.hex()}'

def check_password(password: str, encoded: str) -> bool:
    try:
        if len(password)>256 or len(password.encode())>1024: return False
        algo,n,r,p,salt,value=encoded.split('$')
        if (algo,n,r,p)!=('scrypt','16384','8','1'): return False
        salt_b,value_b=bytes.fromhex(salt),bytes.fromhex(value)
        if len(salt_b)!=16 or len(value_b)!=32: return False
        return hmac.compare_digest(hashlib.scrypt(password.encode(),salt=salt_b,n=16384,r=8,p=1,dklen=32),value_b)
    except (ValueError,TypeError,UnicodeError): return False

def upsert_user(db, username: str, password: str, role: str, workspace_id: int=1):
    username=username_normalize(username)
    if role not in ('admin','analyst','viewer'): raise ValueError('Invalid role')
    workspace=db.get(Workspace,workspace_id)
    if not workspace or not workspace.active: raise ValueError('Workspace not available')
    password_hash=hash_password(password)
    user=db.scalar(select(User).where(User.username==username).with_for_update())
    if user:
        if user.workspace_id!=workspace_id: raise ValueError('Moving accounts between workspaces is not supported')
        user.password_hash=password_hash; user.role=role; user.active=True
        db.execute(delete(Session).where(Session.user_id==user.id))
    else:
        user=User(username=username,password_hash=password_hash,role=role,active=True,workspace_id=workspace_id); db.add(user)
    db.flush(); return user

def create_session(db, user_id, mfa_verified=False):
    token,csrf=secrets.token_urlsafe(32),secrets.token_urlsafe(32)
    db.add(Session(token_hash=digest(token),csrf_hash=digest(csrf),user_id=user_id,mfa_verified=mfa_verified,expires_at=datetime.now(timezone.utc)+timedelta(hours=12)))
    return token,csrf

def get_session(db,token,require_mfa=False):
    if not token or len(token)>256: return None
    query=select(Session,User).join(User,Session.user_id==User.id).join(Workspace,Workspace.id==User.workspace_id).where(Session.token_hash==digest(token),Session.expires_at>datetime.now(timezone.utc),User.active.is_(True),Workspace.active.is_(True))
    enrollment=exists(select(UserMfa.user_id).where(UserMfa.user_id==User.id))
    query=query.where(or_(Session.mfa_verified.is_(True),~enrollment))
    if require_mfa:query=query.where(enrollment,Session.mfa_verified.is_(True))
    return db.execute(query).first()
