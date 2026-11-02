"""Optional TOTP for trusted-local development; encryption key stays outside the database."""
import argparse
import base64
import binascii
import getpass
import hmac
import os
import re
import secrets
import time
import pyotp
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import delete, select, update
from .db import SessionLocal
from .models import Audit, Session, User, UserMfa, Workspace, utcnow
from .security import username_normalize


class MfaUnavailable(Exception):
    """Missing or incorrect server key must fail closed for enrolled users."""


def key_from_env():
    encoded=os.environ.get('CICC_MFA_KEY','')
    try:
        if not isinstance(encoded,str):raise ValueError()
        key=base64.b64decode(encoded.encode('ascii'),altchars=b'-_',validate=True)
        if len(key)!=32:raise ValueError()
        return key
    except (ValueError,UnicodeError,binascii.Error) as exc:
        raise MfaUnavailable('MFA key is not configured correctly') from exc


def encrypt_secret(user_id,secret):
    nonce=secrets.token_bytes(12)
    return nonce+AESGCM(key_from_env()).encrypt(nonce,secret.encode('ascii'),b'cicc:mfa:v1:'+str(user_id).encode('ascii'))


def decrypt_secret(user_id,encrypted):
    try:
        if not isinstance(encrypted,bytes) or len(encrypted)<29:raise ValueError()
        return AESGCM(key_from_env()).decrypt(encrypted[:12],encrypted[12:],b'cicc:mfa:v1:'+str(user_id).encode('ascii')).decode('ascii')
    except (ValueError,UnicodeError,InvalidTag) as exc:
        raise MfaUnavailable('MFA secret cannot be decrypted') from exc


def match_counter(secret,code,now=None):
    if not isinstance(code,str) or not re.fullmatch(r'[0-9]{6}',code):return None
    counter=int(time.time() if now is None else now)//30
    totp=pyotp.TOTP(secret,digits=6,interval=30)
    for step in (counter,counter-1,counter+1):
        if step>=0 and hmac.compare_digest(totp.generate_otp(step),code):return step
    return None


def consume_code(db,user_id,record,code):
    secret=decrypt_secret(user_id,record.encrypted_secret)
    counter=match_counter(secret,code)
    if counter is None or counter<=record.last_counter:return False
    result=db.execute(update(UserMfa).where(UserMfa.user_id==user_id,UserMfa.last_counter<counter,UserMfa.encrypted_secret==record.encrypted_secret).values(last_counter=counter))
    return result.rowcount==1


def enroll(db,user,secret,code):
    """Caller must have locked and rechecked the active user in the transaction."""
    if db.get(UserMfa,user.id):raise ValueError('MFA is already enabled')
    counter=match_counter(secret,code)
    if counter is None:raise ValueError('Invalid authenticator code')
    encrypted=encrypt_secret(user.id,secret)
    db.add(UserMfa(user_id=user.id,encrypted_secret=encrypted,last_counter=counter,enabled_at=utcnow()))
    db.execute(delete(Session).where(Session.user_id==user.id))
    db.add(Audit(workspace_id=user.workspace_id,actor='local-cli',action='account.mfa_enabled',detail=user.username))
    db.flush()


def reset(db,user):
    """Trusted local recovery removes MFA and revokes sessions; never self-service."""
    if not db.get(UserMfa,user.id):raise ValueError('MFA is not enabled')
    db.execute(delete(UserMfa).where(UserMfa.user_id==user.id))
    db.execute(delete(Session).where(Session.user_id==user.id))
    db.add(Audit(workspace_id=user.workspace_id,actor='local-cli',action='account.mfa_reset',detail=user.username))
    db.flush()


def find_user(db,username,workspace,lock=False):
    query=select(User).join(Workspace,Workspace.id==User.workspace_id).where(User.username==username,Workspace.slug==workspace,User.active.is_(True),Workspace.active.is_(True))
    if lock:query=query.with_for_update(of=User)
    return db.scalar(query)


def main():
    parser=argparse.ArgumentParser(description='Trusted-local optional TOTP enrollment and recovery')
    parser.add_argument('action',choices=['enroll','reset']);parser.add_argument('username');parser.add_argument('--workspace',default='default')
    parser.add_argument('--confirm-reset',action='store_true',help='Required to remove MFA')
    args=parser.parse_args()
    try:username=username_normalize(args.username)
    except ValueError as exc:raise SystemExit(str(exc)) from exc
    if args.action=='reset' and not args.confirm_reset:parser.error('reset requires --confirm-reset')
    if args.action=='enroll':
        try:key_from_env()
        except MfaUnavailable as exc:raise SystemExit(str(exc)) from exc
        with SessionLocal() as db:
            user=find_user(db,username,args.workspace)
            if not user:raise SystemExit('Active account not found in workspace')
            if db.get(UserMfa,user.id):raise SystemExit('MFA is already enabled')
            user_id=user.id
        secret=pyotp.random_base32()
        print('Sensitive enrollment secret follows. Use a private trusted terminal; do not share or log it.')
        print(pyotp.TOTP(secret).provisioning_uri(name=username,issuer_name='CICC Development'))
        code=getpass.getpass('Authenticator code: ').strip()
        with SessionLocal.begin() as db:
            user=find_user(db,username,args.workspace,lock=True)
            if not user or user.id!=user_id:raise SystemExit('Account changed during enrollment')
            try:enroll(db,user,secret,code)
            except (ValueError,MfaUnavailable) as exc:raise SystemExit(str(exc)) from exc
        print('MFA enabled; previous sessions revoked. Use a new code when signing in.')
    else:
        with SessionLocal.begin() as db:
            user=find_user(db,username,args.workspace,lock=True)
            if not user:raise SystemExit('Active account not found in workspace')
            try:reset(db,user)
            except ValueError as exc:raise SystemExit(str(exc)) from exc
        print('MFA reset; previous sessions revoked. Enroll a new authenticator promptly.')

if __name__=='__main__':main()
