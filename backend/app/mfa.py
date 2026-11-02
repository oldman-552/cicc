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


def key_from_env(name='CICC_MFA_KEY'):
    encoded=os.environ.get(name,'')
    try:
        if not isinstance(encoded,str):raise ValueError()
        key=base64.b64decode(encoded.encode('ascii'),altchars=b'-_',validate=True)
        if len(key)!=32:raise ValueError()
        return key
    except (ValueError,UnicodeError,binascii.Error) as exc:
        raise MfaUnavailable('MFA key is not configured correctly') from exc


def encrypt_secret(user_id,secret,key=None):
    nonce=secrets.token_bytes(12)
    return nonce+AESGCM(key if key is not None else key_from_env()).encrypt(nonce,secret.encode('ascii'),b'cicc:mfa:v1:'+str(user_id).encode('ascii'))


def decrypt_secret(user_id,encrypted,key=None):
    try:
        if not isinstance(encrypted,bytes) or len(encrypted)<29:raise ValueError()
        return AESGCM(key if key is not None else key_from_env()).decrypt(encrypted[:12],encrypted[12:],b'cicc:mfa:v1:'+str(user_id).encode('ascii')).decode('ascii')
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



def rotate_key(db,old_key,new_key):
    """Offline-only; rotate every enrolled seed atomically and revoke affected sessions."""
    if len(old_key)!=32 or len(new_key)!=32 or hmac.compare_digest(old_key,new_key):raise ValueError('A different valid 32-byte key is required')
    rows=db.execute(select(User,UserMfa).join(UserMfa,UserMfa.user_id==User.id).order_by(User.id).limit(1001).with_for_update(of=(User,UserMfa))).all()
    if len(rows)>1000:raise ValueError('Offline rotation is limited to 1000 enrolled accounts')
    # Validate and encrypt every seed before changing any persisted row.
    replacements=[(user,record,encrypt_secret(user.id,decrypt_secret(user.id,record.encrypted_secret,old_key),new_key)) for user,record in rows]
    counts={}
    for user,record,ciphertext in replacements:
        record.encrypted_secret=ciphertext
        db.execute(delete(Session).where(Session.user_id==user.id))
        counts[user.workspace_id]=counts.get(user.workspace_id,0)+1
    for workspace_id,count in counts.items():
        db.add(Audit(workspace_id=workspace_id,actor='local-cli',action='account.mfa_key_rotated',detail=f'{count} enrolled accounts'))
    db.flush()
    return len(replacements)

def find_user(db,username,workspace,lock=False):
    query=select(User).join(Workspace,Workspace.id==User.workspace_id).where(User.username==username,Workspace.slug==workspace,User.active.is_(True),Workspace.active.is_(True))
    if lock:query=query.with_for_update(of=User)
    return db.scalar(query)


def main():
    parser=argparse.ArgumentParser(description='Trusted-local optional TOTP enrollment and recovery')
    parser.add_argument('action',choices=['enroll','reset','rotate-key']);parser.add_argument('username',nargs='?');parser.add_argument('--workspace')
    parser.add_argument('--confirm-reset',action='store_true',help='Required to remove MFA')
    parser.add_argument('--confirm-offline-rotation',action='store_true',help='Acknowledge that all API and account/MFA writers are stopped')
    args=parser.parse_args()
    if args.action=='rotate-key':
        if args.username or args.workspace is not None or args.confirm_reset or not args.confirm_offline_rotation:parser.error('rotate-key is global and requires --confirm-offline-rotation, with no username or workspace')
        try:
            old_key=key_from_env();new_key=key_from_env('CICC_MFA_NEW_KEY')
            with SessionLocal.begin() as db:count=rotate_key(db,old_key,new_key)
        except (ValueError,MfaUnavailable) as exc:raise SystemExit(str(exc)) from exc
        print(f'Rotated {count} enrolled accounts; affected sessions revoked. Start all APIs with the new key.')
        return
    if not args.username:parser.error('username is required')
    if args.action=='enroll' and args.confirm_reset:parser.error('--confirm-reset is only for reset')
    workspace=args.workspace or 'default'
    if args.confirm_offline_rotation:parser.error('--confirm-offline-rotation is only for rotate-key')
    try:username=username_normalize(args.username)
    except ValueError as exc:raise SystemExit(str(exc)) from exc
    if args.action=='reset' and not args.confirm_reset:parser.error('reset requires --confirm-reset')
    if args.action=='enroll':
        try:key_from_env()
        except MfaUnavailable as exc:raise SystemExit(str(exc)) from exc
        with SessionLocal() as db:
            user=find_user(db,username,workspace)
            if not user:raise SystemExit('Active account not found in workspace')
            if db.get(UserMfa,user.id):raise SystemExit('MFA is already enabled')
            user_id=user.id
        secret=pyotp.random_base32()
        print('Sensitive enrollment secret follows. Use a private trusted terminal; do not share or log it.')
        print(pyotp.TOTP(secret).provisioning_uri(name=username,issuer_name='CICC Development'))
        code=getpass.getpass('Authenticator code: ').strip()
        with SessionLocal.begin() as db:
            user=find_user(db,username,workspace,lock=True)
            if not user or user.id!=user_id:raise SystemExit('Account changed during enrollment')
            try:enroll(db,user,secret,code)
            except (ValueError,MfaUnavailable) as exc:raise SystemExit(str(exc)) from exc
        print('MFA enabled; previous sessions revoked. Use a new code when signing in.')
    else:
        with SessionLocal.begin() as db:
            user=find_user(db,username,workspace,lock=True)
            if not user:raise SystemExit('Active account not found in workspace')
            try:reset(db,user)
            except ValueError as exc:raise SystemExit(str(exc)) from exc
        print('MFA reset; previous sessions revoked. Enroll a new authenticator promptly.')

if __name__=='__main__':main()
