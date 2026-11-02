"""Trusted-local development account management, not a substitute for IAM/SSO."""
import argparse, getpass
from sqlalchemy import delete, select
from .db import SessionLocal
from .security import upsert_user, username_normalize
from .models import Audit, Session, User, Workspace


def configure_account(db, username, password, role, workspace_id):
    user=upsert_user(db,username,password,role,workspace_id=workspace_id)
    db.add(Audit(workspace_id=workspace_id,actor='local-cli',action='account.configured',detail=f'{user.username}: {user.role}'))
    return user


def disable_account(db, username, workspace_id):
    username=username_normalize(username)
    user=db.scalar(select(User).where(User.username==username,User.workspace_id==workspace_id).with_for_update())
    if not user: raise ValueError('Account not found in workspace')
    user.active=False
    db.execute(delete(Session).where(Session.user_id==user.id))
    db.add(Audit(workspace_id=workspace_id,actor='local-cli',action='account.disabled',detail=user.username))
    db.flush()
    return user


def main():
    parser=argparse.ArgumentParser(description='Create, reset or disable a local development account')
    parser.add_argument('username');parser.add_argument('--role',choices=['admin','analyst','viewer']);parser.add_argument('--workspace',default='default')
    parser.add_argument('--disable',action='store_true',help='Disable the account and revoke its sessions; no password prompt')
    args=parser.parse_args()
    if args.disable and args.role: parser.error('--role cannot be used with --disable')
    password=None
    if not args.disable:
        password=getpass.getpass('Password (12–256 characters): ')
        if password!=getpass.getpass('Confirm password: '): raise SystemExit('Passwords do not match')
    with SessionLocal.begin() as db:
        workspace=db.scalar(select(Workspace).where(Workspace.slug==args.workspace))
        if not workspace or (not workspace.active and not args.disable): raise SystemExit('Workspace not found or inactive')
        try:
            if args.disable:
                user=disable_account(db,args.username,workspace.id)
                message=f'Disabled {user.username} in workspace {workspace.slug}; sessions revoked.'
            else:
                user=configure_account(db,args.username,password,args.role or 'admin',workspace.id)
                message=f'Configured {user.username} as {user.role} in workspace {workspace.slug}; previous sessions revoked.'
        except ValueError as exc: raise SystemExit(str(exc)) from exc
    print(message)

if __name__=='__main__':main()
