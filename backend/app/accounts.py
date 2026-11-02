import argparse, getpass
from .db import SessionLocal
from .security import upsert_user
from .models import Workspace
from sqlalchemy import select

def main():
    parser=argparse.ArgumentParser(description='Create or reset a local development account')
    parser.add_argument('username'); parser.add_argument('--role',choices=['admin','analyst','viewer'],default='admin'); parser.add_argument('--workspace',default='default')
    args=parser.parse_args(); password=getpass.getpass('Password (12–256 characters): ')
    if password!=getpass.getpass('Confirm password: '): raise SystemExit('Passwords do not match')
    with SessionLocal.begin() as db:
        workspace=db.scalar(select(Workspace).where(Workspace.slug==args.workspace,Workspace.active.is_(True)))
        if not workspace: raise SystemExit('Workspace not found or inactive')
        user=upsert_user(db,args.username,password,args.role,workspace_id=workspace.id)
        print(f'Configured {user.username} as {user.role} in workspace {workspace.slug}; previous sessions revoked.')
if __name__=='__main__': main()
