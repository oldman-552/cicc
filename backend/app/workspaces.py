"""Local workspace administration for development; not a self-service tenant manager."""
import argparse
import re
from sqlalchemy import select
from .db import SessionLocal
from .models import Audit, Workspace


def create_workspace(db,slug,name):
    slug=slug.strip().lower();name=name.strip()
    if len(slug)>40 or not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*',slug): raise ValueError('Invalid workspace slug')
    if not name or len(name)>160: raise ValueError('Invalid workspace name')
    if db.scalar(select(Workspace).where(Workspace.slug==slug)): raise ValueError('Workspace already exists')
    obj=Workspace(slug=slug,name=name,active=True);db.add(obj);db.flush();return obj


def main():
    parser=argparse.ArgumentParser(description='Create a local development workspace')
    parser.add_argument('slug');parser.add_argument('name');args=parser.parse_args()
    with SessionLocal.begin() as db:
        workspace=create_workspace(db,args.slug,args.name)
        db.add(Audit(workspace_id=workspace.id,actor='local-cli',action='workspace.created',detail=workspace.slug))
        message=f'Created workspace {workspace.slug} (id {workspace.id}).'
    print(message)

if __name__=='__main__':main()
