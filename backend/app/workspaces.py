"""Local workspace administration for development; not a self-service tenant manager."""
import argparse
import re
from sqlalchemy import delete, select
from .db import SessionLocal
from .models import Audit, Session, User, Workspace


def create_workspace(db,slug,name):
    slug=slug.strip().lower();name=name.strip()
    if len(slug)>40 or not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*',slug): raise ValueError('Invalid workspace slug')
    if not name or len(name)>160: raise ValueError('Invalid workspace name')
    if db.scalar(select(Workspace).where(Workspace.slug==slug)): raise ValueError('Workspace already exists')
    obj=Workspace(slug=slug,name=name,active=True);db.add(obj);db.flush();return obj



def set_workspace_active(db,slug,active):
    """Trusted CLI only; revoke all sessions on either transition."""
    workspace=db.scalar(select(Workspace).where(Workspace.slug==slug).with_for_update(key_share=True))
    if not workspace:raise ValueError('Workspace not found')
    workspace.active=active
    users=select(User.id).where(User.workspace_id==workspace.id)
    db.execute(delete(Session).where(Session.user_id.in_(users)))
    db.add(Audit(workspace_id=workspace.id,actor='local-cli',action='workspace.enabled' if active else 'workspace.disabled',detail=workspace.slug))
    db.flush()
    return workspace

def main():
    parser=argparse.ArgumentParser(description='Manage local development workspaces')
    parser.add_argument('slug');parser.add_argument('name',nargs='?')
    actions=parser.add_mutually_exclusive_group();actions.add_argument('--disable',action='store_true');actions.add_argument('--enable',action='store_true')
    args=parser.parse_args()
    if (args.disable or args.enable) and args.name:parser.error('name is only used when creating a workspace')
    if not (args.disable or args.enable) and not args.name:parser.error('name is required when creating a workspace')
    try:
        with SessionLocal.begin() as db:
            if args.disable or args.enable:
                workspace=set_workspace_active(db,args.slug,args.enable)
                message=f"{'Enabled' if args.enable else 'Disabled'} workspace {workspace.slug}; all sessions revoked."
            else:
                workspace=create_workspace(db,args.slug,args.name)
                db.add(Audit(workspace_id=workspace.id,actor='local-cli',action='workspace.created',detail=workspace.slug))
                message=f'Created workspace {workspace.slug} (id {workspace.id}).'
    except ValueError as exc:raise SystemExit(str(exc)) from exc
    print(message)

if __name__=='__main__':main()
