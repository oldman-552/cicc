"""Trusted-local, unencrypted SQLite copies. Not a production backup system."""
import argparse
from contextlib import closing
import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from alembic.script import ScriptDirectory
from pathlib import Path


def open_readonly(path):
    source=Path(path).resolve(strict=True)
    if not source.is_file():raise ValueError('Source must be an existing SQLite file')
    return sqlite3.connect(source.as_uri()+'?mode=ro',uri=True,timeout=5)


def check_integrity(connection):
    result=connection.execute('PRAGMA integrity_check').fetchall()
    if result!=[('ok',)]:raise ValueError('SQLite integrity check failed')


def verify(path):
    with closing(open_readonly(path)) as source:
        check_integrity(source)


def copy_to_new(source_path,destination_path):
    """Copy a trusted SQLite DB to a new 0600 file; never overwrite an existing path."""
    target=Path(destination_path).absolute()
    # Validate before creating any output; mode=ro never creates a missing source.
    with closing(open_readonly(source_path)) as source:
        check_integrity(source)
        fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        created=os.fstat(fd)
        try:
            with closing(sqlite3.connect(target,timeout=5)) as destination:
                source.backup(destination)
                check_integrity(destination)
            os.fsync(fd)
        except BaseException:
            # Remove only the file this call created, never a replacement path.
            try:
                current=target.stat(follow_symlinks=False)
                if (current.st_dev,current.st_ino)==(created.st_dev,created.st_ino):target.unlink()
            except FileNotFoundError:pass
            raise
        finally:
            os.close(fd)



def current_schema_head():
    # Resolve the migration directory independently of the operator's cwd.
    migrations=Path(__file__).resolve().parents[1]/'migrations'
    return ScriptDirectory(str(migrations)).get_current_head()


def _sanitize_restore(path):
    """Invalidate all sessions and record a local recovery event before publication."""
    with closing(sqlite3.connect(path,timeout=5)) as db:
        # Ensure all changes are in the main file before it is published by link.
        if db.execute('PRAGMA journal_mode=DELETE').fetchone()!=('delete',):
            raise ValueError('Cannot make restored database self-contained')
        versions=db.execute('SELECT version_num FROM alembic_version').fetchall()
        if versions!=[(current_schema_head(),)]:raise ValueError('Backup schema revision does not match this code')
        check_integrity(db)
        db.execute('BEGIN IMMEDIATE')
        count=db.execute('SELECT COUNT(*) FROM sessions').fetchone()[0]
        db.execute('DELETE FROM sessions')
        db.execute("INSERT INTO audit(workspace_id,actor,action,detail,created_at) VALUES (NULL,'local-cli','recovery.sessions_revoked',?,?)",
                   (f'{count} sessions removed from restored copy',datetime.now(timezone.utc).isoformat()))
        db.commit()
        check_integrity(db)
    return count


def restore_to_new(source_path,destination_path):
    """Publish only a sanitized new local copy, never overwrite an existing path.

    This does not authenticate a backup or reconcile rolled-back credentials.
    """
    target=Path(destination_path).absolute()
    with tempfile.TemporaryDirectory(prefix='.cicc-restore-',dir=target.parent) as directory:
        staged=Path(directory)/'staged.sqlite3'
        copy_to_new(source_path,staged)
        count=_sanitize_restore(staged)
        with open(staged,'rb') as file:os.fsync(file.fileno())
        # Hard-link publication is atomic and fails if destination exists.
        os.link(staged,target)
        return count

def main():
    parser=argparse.ArgumentParser(description='Unencrypted development SQLite backup/restore-to-new-file')
    sub=parser.add_subparsers(dest='action',required=True)
    check=sub.add_parser('verify');check.add_argument('source')
    copy=sub.add_parser('copy');copy.add_argument('source');copy.add_argument('destination')
    restore=sub.add_parser('restore');restore.add_argument('source');restore.add_argument('destination')
    restore.add_argument('--acknowledge-stale-security-state',action='store_true',help='Acknowledge that old passwords, MFA settings and audit state are not reconciled')
    args=parser.parse_args()
    if args.action=='restore' and not args.acknowledge_stale_security_state:parser.error('restore requires --acknowledge-stale-security-state')
    try:
        if args.action=='verify':verify(args.source);print('SQLite integrity check passed; authenticity and recovery are not verified.')
        elif args.action=='copy':copy_to_new(args.source,args.destination);print('Unencrypted SQLite copy created; protect it as sensitive data.')
        else:
            count=restore_to_new(args.source,args.destination)
            print(f'Unencrypted restored copy created; {count} sessions revoked. Reconcile stale security state before use.')
    except (OSError,sqlite3.Error,ValueError) as exc:raise SystemExit(f'SQLite copy/check failed: {exc}') from exc

if __name__=='__main__':main()
