"""Trusted-local, unencrypted SQLite copies. Not a production backup system."""
import argparse
from contextlib import closing
import os
import sqlite3
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


def main():
    parser=argparse.ArgumentParser(description='Unencrypted development SQLite backup/restore-to-new-file')
    sub=parser.add_subparsers(dest='action',required=True)
    check=sub.add_parser('verify');check.add_argument('source')
    copy=sub.add_parser('copy');copy.add_argument('source');copy.add_argument('destination')
    args=parser.parse_args()
    try:
        if args.action=='verify':verify(args.source);print('SQLite integrity check passed; authenticity and recovery are not verified.')
        else:copy_to_new(args.source,args.destination);print('Unencrypted SQLite copy created; protect it as sensitive data.')
    except (OSError,sqlite3.Error,ValueError) as exc:raise SystemExit(f'SQLite copy/check failed: {exc}') from exc

if __name__=='__main__':main()
