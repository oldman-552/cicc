"""Experimental authenticated SQLite backups; trusted local operator only.

This is not a production backup service, KMS, anti-rollback system, or disaster
recovery certification. Plaintext staging is required; see docs/RECOVERY.md.
"""
import argparse
import base64
import binascii
import os
from pathlib import Path
import sqlite3
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from . import sqlite_backup

MAGIC=b'CICCDB\x00\x01'
NONCE_SIZE=12
TAG_SIZE=16
CHUNK_SIZE=1024*1024
MAX_BYTES=256*1024*1024


def backup_key():
    try:
        key=base64.b64decode(os.environ.get('CICC_BACKUP_KEY','').encode('ascii'),altchars=b'-_',validate=True)
    except (ValueError,UnicodeError,binascii.Error) as exc:raise ValueError('Invalid CICC_BACKUP_KEY') from exc
    if len(key)!=32:raise ValueError('CICC_BACKUP_KEY must encode exactly 32 bytes')
    return key


def _encrypt(source,destination,key):
    size=source.stat().st_size
    if size>MAX_BYTES:raise ValueError('SQLite backup exceeds the 256 MiB development limit')
    header=MAGIC+os.urandom(NONCE_SIZE)
    encryptor=Cipher(algorithms.AES(key),modes.GCM(header[len(MAGIC):])).encryptor()
    encryptor.authenticate_additional_data(header)
    fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as out,open(source,'rb') as inp:
        out.write(header);total=0
        while True:
            chunk=inp.read(CHUNK_SIZE)
            if not chunk:break
            total+=len(chunk)
            if total>MAX_BYTES:raise ValueError('SQLite backup exceeds the 256 MiB development limit')
            out.write(encryptor.update(chunk))
        out.write(encryptor.finalize());out.write(encryptor.tag);out.flush();os.fsync(out.fileno())


def _decrypt(source,destination,key):
    with open(source,'rb') as inp:
        size=os.fstat(inp.fileno()).st_size
        if not len(MAGIC)+NONCE_SIZE+TAG_SIZE<=size<=len(MAGIC)+NONCE_SIZE+MAX_BYTES+TAG_SIZE:
            raise ValueError('Invalid encrypted backup length')
        header=inp.read(len(MAGIC)+NONCE_SIZE)
        if len(header)!=len(MAGIC)+NONCE_SIZE or not header.startswith(MAGIC):raise ValueError('Invalid encrypted backup format')
        inp.seek(size-TAG_SIZE);tag=inp.read(TAG_SIZE);inp.seek(len(header))
        decryptor=Cipher(algorithms.AES(key),modes.GCM(header[len(MAGIC):],tag)).decryptor()
        decryptor.authenticate_additional_data(header)
        fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as out:
            remaining=size-len(header)-TAG_SIZE
            while remaining:
                chunk=inp.read(min(CHUNK_SIZE,remaining))
                if not chunk:raise ValueError('Truncated encrypted backup')
                out.write(decryptor.update(chunk));remaining-=len(chunk)
            out.write(decryptor.finalize())
            inp.seek(size)
            if inp.read(1) or os.fstat(inp.fileno()).st_size!=size:raise ValueError('Encrypted backup changed while reading')
            out.flush();os.fsync(out.fileno())


def _validate_key(key):
    if not isinstance(key,bytes) or len(key)!=32:raise ValueError('Backup key must be 32 bytes')


def create_encrypted_backup(source,destination,key):
    _validate_key(key)
    target=Path(destination).absolute()
    with tempfile.TemporaryDirectory(prefix='.cicc-encrypted-',dir=target.parent) as directory:
        plaintext=Path(directory)/'snapshot.sqlite3';encrypted=Path(directory)/'encrypted.cicc'
        sqlite_backup.copy_to_new(source,plaintext)
        _encrypt(plaintext,encrypted,key)
        os.link(encrypted,target)


def restore_encrypted_backup(source,destination,key):
    _validate_key(key)
    target=Path(destination).absolute()
    with tempfile.TemporaryDirectory(prefix='.cicc-decrypt-',dir=target.parent) as directory:
        plaintext=Path(directory)/'snapshot.sqlite3'
        # No restored database is published until GCM authentication succeeds.
        _decrypt(Path(source),plaintext,key)
        return sqlite_backup.restore_to_new(plaintext,target)


def main():
    parser=argparse.ArgumentParser(description='Experimental authenticated SQLite backup; requires protected plaintext staging')
    sub=parser.add_subparsers(dest='action',required=True)
    for action in ('create','restore'):
        command=sub.add_parser(action);command.add_argument('source');command.add_argument('destination')
        command.add_argument('--acknowledge-plaintext-staging',action='store_true')
        if action=='restore':command.add_argument('--acknowledge-stale-security-state',action='store_true')
    args=parser.parse_args()
    if not args.acknowledge_plaintext_staging:parser.error('protected plaintext staging acknowledgment is required')
    if args.action=='restore' and not args.acknowledge_stale_security_state:parser.error('stale security state acknowledgment is required')
    try:
        key=backup_key()
        if args.action=='create':
            create_encrypted_backup(args.source,args.destination,key)
            print('Authenticated encrypted SQLite backup created; manage its independent key securely.')
        else:
            count=restore_encrypted_backup(args.source,args.destination,key)
            print(f'Restored copy created; {count} sessions revoked. Reconcile stale security state before use.')
    except InvalidTag:raise SystemExit('Encrypted backup authentication failed') from None
    except (OSError,sqlite3.Error,ValueError) as exc:raise SystemExit(f'Encrypted backup operation failed: {exc}') from exc

if __name__=='__main__':main()
