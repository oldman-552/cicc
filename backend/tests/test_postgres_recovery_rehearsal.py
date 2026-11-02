"""CI-only synthetic dump/restore rehearsal, never a production recovery tool.

The test creates and drops its own random database inside the CI PostgreSQL
service. It never accepts a dump or target chosen by a caller. The CI service
and all test data are disposable. A pre-restore activity check is not a lock
against new connections and is not a production isolation guarantee.
"""
import os
import re
import subprocess
from uuid import uuid4

import pytest
from sqlalchemy import create_engine,delete,func,select,text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session as DbSession

from backend.app import accounts,security
from backend.app.db import SessionLocal,engine
from backend.app.models import Session,User
from backend.app.workspaces import create_workspace

URL=os.environ.get('CICC_TEST_POSTGRES_URL','')
CONTAINER=os.environ.get('CICC_TEST_POSTGRES_CONTAINER_ID','')
ENABLED=(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('CICC_TEST_DISPOSABLE_DB')=='1' and os.environ.get('CICC_TEST_CI_REHEARSAL')=='1' and URL==os.environ.get('DATABASE_URL') and bool(re.fullmatch('[0-9a-f]{12,64}',CONTAINER)))
pytestmark=pytest.mark.skipif(not ENABLED,reason='requires explicitly opted-in disposable CI service container')


def test_synthetic_postgres_dump_restore_revokes_sessions():
    url=make_url(URL)
    assert url.get_backend_name()=='postgresql' and url.host in ('localhost','127.0.0.1')
    assert url.database=='cicc_test' and url.username=='cicc_test'
    suffix=uuid4().hex;target='cicc_restore_'+suffix;username='rehearsal'+suffix[:16]
    with SessionLocal.begin() as db:
        workspace=create_workspace(db,'rehearsal-'+suffix[:24],'Synthetic recovery rehearsal')
        user=accounts.configure_account(db,username,'synthetic-password-123456','admin',workspace.id)
        token,_=security.create_session(db,user.id);db.flush()
    # This produces the archive from the disposable service, not a supplied file.
    dump=subprocess.run(['docker','exec',CONTAINER,'pg_dump','--format=custom','--no-owner','--no-privileges','-U','cicc_test','-d','cicc_test'],capture_output=True,timeout=60)
    assert dump.returncode==0,dump.stderr.decode(errors='replace')[-4000:]
    archive=dump.stdout
    assert archive.startswith(b'PGDMP') and len(archive)<16*1024*1024
    created=False;restore_engine=None
    try:
        # The name is generated in this test; CREATE fails rather than replacing a database.
        with engine.connect().execution_options(isolation_level='AUTOCOMMIT') as db:
            db.execute(text(f'CREATE DATABASE "{target}"'));created=True
            assert db.scalar(text('SELECT count(*) FROM pg_stat_activity WHERE datname=:target'),{'target':target})==0
        restore=subprocess.run(['docker','exec','-i',CONTAINER,'pg_restore','--exit-on-error','--no-owner','--no-privileges','-U','cicc_test','-d',target],input=archive,capture_output=True,timeout=60)
        assert restore.returncode==0,restore.stderr.decode(errors='replace')[-4000:]
        restore_engine=create_engine(url.set(database=target),pool_pre_ping=True)
        with DbSession(restore_engine) as db:
            assert db.scalar(select(User).where(User.username==username)) is not None
            assert security.get_session(db,token) is not None
            assert db.scalar(select(func.count()).select_from(Session))>0
            db.execute(delete(Session));db.commit()
            assert security.get_session(db,token) is None
            assert db.scalar(select(func.count()).select_from(Session))==0
        # Rehearsal must not revoke sessions on the original disposable source.
        with SessionLocal() as db:assert security.get_session(db,token) is not None
    finally:
        if restore_engine is not None:restore_engine.dispose()
        if created:
            with engine.connect().execution_options(isolation_level='AUTOCOMMIT') as db:
                # No forced termination: fail if unexpected connections remain.
                db.execute(text(f'DROP DATABASE "{target}"'))


@pytest.mark.parametrize('damage',['invalid','truncated'])
def test_failed_synthetic_restore_cleans_target_and_preserves_source(damage):
    url=make_url(URL)
    assert url.get_backend_name()=='postgresql' and url.host in ('localhost','127.0.0.1')
    assert url.database=='cicc_test' and url.username=='cicc_test'
    suffix=uuid4().hex;target='cicc_restore_'+suffix;username='restorefail'+suffix[:16]
    with SessionLocal.begin() as db:
        workspace=create_workspace(db,'fail-'+suffix[:24],'Synthetic failed recovery')
        user=accounts.configure_account(db,username,'synthetic-password-123456','admin',workspace.id)
        token,_=security.create_session(db,user.id);db.flush()
    if damage=='truncated':
        dump=subprocess.run(['docker','exec',CONTAINER,'pg_dump','--format=custom','--no-owner','--no-privileges','-U','cicc_test','-d','cicc_test'],capture_output=True,timeout=60)
        assert dump.returncode==0,dump.stderr.decode(errors='replace')[-4000:]
        assert dump.stdout.startswith(b'PGDMP') and len(dump.stdout)<16*1024*1024
        archive=dump.stdout[:len(dump.stdout)//2]
    else:archive=b'not a valid PostgreSQL archive'
    created=False
    try:
        with engine.connect().execution_options(isolation_level='AUTOCOMMIT') as db:
            db.execute(text(f'CREATE DATABASE "{target}"'));created=True
            assert db.scalar(text('SELECT count(*) FROM pg_stat_activity WHERE datname=:target'),{'target':target})==0
        restore=subprocess.run(['docker','exec','-i',CONTAINER,'pg_restore','--exit-on-error','--no-owner','--no-privileges','-U','cicc_test','-d',target],input=archive,capture_output=True,timeout=60)
        assert restore.returncode!=0,'invalid archive unexpectedly restored'
    finally:
        if created:
            with engine.connect().execution_options(isolation_level='AUTOCOMMIT') as db:
                db.execute(text(f'DROP DATABASE "{target}"'))
    with engine.connect() as db:
        assert db.scalar(text('SELECT count(*) FROM pg_database WHERE datname=:target'),{'target':target})==0
    with SessionLocal() as db:
        assert security.get_session(db,token) is not None
        assert db.scalar(select(User).where(User.username==username)) is not None
