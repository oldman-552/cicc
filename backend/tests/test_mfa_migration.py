import os
import sqlite3
import subprocess
import sys


def test_mfa_migration_refuses_downgrade_until_enrollment_removed(tmp_path):
    path=tmp_path/'mfa.db';env={**os.environ,'DATABASE_URL':f'sqlite:///{path}'}
    def alembic(*args):return subprocess.run([sys.executable,'-m','alembic','-c','backend/alembic.ini',*args],env=env,capture_output=True,text=True)
    result=alembic('upgrade','23c58ba2b681');assert result.returncode==0,result.stderr
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO users (id,workspace_id,username,password_hash,role,active) VALUES (1,1,'test-user','not-a-real-hash','viewer',1)")
        db.execute("INSERT INTO user_mfa (user_id,encrypted_secret,last_counter,enabled_at) VALUES (1,x'010203',100,'2025-01-01')")
    result=alembic('downgrade','484b2e0f87f1')
    assert result.returncode!=0 and 'Cannot downgrade while MFA accounts are enrolled' in result.stderr
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT COUNT(*) FROM user_mfa').fetchone()==(1,)
        assert db.execute('SELECT version_num FROM alembic_version').fetchone()==('23c58ba2b681',)
        db.execute('DELETE FROM user_mfa')
    result=alembic('downgrade','484b2e0f87f1');assert result.returncode==0,result.stderr
    result=alembic('upgrade','head');assert result.returncode==0,result.stderr
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT username FROM users').fetchone()==('test-user',)
        assert db.execute('SELECT COUNT(*) FROM user_mfa').fetchone()==(0,)


def test_existing_sessions_are_not_claimed_as_mfa_verified(tmp_path):
    path=tmp_path/'old-session.db';env={**os.environ,'DATABASE_URL':f'sqlite:///{path}'}
    def alembic(*args):return subprocess.run([sys.executable,'-m','alembic','-c','backend/alembic.ini',*args],env=env,capture_output=True,text=True)
    result=alembic('upgrade','412b3727a8fe');assert result.returncode==0,result.stderr
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO users (id,workspace_id,username,password_hash,role,active) VALUES (1,1,'test-user','not-a-real-hash','viewer',1)")
        db.execute("INSERT INTO sessions (token_hash,csrf_hash,user_id,expires_at) VALUES ('token','csrf',1,'2028-01-01')")
    result=alembic('upgrade','head');assert result.returncode==0,result.stderr
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT mfa_verified FROM sessions').fetchone()==(0,)
