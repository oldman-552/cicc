import sqlite3
import pytest
from backend.tests.test_database_workspace_guards import migrate


def seed(path):
    result=migrate(path,'upgrade','head');assert result.returncode==0,result.stderr
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO workspaces(id,slug,name,active) VALUES (2,'other','Other',1)")
        db.executemany("INSERT INTO users(id,workspace_id,username,password_hash,role,active) VALUES (?,?,?,?,?,1)",[(1,1,'first','hash','admin'),(2,2,'second','hash','viewer')])
        db.execute("INSERT INTO user_mfa(user_id,encrypted_secret,last_counter,enabled_at) VALUES (1,x'010203',1,'2025-01-01')")
        db.executemany("INSERT INTO sessions(token_hash,csrf_hash,user_id,mfa_verified,expires_at) VALUES (?,?,?,1,'2030-01-01')",[('a','a',1),('b','b',2)])


@pytest.mark.parametrize('sql',[
    "UPDATE users SET role='viewer' WHERE id=1",
    "UPDATE users SET password_hash='changed' WHERE id=1",
    "UPDATE users SET username='renamed' WHERE id=1",
    'UPDATE users SET active=0 WHERE id=1',
    'UPDATE workspaces SET active=0 WHERE id=1',
    "UPDATE user_mfa SET encrypted_secret=x'040506' WHERE user_id=1",
    'DELETE FROM user_mfa WHERE user_id=1',
])
def test_database_security_changes_revoke_only_affected_sessions(tmp_path,sql):
    path=tmp_path/'state.db';seed(path)
    with sqlite3.connect(path) as db:
        db.execute(sql)
        assert db.execute('SELECT token_hash FROM sessions').fetchall()==[('b',)]
        db.rollback()
        assert db.execute('SELECT token_hash FROM sessions ORDER BY token_hash').fetchall()==[('a',),('b',)]
        db.execute(sql)
    with sqlite3.connect(path) as db:assert db.execute('SELECT token_hash FROM sessions').fetchall()==[('b',)]


def test_mfa_enrollment_revoke_noop_and_security_parent_immutability(tmp_path):
    path=tmp_path/'state.db';seed(path)
    with sqlite3.connect(path) as db:
        db.execute('UPDATE user_mfa SET last_counter=2 WHERE user_id=1')
        db.execute('UPDATE users SET role=role WHERE id=1')
        db.execute('UPDATE workspaces SET active=active WHERE id=1')
        db.execute('UPDATE user_mfa SET encrypted_secret=encrypted_secret WHERE user_id=1')
        assert db.execute('SELECT count(*) FROM sessions').fetchone()==(2,)
        with pytest.raises(sqlite3.IntegrityError,match='security record parent reassignment forbidden'):
            db.execute("UPDATE sessions SET user_id=2 WHERE token_hash='a'")
        with pytest.raises(sqlite3.IntegrityError,match='security record parent reassignment forbidden'):
            db.execute('UPDATE user_mfa SET user_id=2 WHERE user_id=1')
        db.execute("INSERT INTO user_mfa(user_id,encrypted_secret,last_counter,enabled_at) VALUES (2,x'010203',1,'2025-01-01')")
        assert db.execute('SELECT token_hash FROM sessions').fetchall()==[('a',)]


def test_workspace_reactivation_does_not_revive_sessions_and_downgrade_is_guarded(tmp_path):
    path=tmp_path/'state.db';seed(path)
    with sqlite3.connect(path) as db:
        db.execute('UPDATE workspaces SET active=0 WHERE id=1')
        db.execute('UPDATE workspaces SET active=1 WHERE id=1')
        assert db.execute('SELECT token_hash FROM sessions').fetchall()==[('b',)]
    result=migrate(path,'downgrade','c1af7842d90b')
    assert result.returncode!=0 and 'Cannot downgrade while accounts exist' in result.stderr
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT version_num FROM alembic_version').fetchone()==('ea2dd04051c8',)
        assert db.execute('SELECT count(*) FROM users').fetchone()==(2,)
