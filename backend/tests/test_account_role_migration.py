import sqlite3
import pytest
from backend.tests.test_database_workspace_guards import migrate


def test_role_migration_rejects_invalid_existing_roles_without_changes(tmp_path):
    path=tmp_path/'roles.db';result=migrate(path,'upgrade','a63c9f170b42');assert result.returncode==0,result.stderr
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO users(id,workspace_id,username,password_hash,role,active) VALUES (1,1,'legacy','hash','unexpected',1)")
    result=migrate(path,'upgrade','head')
    assert result.returncode!=0 and 'unsupported role values exist' in result.stderr
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT role FROM users').fetchone()==('unexpected',)
        assert db.execute('SELECT version_num FROM alembic_version').fetchone()==('a63c9f170b42',)
        assert db.execute("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name LIKE 'cicc_users_role_%'").fetchone()==(0,)
        db.execute("UPDATE users SET role='viewer'")
    result=migrate(path,'upgrade','head');assert result.returncode==0,result.stderr


def test_role_guards_block_direct_sql_and_downgrade(tmp_path):
    path=tmp_path/'roles.db';result=migrate(path,'upgrade','head');assert result.returncode==0,result.stderr
    with sqlite3.connect(path) as db:
        for id,role in enumerate(('admin','analyst','viewer'),1):
            db.execute('INSERT INTO users(id,workspace_id,username,password_hash,role,active) VALUES (?,1,?,?,?,1)',(id,'user'+str(id),'hash',role))
        with pytest.raises(sqlite3.IntegrityError,match='unsupported account role'):
            db.execute("UPDATE users SET role='administrator' WHERE id=1")
        with pytest.raises(sqlite3.IntegrityError,match='unsupported account role'):
            db.execute("INSERT INTO users(workspace_id,username,password_hash,role,active) VALUES (1,'bad','hash','',1)")
        with pytest.raises(sqlite3.IntegrityError,match='unsupported account role'):
            db.execute("UPDATE users SET role=NULL WHERE id=1")
        db.execute("UPDATE users SET role='viewer' WHERE id=3")
        assert db.execute('SELECT role FROM users WHERE id=1').fetchone()==('admin',)
    result=migrate(path,'downgrade','a63c9f170b42')
    assert result.returncode!=0 and 'Cannot downgrade while accounts exist' in result.stderr
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT count(*) FROM users').fetchone()==(3,)
        assert db.execute('SELECT version_num FROM alembic_version').fetchone()==('c1af7842d90b',)
        db.execute('DELETE FROM users')
    result=migrate(path,'downgrade','a63c9f170b42');assert result.returncode==0,result.stderr
    result=migrate(path,'upgrade','head');assert result.returncode==0,result.stderr
