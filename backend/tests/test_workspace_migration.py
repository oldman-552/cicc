import os
import sqlite3
import subprocess
import sys


def test_workspace_migration_backfills_and_blocks_unsafe_downgrade(tmp_path):
    path=tmp_path/'migration.db';environment={**os.environ,'DATABASE_URL':f'sqlite:///{path}'}
    def alembic(*args):
        return subprocess.run([sys.executable,'-m','alembic','-c','backend/alembic.ini',*args],env=environment,capture_output=True,text=True)
    assert alembic('upgrade','d98dbca43b80').returncode==0
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO investigations (title,status,created_at) VALUES ('Legacy case','open','2025-01-01 00:00:00')")
        db.execute("INSERT INTO audit (actor,action,detail,created_at) VALUES ('demo','legacy','test','2025-01-01 00:00:00')")
    result=alembic('upgrade','b8936d1c2327');assert result.returncode==0,result.stderr
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT workspace_id FROM investigations').fetchone()==(1,)
        assert db.execute('SELECT workspace_id FROM audit').fetchone()==(1,)
        assert db.execute("SELECT slug FROM workspaces WHERE id=1").fetchone()==('default',)
        db.execute("INSERT INTO workspaces (id,slug,name,active) VALUES (2,'second','Second',1)")
    result=alembic('downgrade','-1')
    assert result.returncode!=0 and 'Cannot downgrade while additional workspaces' in result.stderr
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT COUNT(*) FROM workspaces').fetchone()==(2,)
        assert db.execute('SELECT title FROM investigations').fetchone()==('Legacy case',)
