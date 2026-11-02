import os
import sqlite3
import subprocess
import sys


def test_epss_migration_round_trip_preserves_other_data(tmp_path):
    path=tmp_path/'migration.db';environment={**os.environ,'DATABASE_URL':f'sqlite:///{path}'}
    def alembic(*args):
        return subprocess.run([sys.executable,'-m','alembic','-c','backend/alembic.ini',*args],env=environment,capture_output=True,text=True)
    first=alembic('upgrade','b8936d1c2327');assert first.returncode==0,first.stderr
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO investigations (workspace_id,title,status,created_at) VALUES (1,'Legacy case','open','2025-01-01 00:00:00')")
    upgraded=alembic('upgrade','ea2dd04051c8');assert upgraded.returncode==0,upgraded.stderr
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO sources (id,count) VALUES ('epss',1)")
        db.execute("INSERT INTO epss_scores (cve,score,percentile,score_date,collected_at) VALUES ('CVE-2025-1234','0.100000000','0.500000000','2025-01-01','2025-01-01 00:00:00')")
    down=alembic('downgrade','b8936d1c2327');assert down.returncode==0,down.stderr
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT title FROM investigations").fetchone()==('Legacy case',)
        assert db.execute("SELECT count(*) FROM sources WHERE id='epss'").fetchone()==(0,)
        assert db.execute("SELECT count(*) FROM sqlite_master WHERE name='epss_scores'").fetchone()==(0,)
    again=alembic('upgrade','head');assert again.returncode==0,again.stderr
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT count(*) FROM epss_scores').fetchone()==(0,)
        assert db.execute('SELECT title FROM investigations').fetchone()==('Legacy case',)
