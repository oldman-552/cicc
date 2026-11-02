"""Exercise actual migrated SQLite schema through direct SQL, not the ORM hook."""
import os
import sqlite3
import subprocess
import sys
import pytest


def migrate(path,*args):
    env={**os.environ,'DATABASE_URL':f'sqlite:///{path}'}
    return subprocess.run([sys.executable,'-m','alembic','-c','backend/alembic.ini',*args],env=env,capture_output=True,text=True)


def populate(db,cross_link=False):
    db.execute("INSERT INTO workspaces (id,slug,name,active) VALUES (2,'other','Other',1)")
    db.executemany("INSERT INTO investigations (id,workspace_id,title,status,created_at) VALUES (?,?,?,'open','2025-01-01')",[(1,1,'Case one'),(2,2,'Case two')])
    db.executemany("INSERT INTO assets (id,workspace_id,name,asset_type,identifier,owner,scope_basis,status,created_by,created_at,updated_at) VALUES (?,?,?,'application',?,'test','test','active','test','2025-01-01','2025-01-01')",[(1,1,'Asset one','one'),(2,2,'Asset two','two')])
    db.executemany("INSERT INTO sboms (id,workspace_id,name,format,created_at,component_count) VALUES (?,?,?,'CycloneDX','2025-01-01',0)",[(1,1,'SBOM one'),(2,2,'SBOM two')])
    if cross_link:
        db.execute("INSERT INTO investigation_assets (investigation_id,asset_id,snapshot,linked_by,linked_at) VALUES (1,2,'{}','test','2025-01-01')")


def test_migration_refuses_existing_cross_workspace_link_without_modifying_it(tmp_path):
    path=tmp_path/'legacy.db';result=migrate(path,'upgrade','35a07a27de4a');assert result.returncode==0,result.stderr
    with sqlite3.connect(path) as db:populate(db,cross_link=True)
    result=migrate(path,'upgrade','head')
    assert result.returncode!=0 and 'cross-workspace links in investigation_assets' in result.stderr
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT investigation_id,asset_id FROM investigation_assets').fetchone()==(1,2)
        assert db.execute('SELECT version_num FROM alembic_version').fetchone()==('35a07a27de4a',)
        assert db.execute("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name LIKE 'cicc_%'").fetchone()==(0,)


def test_migrated_sqlite_guards_direct_writes_and_allows_valid_links(tmp_path):
    path=tmp_path/'guarded.db';result=migrate(path,'upgrade','head');assert result.returncode==0,result.stderr
    with sqlite3.connect(path) as db:
        # Explicitly disable native FK checks to test the new triggers independently.
        db.execute('PRAGMA foreign_keys=OFF');populate(db)
        db.execute("INSERT INTO investigation_assets (id,investigation_id,asset_id,snapshot,linked_by,linked_at) VALUES (1,1,1,'{}','test','2025-01-01')")
        db.execute("INSERT INTO asset_sboms (id,asset_id,sbom_id,snapshot,linked_by,linked_at) VALUES (1,1,1,'{}','test','2025-01-01')")
        db.execute("INSERT INTO audit (workspace_id,actor,action,detail,created_at) VALUES (NULL,'unknown','login','', '2025-01-01')")
        db.commit()
        attempts=[
            ("INSERT INTO investigations (workspace_id,title,status,created_at) VALUES (999,'Bad','open','2025-01-01')",'invalid workspace reference'),
            ("UPDATE investigations SET workspace_id=2 WHERE id=1",'workspace reassignment forbidden'),
            ("UPDATE assets SET workspace_id=2 WHERE id=1",'workspace reassignment forbidden'),
            ("UPDATE sboms SET workspace_id=2 WHERE id=1",'workspace reassignment forbidden'),
            ("INSERT INTO audit (workspace_id,actor,action,detail,created_at) VALUES (999,'bad','login','','2025-01-01')",'invalid workspace reference'),
            ("INSERT INTO investigation_assets (investigation_id,asset_id,snapshot,linked_by,linked_at) VALUES (1,2,'{}','test','2025-01-01')",'cross-workspace'),
            ("UPDATE investigation_assets SET asset_id=2 WHERE id=1",'cross-workspace'),
            ("INSERT INTO asset_sboms (asset_id,sbom_id,snapshot,linked_by,linked_at) VALUES (1,2,'{}','test','2025-01-01')",'cross-workspace'),
            ("UPDATE asset_sboms SET sbom_id=2 WHERE id=1",'cross-workspace'),
            ("DELETE FROM workspaces WHERE id=1",'workspace is referenced'),
            ("UPDATE workspaces SET id=3 WHERE id=1",'workspace is referenced'),
        ]
        for statement,message in attempts:
            with pytest.raises(sqlite3.IntegrityError,match=message):db.execute(statement)
        assert db.execute('SELECT workspace_id FROM investigations WHERE id=1').fetchone()==(1,)
        assert db.execute('SELECT asset_id FROM investigation_assets WHERE id=1').fetchone()==(1,)
        assert db.execute('SELECT sbom_id FROM asset_sboms WHERE id=1').fetchone()==(1,)
    down=migrate(path,'downgrade','35a07a27de4a');assert down.returncode==0,down.stderr
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT count(*) FROM investigations').fetchone()==(2,)
        assert db.execute("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name LIKE 'cicc_%'").fetchone()==(0,)
    up=migrate(path,'upgrade','head');assert up.returncode==0,up.stderr


@pytest.mark.parametrize('corruption,expected',[
    ("UPDATE investigations SET workspace_id=999 WHERE id=1",'invalid workspace references in investigations'),
    ("INSERT INTO asset_sboms (asset_id,sbom_id,snapshot,linked_by,linked_at) VALUES (1,2,'{}','test','2025-01-01')",'cross-workspace links in asset_sboms'),
])
def test_migration_refuses_other_inconsistent_existing_records(tmp_path,corruption,expected):
    path=tmp_path/'bad.db';result=migrate(path,'upgrade','35a07a27de4a');assert result.returncode==0,result.stderr
    with sqlite3.connect(path) as db:
        db.execute('PRAGMA foreign_keys=OFF');populate(db);db.execute(corruption)
    result=migrate(path,'upgrade','head')
    assert result.returncode!=0 and expected in result.stderr
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT version_num FROM alembic_version').fetchone()==('35a07a27de4a',)
        assert db.execute("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name LIKE 'cicc_%'").fetchone()==(0,)
