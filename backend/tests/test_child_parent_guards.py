"""Migration and ORM checks for inherited workspace ownership, not RLS."""
import sqlite3
import pytest
from backend.tests.test_database_workspace_guards import migrate,populate
from backend.tests.test_api import env
from backend.app.models import Investigation,Note


ROWS=(
    ("INSERT INTO evidence(id,investigation_id,advisory_id,snapshot,added_at) VALUES (1,1,'A','{}','2025-01-01')",'evidence','investigation_id'),
    ("INSERT INTO notes(id,investigation_id,content,classification,created_at) VALUES (1,1,'test','UNKNOWN','2025-01-01')",'notes','investigation_id'),
    ("INSERT INTO investigation_events(id,investigation_id,event_type,actor,details,created_at) VALUES (1,1,'test','test','{}','2025-01-01')",'investigation_events','investigation_id'),
    ("INSERT INTO investigation_techniques(id,investigation_id,technique_id,snapshot,linked_by,linked_at) VALUES (1,1,'T1000','{}','test','2025-01-01')",'investigation_techniques','investigation_id'),
    ("INSERT INTO sbom_components(id,sbom_id,name) VALUES (1,1,'one'),(2,2,'two')",'sbom_components','sbom_id'),
    ("INSERT INTO sbom_candidates(id,component_id,advisory_id,snapshot) VALUES (1,1,'A','{}')",'sbom_candidates','component_id'),
)


def test_migrated_child_parent_guards_and_downgrade_refusal(tmp_path):
    path=tmp_path/'test.db';result=migrate(path,'upgrade','head');assert result.returncode==0,result.stderr
    with sqlite3.connect(path) as db:
        populate(db)
        for sql,_,_ in ROWS:db.execute(sql)
        db.commit()
        for _,table,column in ROWS:
            db.execute(f'UPDATE {table} SET {column}={column} WHERE id=1')
            with pytest.raises(sqlite3.IntegrityError,match='child parent reassignment forbidden'):
                db.execute(f'UPDATE {table} SET {column}=2 WHERE id=1')
        db.execute("UPDATE notes SET content='edited' WHERE id=1")
        assert db.execute('SELECT content FROM notes WHERE id=1').fetchone()==('edited',)
    result=migrate(path,'downgrade','23c58ba2b681')
    assert result.returncode!=0 and 'Cannot downgrade while workspace-bound child records exist' in result.stderr
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT version_num FROM alembic_version').fetchone()==('a63c9f170b42',)
        assert db.execute("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name LIKE 'cicc_%_parent_immutable'").fetchone()==(6,)
        for _,table,_ in reversed(ROWS):db.execute(f'DELETE FROM {table}')
    result=migrate(path,'downgrade','23c58ba2b681');assert result.returncode==0,result.stderr
    result=migrate(path,'upgrade','head');assert result.returncode==0,result.stderr


def test_migration_refuses_orphaned_children_without_changes(tmp_path):
    path=tmp_path/'bad.db';result=migrate(path,'upgrade','23c58ba2b681');assert result.returncode==0,result.stderr
    with sqlite3.connect(path) as db:
        db.execute('PRAGMA foreign_keys=OFF')
        db.execute("INSERT INTO notes(id,investigation_id,content,classification,created_at) VALUES (1,999,'orphan','UNKNOWN','2025-01-01')")
    result=migrate(path,'upgrade','head')
    assert result.returncode!=0 and 'orphaned records in notes' in result.stderr
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT investigation_id FROM notes').fetchone()==(999,)
        assert db.execute('SELECT version_num FROM alembic_version').fetchone()==('23c58ba2b681',)
        assert db.execute("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name LIKE 'cicc_%_parent_immutable'").fetchone()==(0,)


def test_orm_rejects_child_reparenting(env):
    _,factory=env
    with factory.begin() as db:
        a=Investigation(workspace_id=1,title='one');b=Investigation(workspace_id=1,title='two');db.add_all([a,b]);db.flush()
        note=Note(investigation_id=a.id,content='test',classification='UNKNOWN');db.add(note);db.flush();note_id=note.id;new_parent=b.id
    with pytest.raises(ValueError,match='workspace-bound child'):
        with factory.begin() as db:db.get(Note,note_id).investigation_id=new_parent
