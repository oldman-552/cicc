import sqlite3
from backend.tests.test_database_workspace_guards import migrate


def test_source_sequences_preserve_cached_data_and_guard_downgrade(tmp_path):
    path=tmp_path/'source.db';result=migrate(path,'upgrade','ea2dd04051c8');assert result.returncode==0,result.stderr
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO sources(id,count,version,last_success) VALUES ('cisa',12,'test','2025-01-01')")
    result=migrate(path,'upgrade','head');assert result.returncode==0,result.stderr
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT count,version,attempt_sequence,completed_sequence FROM sources').fetchone()==(12,'test',0,0)
    result=migrate(path,'downgrade','ea2dd04051c8')
    assert result.returncode!=0 and 'Cannot downgrade while source records exist' in result.stderr
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT version_num FROM alembic_version').fetchone()==('2ecb93a547b1',)
        assert db.execute("SELECT version FROM sources WHERE id='cisa'").fetchone()==('test',)
        db.execute('DELETE FROM sources')
    result=migrate(path,'downgrade','ea2dd04051c8');assert result.returncode==0,result.stderr
    result=migrate(path,'upgrade','head');assert result.returncode==0,result.stderr
