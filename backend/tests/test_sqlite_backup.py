from backend.tests.test_api import env
import sqlite3
import stat
import pytest
from backend.app import sqlite_backup


def test_sqlite_backup_and_restore_to_new_file_with_wal(tmp_path):
    source=tmp_path/'source & db.sqlite3';backup=tmp_path/'backup.sqlite3';restore=tmp_path/'restore.sqlite3'
    with sqlite3.connect(source) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('CREATE TABLE items(id INTEGER PRIMARY KEY, value TEXT NOT NULL)')
        db.execute("INSERT INTO items(value) VALUES ('synthetic data')");db.commit()
        # Copy while the source connection is still open, including committed WAL state.
        sqlite_backup.copy_to_new(source,backup)
    sqlite_backup.verify(backup)
    sqlite_backup.copy_to_new(backup,restore)
    with sqlite3.connect(restore) as db:
        assert db.execute('SELECT value FROM items').fetchall()==[('synthetic data',)]
    assert stat.S_IMODE(backup.stat().st_mode)==0o600
    assert stat.S_IMODE(restore.stat().st_mode)==0o600
    with pytest.raises(FileExistsError):sqlite_backup.copy_to_new(source,restore)
    with sqlite3.connect(restore) as db:assert db.execute('SELECT count(*) FROM items').fetchone()==(1,)
    with pytest.raises(FileExistsError):sqlite_backup.copy_to_new(source,source)


def test_sqlite_copy_rejects_bad_source_and_existing_or_symlink_target(tmp_path):
    source=tmp_path/'source.sqlite3'
    with sqlite3.connect(source) as db:db.execute('CREATE TABLE sample(id INTEGER)')
    bad=tmp_path/'bad.sqlite3';bad.write_text('not a database')
    output=tmp_path/'out.sqlite3'
    with pytest.raises(sqlite3.DatabaseError):sqlite_backup.copy_to_new(bad,output)
    assert not output.exists()
    with pytest.raises(FileNotFoundError):sqlite_backup.copy_to_new(tmp_path/'absent.sqlite3',output)
    assert not output.exists()
    existing=tmp_path/'existing';existing.write_text('do not overwrite')
    with pytest.raises(FileExistsError):sqlite_backup.copy_to_new(source,existing)
    assert existing.read_text()=='do not overwrite'
    link=tmp_path/'link';link.symlink_to(existing)
    with pytest.raises(FileExistsError):sqlite_backup.copy_to_new(source,link)
    assert existing.read_text()=='do not overwrite'


def test_sqlite_cli_does_not_print_data(monkeypatch,tmp_path,capsys):
    source=tmp_path/'source.sqlite3';output=tmp_path/'backup.sqlite3'
    with sqlite3.connect(source) as db:
        db.execute('CREATE TABLE items(value TEXT)');db.execute("INSERT INTO items VALUES ('private synthetic')")
    monkeypatch.setattr('sys.argv',['sqlite_backup','copy',str(source),str(output)])
    sqlite_backup.main();assert 'private synthetic' not in capsys.readouterr().out
    monkeypatch.setattr('sys.argv',['sqlite_backup','verify',str(output)])
    sqlite_backup.main();assert 'not verified' in capsys.readouterr().out


def test_sqlite_copy_cleans_partial_file_but_not_replaced_path(tmp_path,monkeypatch):
    source=tmp_path/'source.sqlite3';output=tmp_path/'output.sqlite3'
    with sqlite3.connect(source) as db:db.execute('CREATE TABLE sample(id INTEGER)')
    original=sqlite_backup.check_integrity;calls=[]
    def fail_second(connection):
        calls.append(1)
        if len(calls)==2:raise ValueError('synthetic failure')
        original(connection)
    monkeypatch.setattr(sqlite_backup,'check_integrity',fail_second)
    with pytest.raises(ValueError):sqlite_backup.copy_to_new(source,output)
    assert not output.exists()
    calls.clear()
    def replace_then_fail(connection):
        calls.append(1)
        if len(calls)==2:
            output.unlink();output.write_text('replacement must survive')
            raise ValueError('synthetic failure')
        original(connection)
    monkeypatch.setattr(sqlite_backup,'check_integrity',replace_then_fail)
    with pytest.raises(ValueError):sqlite_backup.copy_to_new(source,output)
    assert output.read_text()=='replacement must survive'


def test_restored_snapshot_contains_users_mfa_and_sessions(env,monkeypatch,tmp_path):
    import base64
    import pyotp
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from backend.app import accounts,main,mfa
    from backend.app.db import get_db
    client,factory=env;monkeypatch.setattr(main,'DEMO',False)
    monkeypatch.setenv('CICC_MFA_KEY',base64.urlsafe_b64encode(b'a'*32).decode())
    secret='JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';real=mfa.match_counter
    monkeypatch.setattr(mfa,'match_counter',lambda s,c:real(s,c,now=3030))
    with factory.begin() as db:
        user=accounts.configure_account(db,'backupuser','synthetic-password-123456','admin',1)
        mfa.enroll(db,user,secret,pyotp.TOTP(secret).generate_otp(100))
    assert client.post('/api/auth/login',json={'username':'backupuser','password':'synthetic-password-123456','otp':pyotp.TOTP(secret).generate_otp(101)}).status_code==200
    snapshot=tmp_path/'backup.sqlite3';restored=tmp_path/'restored.sqlite3'
    sqlite_backup.copy_to_new(tmp_path/'test.db',snapshot);sqlite_backup.copy_to_new(snapshot,restored)
    engine=create_engine(f'sqlite:///{restored}',connect_args={'check_same_thread':False})
    restored_factory=sessionmaker(bind=engine,expire_on_commit=False)
    monkeypatch.setattr(main,'SessionLocal',restored_factory)
    def override():
        with restored_factory() as db:yield db
    main.app.dependency_overrides[get_db]=override
    try:
        # Restoring a snapshot can revive sessions; this is not production recovery.
        response=client.get('/api/auth/session')
        assert response.status_code==200 and response.json()['username']=='backupuser'
    finally:engine.dispose()


def test_restore_to_new_revokes_all_sessions_and_records_recovery(tmp_path):
    from sqlalchemy import create_engine,select
    from sqlalchemy.orm import sessionmaker
    from backend.app import accounts,security,workspaces
    from backend.app.models import Audit,Session,User
    from backend.tests.test_database_workspace_guards import migrate
    source=tmp_path/'source.db';destination=tmp_path/'restored.db'
    result=migrate(source,'upgrade','head');assert result.returncode==0,result.stderr
    engine=create_engine(f'sqlite:///{source}');factory=sessionmaker(bind=engine,expire_on_commit=False)
    with factory.begin() as db:
        workspace=workspaces.create_workspace(db,'other','Other')
        first=accounts.configure_account(db,'firstrestore','synthetic-password-123456','admin',1)
        second=accounts.configure_account(db,'secondrestore','synthetic-password-123456','viewer',workspace.id)
        token1,_=security.create_session(db,first.id);token2,_=security.create_session(db,second.id)
    engine.dispose()
    assert sqlite_backup.restore_to_new(source,destination)==2
    assert stat.S_IMODE(destination.stat().st_mode)==0o600
    restored_engine=create_engine(f'sqlite:///{destination}');restored=sessionmaker(bind=restored_engine)
    with restored() as db:
        assert security.get_session(db,token1) is None and security.get_session(db,token2) is None
        assert not db.scalars(select(Session)).all()
        assert len(db.scalars(select(User)).all())==2
        audit=db.scalar(select(Audit).where(Audit.action=='recovery.sessions_revoked'))
        assert audit.workspace_id is None and audit.actor=='local-cli' and audit.detail=='2 sessions removed from restored copy'
    restored_engine.dispose()
    with sqlite3.connect(source) as db:assert db.execute('SELECT count(*) FROM sessions').fetchone()==(2,)
    sqlite_backup.verify(destination)
    assert not list(tmp_path.glob('.cicc-restore-*'))


def test_restore_fails_closed_for_stale_schema_existing_target_and_sanitizer_failure(tmp_path,monkeypatch):
    from backend.tests.test_database_workspace_guards import migrate
    source=tmp_path/'source.db';target=tmp_path/'target.db'
    result=migrate(source,'upgrade','head');assert result.returncode==0,result.stderr
    target.write_text('do not overwrite')
    with pytest.raises(FileExistsError):sqlite_backup.restore_to_new(source,target)
    assert target.read_text()=='do not overwrite'
    target.unlink()
    with sqlite3.connect(source) as db:db.execute("UPDATE alembic_version SET version_num='old'")
    with pytest.raises(ValueError,match='schema revision'):sqlite_backup.restore_to_new(source,target)
    assert not target.exists()
    with sqlite3.connect(source) as db:db.execute('UPDATE alembic_version SET version_num=?',(sqlite_backup.current_schema_head(),))
    def fail(_):raise RuntimeError('synthetic failure')
    monkeypatch.setattr(sqlite_backup,'_sanitize_restore',fail)
    with pytest.raises(RuntimeError):sqlite_backup.restore_to_new(source,target)
    assert not target.exists() and not list(tmp_path.glob('.cicc-restore-*'))


def test_restore_cli_requires_acknowledgment(tmp_path,monkeypatch,capsys):
    from backend.tests.test_database_workspace_guards import migrate
    source=tmp_path/'source.db';target=tmp_path/'target.db'
    result=migrate(source,'upgrade','head');assert result.returncode==0,result.stderr
    monkeypatch.setattr('sys.argv',['sqlite_backup','restore',str(source),str(target)])
    with pytest.raises(SystemExit):sqlite_backup.main()
    assert not target.exists()
    monkeypatch.setattr('sys.argv',['sqlite_backup','restore',str(source),str(target),'--acknowledge-stale-security-state'])
    sqlite_backup.main()
    assert '0 sessions revoked' in capsys.readouterr().out and target.exists()
