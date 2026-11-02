import base64
import sqlite3
import stat
import pytest
from cryptography.exceptions import InvalidTag
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.app import accounts,secure_backup,security
from backend.tests.test_database_workspace_guards import migrate


def source_db(tmp_path):
    source=tmp_path/'source.db';result=migrate(source,'upgrade','head');assert result.returncode==0,result.stderr
    engine=create_engine(f'sqlite:///{source}');factory=sessionmaker(bind=engine,expire_on_commit=False)
    with factory.begin() as db:
        user=accounts.configure_account(db,'secureuser','synthetic-password-123456','admin',1)
        security.create_session(db,user.id)
    engine.dispose()
    with sqlite3.connect(source) as db:
        db.execute("INSERT INTO investigations(workspace_id,title,status,created_at) VALUES (1,'private synthetic recovery value','open','2025-01-01')")
    return source


def test_authenticated_encrypted_backup_restores_without_sessions(tmp_path):
    source=source_db(tmp_path);encrypted=tmp_path/'encrypted.cicc';restored=tmp_path/'restored.db';key=b'k'*32
    secure_backup.create_encrypted_backup(source,encrypted,key)
    assert b'private synthetic recovery value' not in encrypted.read_bytes()
    assert stat.S_IMODE(encrypted.stat().st_mode)==0o600
    assert secure_backup.restore_encrypted_backup(encrypted,restored,key)==1
    with sqlite3.connect(restored) as db:
        assert db.execute('SELECT count(*) FROM sessions').fetchone()==(0,)
        assert db.execute('SELECT title FROM investigations').fetchone()==('private synthetic recovery value',)
        assert db.execute("SELECT count(*) FROM audit WHERE action='recovery.sessions_revoked'").fetchone()==(1,)
    with sqlite3.connect(source) as db:assert db.execute('SELECT count(*) FROM sessions').fetchone()==(1,)
    assert not list(tmp_path.glob('.cicc-*'))


@pytest.mark.parametrize('corruption',['nonce','ciphertext','tag','wrong_key','truncate','header'])
def test_encrypted_restore_rejects_tampering_without_publishing(tmp_path,corruption):
    source=source_db(tmp_path);encrypted=tmp_path/'encrypted.cicc';target=tmp_path/'restored.db';key=b'k'*32
    secure_backup.create_encrypted_backup(source,encrypted,key)
    payload=bytearray(encrypted.read_bytes())
    if corruption=='nonce':payload[len(secure_backup.MAGIC)]^=1
    if corruption=='ciphertext':payload[len(secure_backup.MAGIC)+secure_backup.NONCE_SIZE]^=1
    if corruption=='tag':payload[-1]^=1
    if corruption=='truncate':payload=payload[:10]
    if corruption=='header':payload[0]^=1
    encrypted.write_bytes(payload)
    if corruption=='wrong_key':key=b'w'*32
    with pytest.raises((InvalidTag,ValueError)):secure_backup.restore_encrypted_backup(encrypted,target,key)
    assert not target.exists() and not list(tmp_path.glob('.cicc-*'))
    with sqlite3.connect(source) as db:assert db.execute('SELECT count(*) FROM sessions').fetchone()==(1,)


def test_encrypted_backup_respects_limits_and_never_overwrites(tmp_path,monkeypatch):
    source=source_db(tmp_path);encrypted=tmp_path/'encrypted.cicc';target=tmp_path/'restored.db';key=b'k'*32
    monkeypatch.setattr(secure_backup,'MAX_BYTES',1)
    with pytest.raises(ValueError,match='limit'):secure_backup.create_encrypted_backup(source,encrypted,key)
    assert not encrypted.exists() and not list(tmp_path.glob('.cicc-*'))
    monkeypatch.setattr(secure_backup,'MAX_BYTES',256*1024*1024)
    secure_backup.create_encrypted_backup(source,encrypted,key);original=encrypted.read_bytes()
    with pytest.raises(FileExistsError):secure_backup.create_encrypted_backup(source,encrypted,key)
    assert encrypted.read_bytes()==original
    target.write_text('do not overwrite')
    with pytest.raises(FileExistsError):secure_backup.restore_encrypted_backup(encrypted,target,key)
    assert target.read_text()=='do not overwrite'


def test_backup_cli_requires_acknowledgments_and_valid_secret(tmp_path,monkeypatch,capsys):
    source=source_db(tmp_path);encrypted=tmp_path/'encrypted.cicc';target=tmp_path/'restored.db'
    monkeypatch.setenv('CICC_BACKUP_KEY',base64.urlsafe_b64encode(b'k'*32).decode())
    monkeypatch.setattr('sys.argv',['secure_backup','create',str(source),str(encrypted)])
    with pytest.raises(SystemExit):secure_backup.main()
    assert not encrypted.exists()
    monkeypatch.setattr('sys.argv',['secure_backup','create',str(source),str(encrypted),'--acknowledge-plaintext-staging'])
    secure_backup.main();assert encrypted.exists()
    monkeypatch.setattr('sys.argv',['secure_backup','restore',str(encrypted),str(target),'--acknowledge-plaintext-staging'])
    with pytest.raises(SystemExit):secure_backup.main()
    assert not target.exists()
    monkeypatch.setattr('sys.argv',['secure_backup','restore',str(encrypted),str(target),'--acknowledge-plaintext-staging','--acknowledge-stale-security-state'])
    secure_backup.main();assert '1 sessions revoked' in capsys.readouterr().out
    for invalid in ('','%%%','bm90MzJieXRlcw=='):
        monkeypatch.setenv('CICC_BACKUP_KEY',invalid)
        with pytest.raises(ValueError):secure_backup.backup_key()


def test_backup_rejects_non_256_bit_keys_and_cleans_up(tmp_path):
    source=source_db(tmp_path);target=tmp_path/'backup.cicc'
    for key in (b'a'*16,b'a'*24,b'',None):
        with pytest.raises(ValueError,match='32 bytes'):secure_backup.create_encrypted_backup(source,target,key)
    assert not target.exists() and not list(tmp_path.glob('.cicc-*'))
