"""Revoke sessions when supported database identity security state changes.

These database safeguards do not authenticate operators or replace RLS.
"""
from alembic import context,op
import sqlalchemy as sa

revision='ea2dd04051c8'
down_revision='c1af7842d90b'
branch_labels=None
depends_on=None


def upgrade():
    if context.is_offline_mode():raise RuntimeError('Security state guard migration requires online validation')
    dialect=op.get_bind().dialect.name
    if dialect not in ('sqlite','postgresql'):raise RuntimeError('Unsupported database for security state guards')
    if dialect=='sqlite':
        for table in ('sessions','user_mfa'):
            op.execute(f"CREATE TRIGGER cicc_{table}_user_immutable BEFORE UPDATE OF user_id ON {table} WHEN NEW.user_id IS NOT OLD.user_id BEGIN SELECT RAISE(ABORT, 'security record parent reassignment forbidden'); END")
        op.execute('''CREATE TRIGGER cicc_users_auth_change_revoke AFTER UPDATE OF username,role,password_hash,active ON users
            WHEN NEW.username IS NOT OLD.username OR NEW.role IS NOT OLD.role OR NEW.password_hash IS NOT OLD.password_hash OR NEW.active IS NOT OLD.active
            BEGIN DELETE FROM sessions WHERE user_id=NEW.id; END''')
        op.execute('''CREATE TRIGGER cicc_workspaces_active_revoke AFTER UPDATE OF active ON workspaces
            WHEN NEW.active IS NOT OLD.active
            BEGIN DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE workspace_id=NEW.id); END''')
        op.execute('''CREATE TRIGGER cicc_user_mfa_insert_revoke AFTER INSERT ON user_mfa
            BEGIN DELETE FROM sessions WHERE user_id=NEW.user_id; END''')
        op.execute('''CREATE TRIGGER cicc_user_mfa_update_revoke AFTER UPDATE OF encrypted_secret ON user_mfa
            WHEN NEW.encrypted_secret IS NOT OLD.encrypted_secret
            BEGIN DELETE FROM sessions WHERE user_id=NEW.user_id; END''')
        op.execute('''CREATE TRIGGER cicc_user_mfa_delete_revoke AFTER DELETE ON user_mfa
            BEGIN DELETE FROM sessions WHERE user_id=OLD.user_id; END''')
    else:
        for table in ('sessions','user_mfa'):
            op.execute(f"CREATE TRIGGER cicc_{table}_user_immutable BEFORE UPDATE OF user_id ON {table} FOR EACH ROW EXECUTE FUNCTION cicc_child_parent_immutable('user_id')")
        op.execute('''CREATE FUNCTION cicc_revoke_user_auth_change() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN IF NEW.username IS DISTINCT FROM OLD.username OR NEW.role IS DISTINCT FROM OLD.role OR NEW.password_hash IS DISTINCT FROM OLD.password_hash OR NEW.active IS DISTINCT FROM OLD.active THEN
                DELETE FROM sessions WHERE user_id=NEW.id;
            END IF; RETURN NEW; END $$''')
        op.execute('''CREATE TRIGGER cicc_users_auth_change_revoke AFTER UPDATE OF username,role,password_hash,active ON users
            FOR EACH ROW EXECUTE FUNCTION cicc_revoke_user_auth_change()''')
        op.execute('''CREATE FUNCTION cicc_revoke_workspace_active_change() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN IF NEW.active IS DISTINCT FROM OLD.active THEN
                DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE workspace_id=NEW.id);
            END IF; RETURN NEW; END $$''')
        op.execute('''CREATE TRIGGER cicc_workspaces_active_revoke AFTER UPDATE OF active ON workspaces
            FOR EACH ROW EXECUTE FUNCTION cicc_revoke_workspace_active_change()''')
        op.execute('''CREATE FUNCTION cicc_revoke_mfa_change() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN IF TG_OP='DELETE' THEN DELETE FROM sessions WHERE user_id=OLD.user_id; RETURN OLD;
            ELSE DELETE FROM sessions WHERE user_id=NEW.user_id; RETURN NEW; END IF; END $$''')
        op.execute('''CREATE TRIGGER cicc_user_mfa_insert_revoke AFTER INSERT ON user_mfa
            FOR EACH ROW EXECUTE FUNCTION cicc_revoke_mfa_change()''')
        op.execute('''CREATE TRIGGER cicc_user_mfa_update_revoke AFTER UPDATE OF encrypted_secret ON user_mfa
            FOR EACH ROW WHEN (NEW.encrypted_secret IS DISTINCT FROM OLD.encrypted_secret) EXECUTE FUNCTION cicc_revoke_mfa_change()''')
        op.execute('''CREATE TRIGGER cicc_user_mfa_delete_revoke AFTER DELETE ON user_mfa
            FOR EACH ROW EXECUTE FUNCTION cicc_revoke_mfa_change()''')


def downgrade():
    if context.is_offline_mode():raise RuntimeError('Security state guard downgrade requires online validation')
    bind=op.get_bind();dialect=bind.dialect.name
    if dialect not in ('sqlite','postgresql'):raise RuntimeError('Unsupported database for security state guards')
    if bind.execute(sa.text('SELECT 1 FROM users LIMIT 1')).first():
        raise RuntimeError('Cannot downgrade while accounts exist; removing session revocation guards would weaken authorization')
    for table,name in (('sessions','cicc_sessions_user_immutable'),('user_mfa','cicc_user_mfa_user_immutable'),('users','cicc_users_auth_change_revoke'),('workspaces','cicc_workspaces_active_revoke'),('user_mfa','cicc_user_mfa_insert_revoke'),('user_mfa','cicc_user_mfa_update_revoke'),('user_mfa','cicc_user_mfa_delete_revoke')):
        op.execute(f'DROP TRIGGER {"IF EXISTS " if dialect=="sqlite" else ""}{name}'+('' if dialect=='sqlite' else f' ON {table}'))
    if dialect=='postgresql':
        for name in ('cicc_revoke_user_auth_change','cicc_revoke_workspace_active_change','cicc_revoke_mfa_change'):
            op.execute(f'DROP FUNCTION {name}()')
