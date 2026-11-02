"""Constrain persisted account roles; application still validates at runtime."""
from alembic import context, op
import sqlalchemy as sa

revision='c1af7842d90b'
down_revision='a63c9f170b42'
branch_labels=None
depends_on=None


def upgrade():
    if context.is_offline_mode():raise RuntimeError('Account role guard migration requires online validation')
    bind=op.get_bind();dialect=bind.dialect.name
    if dialect not in ('sqlite','postgresql'):raise RuntimeError('Unsupported database for account role guards')
    if bind.execute(sa.text("SELECT 1 FROM users WHERE role IS NULL OR role NOT IN ('admin','analyst','viewer') LIMIT 1")).first():
        raise RuntimeError('Cannot install account role guard: unsupported role values exist')
    if dialect=='sqlite':
        for event in ('INSERT','UPDATE OF role'):
            suffix='insert' if event=='INSERT' else 'update'
            op.execute(f"CREATE TRIGGER cicc_users_role_{suffix} BEFORE {event} ON users WHEN NEW.role IS NULL OR NEW.role NOT IN ('admin','analyst','viewer') BEGIN SELECT RAISE(ABORT, 'unsupported account role'); END")
    else:
        op.create_check_constraint('cicc_users_role_valid','users',"role IN ('admin','analyst','viewer')")


def downgrade():
    if context.is_offline_mode():raise RuntimeError('Account role guard downgrade requires online validation')
    bind=op.get_bind();dialect=bind.dialect.name
    if dialect not in ('sqlite','postgresql'):raise RuntimeError('Unsupported database for account role guards')
    if bind.execute(sa.text('SELECT 1 FROM users LIMIT 1')).first():
        raise RuntimeError('Cannot downgrade while accounts exist; removing role guards would weaken authorization')
    if dialect=='sqlite':
        op.execute('DROP TRIGGER IF EXISTS cicc_users_role_insert')
        op.execute('DROP TRIGGER IF EXISTS cicc_users_role_update')
    else:op.drop_constraint('cicc_users_role_valid','users',type_='check')
