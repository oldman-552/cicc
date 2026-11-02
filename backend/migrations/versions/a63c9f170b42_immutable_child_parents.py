"""Prevent reassignment of existing workspace-derived child records.

This is defense in depth, not row-level security or immutable evidence.
"""
from alembic import context, op
import sqlalchemy as sa

revision='a63c9f170b42'
down_revision='23c58ba2b681'
branch_labels=None
depends_on=None

# Child ownership derives from the referenced parent; these references never
# change in the current application. This does not prevent delete/re-insert.
CHILDREN=(('evidence','investigation_id','investigations'),
          ('notes','investigation_id','investigations'),
          ('investigation_events','investigation_id','investigations'),
          ('investigation_techniques','investigation_id','investigations'),
          ('sbom_components','sbom_id','sboms'),
          ('sbom_candidates','component_id','sbom_components'))


def upgrade():
    if context.is_offline_mode():raise RuntimeError('Child parent guard migration requires online validation')
    bind=op.get_bind();dialect=bind.dialect.name
    if dialect not in ('sqlite','postgresql'):raise RuntimeError('Unsupported database for child parent guards')
    # Refuse to install guards over orphaned data. It is impossible to infer the
    # original workspace of records that were reassigned before this migration.
    for table,column,parent in CHILDREN:
        query=f'SELECT 1 FROM {table} c WHERE NOT EXISTS (SELECT 1 FROM {parent} p WHERE p.id=c.{column}) LIMIT 1'
        if bind.execute(sa.text(query)).first():raise RuntimeError(f'Cannot install child parent guards: orphaned records in {table}')
    if dialect=='sqlite':
        for table,column,_ in CHILDREN:
            op.execute(f"CREATE TRIGGER cicc_{table}_parent_immutable BEFORE UPDATE OF {column} ON {table} WHEN NEW.{column} IS NOT OLD.{column} BEGIN SELECT RAISE(ABORT, 'child parent reassignment forbidden'); END")
    else:
        op.execute('''CREATE FUNCTION cicc_child_parent_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN IF (to_jsonb(NEW)->TG_ARGV[0]) IS DISTINCT FROM (to_jsonb(OLD)->TG_ARGV[0]) THEN
                RAISE EXCEPTION 'child parent reassignment forbidden' USING ERRCODE='23514';
            END IF; RETURN NEW; END $$''')
        for table,column,_ in CHILDREN:
            op.execute(f"CREATE TRIGGER cicc_{table}_parent_immutable BEFORE UPDATE OF {column} ON {table} FOR EACH ROW EXECUTE FUNCTION cicc_child_parent_immutable('{column}')")


def downgrade():
    if context.is_offline_mode():raise RuntimeError('Child parent guard downgrade requires online validation')
    bind=op.get_bind();dialect=bind.dialect.name
    if dialect not in ('sqlite','postgresql'):raise RuntimeError('Unsupported database for child parent guards')
    for table,_,_ in CHILDREN:
        if bind.execute(sa.text(f'SELECT 1 FROM {table} LIMIT 1')).first():
            raise RuntimeError('Cannot downgrade while workspace-bound child records exist; removing guards would weaken isolation')
    for table,_,_ in CHILDREN:
        if dialect=='sqlite':op.execute(f'DROP TRIGGER IF EXISTS cicc_{table}_parent_immutable')
        else:op.execute(f'DROP TRIGGER cicc_{table}_parent_immutable ON {table}')
    if dialect=='postgresql':op.execute('DROP FUNCTION cicc_child_parent_immutable()')
