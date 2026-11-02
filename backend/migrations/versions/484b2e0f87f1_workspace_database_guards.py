"""Additional database safeguards for development workspace boundaries.

These constraints are defense in depth, not RLS or production tenant isolation.
"""
from alembic import context, op
import sqlalchemy as sa

revision='484b2e0f87f1'
down_revision='35a07a27de4a'
branch_labels=None
depends_on=None

ROOTS=('users','investigations','assets','sboms')
SCOPED=ROOTS+('audit',)
LINKS=(('investigation_assets','investigation_id','investigations','asset_id','assets'),
       ('asset_sboms','asset_id','assets','sbom_id','sboms'))


def preflight(bind):
    # Existing bad records are not silently repaired, deleted, or reassigned.
    for table in SCOPED:
        condition='t.workspace_id IS NOT NULL AND ' if table=='audit' else ''
        sql=f'SELECT COUNT(*) FROM {table} t WHERE {condition}NOT EXISTS (SELECT 1 FROM workspaces w WHERE w.id=t.workspace_id)'
        if bind.execute(sa.text(sql)).scalar():
            raise RuntimeError(f'Cannot install workspace guards: invalid workspace references in {table}')
    for table,left,left_table,right,right_table in LINKS:
        sql=f'''SELECT COUNT(*) FROM {table} l WHERE NOT EXISTS
                (SELECT 1 FROM {left_table} a JOIN {right_table} b ON a.workspace_id=b.workspace_id
                 WHERE a.id=l.{left} AND b.id=l.{right})'''
        if bind.execute(sa.text(sql)).scalar():
            raise RuntimeError(f'Cannot install workspace guards: invalid or cross-workspace links in {table}')


def upgrade():
    if context.is_offline_mode(): raise RuntimeError('Workspace guard migration requires online validation')
    bind=op.get_bind();dialect=bind.dialect.name
    if dialect not in ('sqlite','postgresql'): raise RuntimeError('Unsupported database for workspace guards')
    preflight(bind)
    if dialect=='sqlite':
        for table in SCOPED:
            condition=('NEW.workspace_id IS NOT NULL AND ' if table=='audit' else '')+'NOT EXISTS (SELECT 1 FROM workspaces WHERE id=NEW.workspace_id)'
            for event in ('INSERT','UPDATE OF workspace_id'):
                name=f'cicc_{table}_workspace_{"insert" if event=="INSERT" else "update"}'
                op.execute(f"CREATE TRIGGER {name} BEFORE {event} ON {table} WHEN {condition} BEGIN SELECT RAISE(ABORT, 'invalid workspace reference'); END")
        for table in ROOTS:
            op.execute(f"CREATE TRIGGER cicc_{table}_workspace_immutable BEFORE UPDATE OF workspace_id ON {table} WHEN NEW.workspace_id IS NOT OLD.workspace_id BEGIN SELECT RAISE(ABORT, 'workspace reassignment forbidden'); END")
        references=' OR '.join(f'EXISTS (SELECT 1 FROM {table} WHERE workspace_id=OLD.id)' for table in SCOPED)
        op.execute(f"CREATE TRIGGER cicc_workspace_delete_guard BEFORE DELETE ON workspaces WHEN {references} BEGIN SELECT RAISE(ABORT, 'workspace is referenced'); END")
        op.execute(f"CREATE TRIGGER cicc_workspace_id_guard BEFORE UPDATE OF id ON workspaces WHEN NEW.id IS NOT OLD.id AND ({references}) BEGIN SELECT RAISE(ABORT, 'workspace is referenced'); END")
        for table,left,left_table,right,right_table in LINKS:
            condition=f'NOT EXISTS (SELECT 1 FROM {left_table} a JOIN {right_table} b ON a.workspace_id=b.workspace_id WHERE a.id=NEW.{left} AND b.id=NEW.{right})'
            for event in ('INSERT',f'UPDATE OF {left}, {right}'):
                name=f'cicc_{table}_{"insert" if event=="INSERT" else "update"}'
                op.execute(f"CREATE TRIGGER {name} BEFORE {event} ON {table} WHEN {condition} BEGIN SELECT RAISE(ABORT, 'invalid or cross-workspace link'); END")
    else:
        for table in SCOPED:
            op.create_foreign_key(f'cicc_{table}_workspace_fk',table,'workspaces',['workspace_id'],['id'])
        op.execute('''CREATE FUNCTION cicc_workspace_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id THEN
                RAISE EXCEPTION 'workspace reassignment forbidden' USING ERRCODE='23514';
            END IF; RETURN NEW; END $$''')
        for table in ROOTS:
            op.execute(f'CREATE TRIGGER cicc_{table}_workspace_immutable BEFORE UPDATE OF workspace_id ON {table} FOR EACH ROW EXECUTE FUNCTION cicc_workspace_immutable()')
        for table,left,left_table,right,right_table in LINKS:
            function=f'cicc_{table}_check'
            op.execute(f'''CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN IF NOT EXISTS (SELECT 1 FROM {left_table} a JOIN {right_table} b ON a.workspace_id=b.workspace_id
                    WHERE a.id=NEW.{left} AND b.id=NEW.{right}) THEN
                    RAISE EXCEPTION 'invalid or cross-workspace link' USING ERRCODE='23514';
                END IF; RETURN NEW; END $$''')
            op.execute(f'CREATE TRIGGER cicc_{table}_guard BEFORE INSERT OR UPDATE OF {left}, {right} ON {table} FOR EACH ROW EXECUTE FUNCTION {function}()')


def downgrade():
    if context.is_offline_mode(): raise RuntimeError('Workspace guard downgrade requires an online database')
    dialect=op.get_bind().dialect.name
    if dialect=='sqlite':
        for table in SCOPED:
            for action in ('insert','update'):op.execute(f'DROP TRIGGER IF EXISTS cicc_{table}_workspace_{action}')
        for table in ROOTS:op.execute(f'DROP TRIGGER IF EXISTS cicc_{table}_workspace_immutable')
        op.execute('DROP TRIGGER IF EXISTS cicc_workspace_delete_guard')
        op.execute('DROP TRIGGER IF EXISTS cicc_workspace_id_guard')
        for table,*_ in LINKS:
            for action in ('insert','update'):op.execute(f'DROP TRIGGER IF EXISTS cicc_{table}_{action}')
    elif dialect=='postgresql':
        for table,*_ in LINKS:
            op.execute(f'DROP TRIGGER cicc_{table}_guard ON {table}')
            op.execute(f'DROP FUNCTION cicc_{table}_check()')
        for table in ROOTS:op.execute(f'DROP TRIGGER cicc_{table}_workspace_immutable ON {table}')
        op.execute('DROP FUNCTION cicc_workspace_immutable()')
        for table in SCOPED:op.drop_constraint(f'cicc_{table}_workspace_fk',table,type_='foreignkey')
    else: raise RuntimeError('Unsupported database for workspace guards')
