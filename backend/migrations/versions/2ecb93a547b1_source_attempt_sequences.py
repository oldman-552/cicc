"""Allocate source attempt order from the database rather than host clocks."""
from alembic import context,op
import sqlalchemy as sa

revision='2ecb93a547b1'
down_revision='ea2dd04051c8'
branch_labels=None
depends_on=None


def upgrade():
    op.add_column('sources',sa.Column('attempt_sequence',sa.BigInteger(),nullable=False,server_default='0'))
    op.add_column('sources',sa.Column('completed_sequence',sa.BigInteger(),nullable=False,server_default='0'))


def downgrade():
    if context.is_offline_mode():raise RuntimeError('Source sequence downgrade requires online validation')
    if op.get_bind().execute(sa.text('SELECT 1 FROM sources LIMIT 1')).first():
        raise RuntimeError('Cannot downgrade while source records exist; removing sequence guards weakens publication ordering')
    op.drop_column('sources','completed_sequence')
    op.drop_column('sources','attempt_sequence')
