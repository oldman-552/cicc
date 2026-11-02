"""FIRST EPSS limited sample cache."""
from alembic import op
import sqlalchemy as sa

revision='35a07a27de4a'
down_revision='b8936d1c2327'
branch_labels=None
depends_on=None


def upgrade():
    op.create_table('epss_scores',
        sa.Column('cve',sa.String(32),primary_key=True),
        sa.Column('score',sa.String(16),nullable=False),
        sa.Column('percentile',sa.String(16),nullable=False),
        sa.Column('score_date',sa.String(10),nullable=False),
        sa.Column('collected_at',sa.DateTime(timezone=True),nullable=False))


def downgrade():
    op.execute("DELETE FROM sources WHERE id='epss'")
    op.drop_table('epss_scores')
