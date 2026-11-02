"""Record whether a session passed TOTP, allowing an opt-in enforcement policy."""
from alembic import context, op
import sqlalchemy as sa

revision='23c58ba2b681'
down_revision='412b3727a8fe'
branch_labels=None
depends_on=None


def upgrade():
    # Existing sessions are conservatively marked as not MFA-verified.
    op.add_column('sessions',sa.Column('mfa_verified',sa.Boolean(),nullable=False,server_default=sa.false()))


def downgrade():
    if context.is_offline_mode():raise RuntimeError('MFA assurance downgrade requires online safety validation')
    if op.get_bind().execute(sa.text('SELECT COUNT(*) FROM user_mfa')).scalar():
        raise RuntimeError('Cannot downgrade while MFA accounts are enrolled; removing session assurance would weaken MFA')
    op.drop_column('sessions','mfa_verified')
