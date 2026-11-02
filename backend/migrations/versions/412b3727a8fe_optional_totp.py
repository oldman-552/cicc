"""Optional local TOTP with encrypted secrets and replay counter."""
from alembic import context, op
import sqlalchemy as sa

revision='412b3727a8fe'
down_revision='484b2e0f87f1'
branch_labels=None
depends_on=None


def upgrade():
    op.create_table('user_mfa',
        sa.Column('user_id',sa.Integer(),sa.ForeignKey('users.id',ondelete='CASCADE'),primary_key=True),
        sa.Column('encrypted_secret',sa.LargeBinary(),nullable=False),
        sa.Column('last_counter',sa.BigInteger(),nullable=False),
        sa.Column('enabled_at',sa.DateTime(timezone=True),nullable=False))


def downgrade():
    if context.is_offline_mode(): raise RuntimeError('MFA downgrade requires online safety validation')
    if op.get_bind().execute(sa.text('SELECT COUNT(*) FROM user_mfa')).scalar():
        raise RuntimeError('Cannot downgrade while MFA accounts are enrolled; removing the table would bypass MFA')
    op.drop_table('user_mfa')
