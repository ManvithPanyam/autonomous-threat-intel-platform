"""add_containment_action_fields_and_audit_logs

Revision ID: 002_phase8
Revises: 001_phase7
Create Date: 2026-07-27 21:40:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '002_phase8'
down_revision: Union[str, None] = '001_phase7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # 1. Add missing columns to containment_actions
    ca_cols = [c['name'] for c in inspector.get_columns('containment_actions')]
    if 'target' not in ca_cols:
        op.add_column('containment_actions', sa.Column('target', sa.String(length=255), nullable=True))
    if 'mock_result' not in ca_cols:
        op.add_column('containment_actions', sa.Column('mock_result', postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    if 'operator_id' not in ca_cols:
        op.add_column('containment_actions', sa.Column('operator_id', sa.String(length=100), nullable=True))
    if 'denied_at' not in ca_cols:
        op.add_column('containment_actions', sa.Column('denied_at', sa.DateTime(timezone=True), nullable=True))
    if 'denial_reason' not in ca_cols:
        op.add_column('containment_actions', sa.Column('denial_reason', sa.Text(), nullable=True))

    # 2. Create audit_logs table if not exists
    tables = inspector.get_table_names()
    if 'audit_logs' not in tables:
        op.create_table(
            'audit_logs',
            sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column('case_id', sa.Integer(), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=True),
            sa.Column('action_id', sa.Integer(), sa.ForeignKey('containment_actions.id', ondelete='CASCADE'), nullable=True),
            sa.Column('actor', sa.String(length=100), nullable=False),
            sa.Column('action', sa.String(length=100), nullable=False),
            sa.Column('before_state', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
            sa.Column('after_state', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        )


def downgrade() -> None:
    op.drop_table('audit_logs')
    op.drop_column('containment_actions', 'denial_reason')
    op.drop_column('containment_actions', 'denied_at')
    op.drop_column('containment_actions', 'operator_id')
    op.drop_column('containment_actions', 'mock_result')
    op.drop_column('containment_actions', 'target')
