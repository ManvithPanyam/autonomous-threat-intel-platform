"""add_llm_prompt_logs_and_analyst_summary

Revision ID: 001_phase7
Revises: 
Create Date: 2026-07-27 21:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001_phase7'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    
    # Add Phase 6 & 7 columns to cases if missing
    columns = [c['name'] for c in inspector.get_columns('cases')]
    if 'technique_id' not in columns:
        op.add_column('cases', sa.Column('technique_id', sa.String(length=50), nullable=True))
    if 'technique_name' not in columns:
        op.add_column('cases', sa.Column('technique_name', sa.String(length=255), nullable=True))
    if 'severity_score' not in columns:
        op.add_column('cases', sa.Column('severity_score', sa.Integer(), nullable=True))
    if 'severity_tier' not in columns:
        op.add_column('cases', sa.Column('severity_tier', sa.String(length=50), nullable=True))
    if 'severity_explanation' not in columns:
        op.add_column('cases', sa.Column('severity_explanation', sa.Text(), nullable=True))
    if 'analyst_summary' not in columns:
        op.add_column('cases', sa.Column('analyst_summary', sa.Text(), nullable=True))


    # Create llm_prompt_logs table if missing
    tables = inspector.get_table_names()
    if 'llm_prompt_logs' not in tables:
        op.create_table(
            'llm_prompt_logs',
            sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column('case_id', sa.Integer(), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False),
            sa.Column('provider', sa.String(length=50), nullable=False),
            sa.Column('model', sa.String(length=100), nullable=False),
            sa.Column('prompt', sa.Text(), nullable=False),
            sa.Column('response', sa.Text(), nullable=False),
            sa.Column('tokens_used', sa.Integer(), nullable=True, server_default='0'),
            sa.Column('latency_ms', sa.Integer(), nullable=True, server_default='0'),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        )



def downgrade() -> None:
    op.drop_table('llm_prompt_logs')
    op.drop_column('cases', 'analyst_summary')
