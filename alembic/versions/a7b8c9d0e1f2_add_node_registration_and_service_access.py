"""add node registration and service access tables

Revision ID: a7b8c9d0e1f2
Revises: fd09b451cc1b
Create Date: 2026-01-24 12:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'a7b8c9d0e1f2'
down_revision = 'fd09b451cc1b'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create node_registrations table
    op.create_table(
        'node_registrations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('node_id', sa.String(length=255), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('node_key_hash', sa.String(length=255), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_rotated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_node_registrations_id'), 'node_registrations', ['id'], unique=False)
    op.create_index(op.f('ix_node_registrations_node_id'), 'node_registrations', ['node_id'], unique=True)
    op.create_index(op.f('ix_node_registrations_user_id'), 'node_registrations', ['user_id'], unique=False)

    # Create node_service_access table
    op.create_table(
        'node_service_access',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('node_id', sa.String(length=255), nullable=False),
        sa.Column('service_id', sa.String(length=255), nullable=False),
        sa.Column('granted_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('granted_by', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['node_id'], ['node_registrations.node_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['granted_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('node_id', 'service_id', name='uq_node_service_access')
    )
    op.create_index(op.f('ix_node_service_access_id'), 'node_service_access', ['id'], unique=False)
    op.create_index(op.f('ix_node_service_access_node_id'), 'node_service_access', ['node_id'], unique=False)
    op.create_index(op.f('ix_node_service_access_service_id'), 'node_service_access', ['service_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_node_service_access_service_id'), table_name='node_service_access')
    op.drop_index(op.f('ix_node_service_access_node_id'), table_name='node_service_access')
    op.drop_index(op.f('ix_node_service_access_id'), table_name='node_service_access')
    op.drop_table('node_service_access')
    op.drop_index(op.f('ix_node_registrations_user_id'), table_name='node_registrations')
    op.drop_index(op.f('ix_node_registrations_node_id'), table_name='node_registrations')
    op.drop_index(op.f('ix_node_registrations_id'), table_name='node_registrations')
    op.drop_table('node_registrations')
