"""add households and memberships

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
Create Date: 2026-02-01 12:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'b8c9d0e1f2a3'
down_revision = 'a7b8c9d0e1f2'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create households table
    op.create_table(
        'households',
        sa.Column('id', postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_households_id'), 'households', ['id'], unique=False)

    # Create household_memberships table
    op.create_table(
        'household_memberships',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('household_id', postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('role', sa.String(length=20), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['household_id'], ['households.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('household_id', 'user_id', name='uq_household_user')
    )
    op.create_index(op.f('ix_household_memberships_id'), 'household_memberships', ['id'], unique=False)
    op.create_index(op.f('ix_household_memberships_household_id'), 'household_memberships', ['household_id'], unique=False)
    op.create_index(op.f('ix_household_memberships_user_id'), 'household_memberships', ['user_id'], unique=False)

    # Modify node_registrations: add household_id and registered_by_user_id, remove user_id
    # First, add new columns as nullable
    op.add_column('node_registrations', sa.Column('household_id', postgresql.UUID(as_uuid=False), nullable=True))
    op.add_column('node_registrations', sa.Column('registered_by_user_id', sa.Integer(), nullable=True))

    # Drop old user_id foreign key and index
    op.drop_constraint('node_registrations_user_id_fkey', 'node_registrations', type_='foreignkey')
    op.drop_index('ix_node_registrations_user_id', table_name='node_registrations')
    op.drop_column('node_registrations', 'user_id')

    # Make household_id non-nullable and add foreign key
    op.alter_column('node_registrations', 'household_id', nullable=False)
    op.create_foreign_key(
        'node_registrations_household_id_fkey',
        'node_registrations', 'households',
        ['household_id'], ['id'],
        ondelete='CASCADE'
    )
    op.create_index(op.f('ix_node_registrations_household_id'), 'node_registrations', ['household_id'], unique=False)

    # Add foreign key for registered_by_user_id
    op.create_foreign_key(
        'node_registrations_registered_by_user_id_fkey',
        'node_registrations', 'users',
        ['registered_by_user_id'], ['id'],
        ondelete='SET NULL'
    )
    op.create_index(op.f('ix_node_registrations_registered_by_user_id'), 'node_registrations', ['registered_by_user_id'], unique=False)


def downgrade() -> None:
    # Restore user_id column to node_registrations
    op.add_column('node_registrations', sa.Column('user_id', sa.Integer(), nullable=True))

    # Drop new foreign keys and indexes
    op.drop_index(op.f('ix_node_registrations_registered_by_user_id'), table_name='node_registrations')
    op.drop_constraint('node_registrations_registered_by_user_id_fkey', 'node_registrations', type_='foreignkey')
    op.drop_index(op.f('ix_node_registrations_household_id'), table_name='node_registrations')
    op.drop_constraint('node_registrations_household_id_fkey', 'node_registrations', type_='foreignkey')

    # Drop new columns
    op.drop_column('node_registrations', 'registered_by_user_id')
    op.drop_column('node_registrations', 'household_id')

    # Restore old user_id constraints (set to nullable since data was lost)
    op.create_index('ix_node_registrations_user_id', 'node_registrations', ['user_id'], unique=False)
    op.create_foreign_key(
        'node_registrations_user_id_fkey',
        'node_registrations', 'users',
        ['user_id'], ['id'],
        ondelete='CASCADE'
    )

    # Drop household_memberships
    op.drop_index(op.f('ix_household_memberships_user_id'), table_name='household_memberships')
    op.drop_index(op.f('ix_household_memberships_household_id'), table_name='household_memberships')
    op.drop_index(op.f('ix_household_memberships_id'), table_name='household_memberships')
    op.drop_table('household_memberships')

    # Drop households
    op.drop_index(op.f('ix_households_id'), table_name='households')
    op.drop_table('households')
