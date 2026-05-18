"""add refresh token rotation chain

Revision ID: a3b4c5d6e7f8
Revises: f2a3b4c5d6e7
Create Date: 2026-05-17 20:40:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

# revision identifiers, used by Alembic.
revision = "a3b4c5d6e7f8"
down_revision = "f2a3b4c5d6e7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    op.add_column(
        "refresh_tokens",
        sa.Column("family_id", UUID(as_uuid=False), nullable=True),
    )
    op.add_column(
        "refresh_tokens",
        sa.Column("parent_id", sa.Integer(), nullable=True),
    )
    op.add_column(
        "refresh_tokens",
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.execute("UPDATE refresh_tokens SET family_id = gen_random_uuid() WHERE family_id IS NULL")

    op.alter_column("refresh_tokens", "family_id", nullable=False)

    op.create_foreign_key(
        "fk_refresh_tokens_parent",
        "refresh_tokens",
        "refresh_tokens",
        ["parent_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_refresh_tokens_family_id",
        "refresh_tokens",
        ["family_id"],
    )
    op.create_index(
        "ix_refresh_tokens_family_revoked",
        "refresh_tokens",
        ["family_id", "revoked"],
    )


def downgrade() -> None:
    op.drop_index("ix_refresh_tokens_family_revoked", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_family_id", table_name="refresh_tokens")
    op.drop_constraint("fk_refresh_tokens_parent", "refresh_tokens", type_="foreignkey")
    op.drop_column("refresh_tokens", "rotated_at")
    op.drop_column("refresh_tokens", "parent_id")
    op.drop_column("refresh_tokens", "family_id")
