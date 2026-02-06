"""Seed default settings

Revision ID: e1f2a3b4c5d6
Revises: d0e1f2a3b4c5
Create Date: 2026-02-05 16:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'e1f2a3b4c5d6'
down_revision = 'd0e1f2a3b4c5'
branch_labels = None
depends_on = None


# Settings definitions from jarvis_auth/app/services/settings_service.py
SETTINGS = [
    {
        "key": "auth.token.access_expire_minutes",
        "value": "30",
        "value_type": "int",
        "category": "auth.token",
        "description": "Access token expiration time in minutes",
        "env_fallback": "ACCESS_TOKEN_EXPIRE_MINUTES",
        "requires_reload": False,
        "is_secret": False,
    },
    {
        "key": "auth.token.refresh_expire_days",
        "value": "14",
        "value_type": "int",
        "category": "auth.token",
        "description": "Refresh token expiration time in days",
        "env_fallback": "REFRESH_TOKEN_EXPIRE_DAYS",
        "requires_reload": False,
        "is_secret": False,
    },
    {
        "key": "auth.algorithm",
        "value": "HS256",
        "value_type": "string",
        "category": "auth",
        "description": "JWT signing algorithm",
        "env_fallback": "AUTH_ALGORITHM",
        "requires_reload": False,
        "is_secret": False,
    },
]


def upgrade() -> None:
    # Get the connection
    conn = op.get_bind()

    # Check if we're using PostgreSQL or SQLite
    is_postgres = conn.dialect.name == 'postgresql'

    for setting in SETTINGS:
        if is_postgres:
            # PostgreSQL: use ON CONFLICT DO NOTHING
            conn.execute(
                sa.text("""
                    INSERT INTO settings (key, value, value_type, category, description,
                                         env_fallback, requires_reload, is_secret,
                                         household_id, node_id, user_id)
                    VALUES (:key, :value, :value_type, :category, :description,
                           :env_fallback, :requires_reload, :is_secret,
                           NULL, NULL, NULL)
                    ON CONFLICT (key, household_id, node_id, user_id) DO NOTHING
                """),
                setting
            )
        else:
            # SQLite: use INSERT OR IGNORE
            conn.execute(
                sa.text("""
                    INSERT OR IGNORE INTO settings (key, value, value_type, category, description,
                                                   env_fallback, requires_reload, is_secret,
                                                   household_id, node_id, user_id)
                    VALUES (:key, :value, :value_type, :category, :description,
                           :env_fallback, :requires_reload, :is_secret,
                           NULL, NULL, NULL)
                """),
                setting
            )


def downgrade() -> None:
    conn = op.get_bind()
    for setting in SETTINGS:
        conn.execute(
            sa.text("""
                DELETE FROM settings
                WHERE key = :key
                  AND household_id IS NULL
                  AND node_id IS NULL
                  AND user_id IS NULL
            """),
            {"key": setting["key"]}
        )
