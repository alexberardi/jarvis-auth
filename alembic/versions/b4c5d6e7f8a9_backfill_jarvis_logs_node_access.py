"""backfill jarvis-logs grant on active nodes

Revision ID: b4c5d6e7f8a9
Revises: a3b4c5d6e7f8
Create Date: 2026-05-24 18:00:00.000000

Until jarvis-command-center v0.1.33, the node-registration call passed an
empty services list. jarvis-auth auto-granted the calling service only
(jarvis-command-center), so existing active nodes never got access to
jarvis-logs and their log batches were rejected with 403. This backfill
grants jarvis-logs to every active node that doesn't already have it.

"""
from alembic import op


revision = "b4c5d6e7f8a9"
down_revision = "a3b4c5d6e7f8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        INSERT INTO node_service_access (node_id, service_id, granted_at, granted_by)
        SELECT n.node_id, 'jarvis-logs', now(), NULL
        FROM node_registrations n
        WHERE n.is_active = true
          AND NOT EXISTS (
            SELECT 1 FROM node_service_access a
            WHERE a.node_id = n.node_id AND a.service_id = 'jarvis-logs'
          )
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DELETE FROM node_service_access
        WHERE service_id = 'jarvis-logs' AND granted_by IS NULL
        """
    )
