"""Refresh-token revocation shared by logout, change-password and admin resets.

Revocation must also purge the in-process grace cache (`core/refresh_cache`):
a just-rotated parent token can otherwise re-serve its cached successor for
`REFRESH_TOKEN_GRACE_SECONDS` after the family was revoked in the DB.

Callers own the commit.
"""
from sqlalchemy.orm import Session

from jarvis_auth.app.core import refresh_cache
from jarvis_auth.app.db import models


def _lock_user(db: Session, user_id: int) -> None:
    """Take the user's row lock so revocation serializes with /auth/refresh.

    Refresh takes the same lock before minting a successor, so either the
    rotation commits first (and our snapshot below includes the successor) or
    we commit first (and refresh re-reads the parent as revoked). No-op on
    SQLite (tests).
    """
    db.query(models.User).filter(models.User.id == user_id).with_for_update().first()


def _revoke_rows(rows: list[models.RefreshToken]) -> int:
    revoked = 0
    for row in rows:
        if not row.revoked:
            row.revoked = True
            revoked += 1
        refresh_cache.delete(row.id)
    return revoked


def revoke_user_refresh_tokens(db: Session, user_id: int) -> int:
    """Revoke every refresh token the user has, across all families/devices."""
    _lock_user(db, user_id)
    rows = (
        db.query(models.RefreshToken)
        .filter(models.RefreshToken.user_id == user_id)
        .all()
    )
    return _revoke_rows(rows)


def revoke_family(db: Session, family_id: str, user_id: int) -> int:
    """Revoke one rotation family — i.e. one device's session."""
    _lock_user(db, user_id)
    rows = (
        db.query(models.RefreshToken)
        .filter(models.RefreshToken.family_id == family_id)
        .all()
    )
    return _revoke_rows(rows)
