"""Account-deletion orchestration.

Deleting an account is a multi-step, ordered operation that fans out to
downstream services BEFORE touching any local state, so that a guard failure
or a downstream 5xx leaves the account fully intact.

Order (see DELETE /auth/me):
    a. verify password
    b. nodes guard   (>=1 active node registered to user -> 409)
    c. household guard (admin of any household -> 409)
    d. downstream purge fan-out (CC + notifications), tolerant-blocking
    e. delete user-scoped settings rows
    f. delete the user's household memberships
    g. delete the user (refresh tokens cascade)
    h. commit
"""

import logging

import httpx
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from jarvis_auth.app.core import service_config
from jarvis_auth.app.db import models
from jarvis_auth.app.db.models import HouseholdRole

logger = logging.getLogger(__name__)

_PURGE_PATH = "/api/v0/me/data"
_PURGE_TIMEOUT_SECONDS = 5.0


def _has_active_node(db: Session, user_id: int) -> bool:
    """True if the user has >=1 active node registered to them."""
    return (
        db.query(models.NodeRegistration)
        .filter(
            models.NodeRegistration.registered_by_user_id == user_id,
            models.NodeRegistration.is_active.is_(True),
        )
        .first()
        is not None
    )


def _blocking_shared_household(db: Session, user_id: int) -> bool:
    """True if the user is the ONLY admin of a household that has OTHER members.

    Removing such a user would orphan the household with no admin, so deletion is
    blocked until they hand off admin (mirrors households.py leave_household). A
    SOLO household (only this user) is NOT blocking — it is auto-deleted with the
    account. A shared household where another admin remains is also fine.
    """
    memberships = (
        db.query(models.HouseholdMembership)
        .filter(models.HouseholdMembership.user_id == user_id)
        .all()
    )
    for membership in memberships:
        if membership.role != HouseholdRole.ADMIN:
            continue
        total_members = (
            db.query(models.HouseholdMembership)
            .filter(
                models.HouseholdMembership.household_id == membership.household_id
            )
            .count()
        )
        if total_members <= 1:
            continue  # solo household -> auto-deleted later, not a block
        other_admins = (
            db.query(models.HouseholdMembership)
            .filter(
                models.HouseholdMembership.household_id == membership.household_id,
                models.HouseholdMembership.user_id != user_id,
                models.HouseholdMembership.role == HouseholdRole.ADMIN,
            )
            .count()
        )
        if other_admins == 0:
            return True
    return False


def _remove_memberships_and_solo_households(db: Session, user_id: int) -> None:
    """Remove the user's memberships; delete any household left with no members.

    A household where the user was the only member is deleted entirely (cascading
    its nodes and invites), mirroring households.py leave_household's last-member
    cleanup. Households with remaining members are left intact.
    """
    memberships = (
        db.query(models.HouseholdMembership)
        .filter(models.HouseholdMembership.user_id == user_id)
        .all()
    )
    household_ids = [m.household_id for m in memberships]
    for membership in memberships:
        db.delete(membership)
    db.flush()

    for household_id in household_ids:
        remaining = (
            db.query(models.HouseholdMembership)
            .filter(models.HouseholdMembership.household_id == household_id)
            .count()
        )
        if remaining == 0:
            household = (
                db.query(models.Household)
                .filter(models.Household.id == household_id)
                .first()
            )
            if household:
                db.delete(household)  # cascade: nodes, invites


def _purge_downstream(base_url: str, token: str, service_name: str) -> None:
    """Call DELETE {base_url}/api/v0/me/data, forwarding the user's Bearer token.

    Tolerant-blocking semantics:
      - 2xx or 404 -> success (return).
      - connection error / unreachable -> log a warning and CONTINUE (return).
      - 5xx -> raise to ABORT the whole deletion.
    """
    url = f"{base_url.rstrip('/')}{_PURGE_PATH}"
    try:
        resp = httpx.request(
            "DELETE",
            url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=_PURGE_TIMEOUT_SECONDS,
        )
    except httpx.HTTPError as exc:
        # Connection error / timeout / unreachable: service likely not deployed
        # in this install. Best-effort -> log and continue.
        logger.warning(
            "Downstream purge to %s unreachable (%s): %s",
            service_name,
            url,
            exc,
        )
        return

    if resp.status_code < 300 or resp.status_code == status.HTTP_404_NOT_FOUND:
        return

    if resp.status_code >= 500:
        logger.error(
            "Downstream purge to %s returned %s; aborting account deletion",
            service_name,
            resp.status_code,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Could not complete account deletion. Please try again.",
        )

    # Any other 4xx (e.g. 401/403) is unexpected for a self-scoped purge with a
    # valid forwarded token. Treat as a hard failure rather than silently
    # leaving orphaned downstream data.
    logger.error(
        "Downstream purge to %s returned unexpected %s; aborting account deletion",
        service_name,
        resp.status_code,
    )
    raise HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail="Could not complete account deletion. Please try again.",
    )


def _purge_all_downstream(token: str) -> None:
    """Fan out the purge to command-center and notifications, in order."""
    cc_url = service_config.get_command_center_url()
    if cc_url:
        _purge_downstream(cc_url, token, service_config.COMMAND_CENTER_SERVICE)
    else:
        logger.info("jarvis-command-center not resolvable; skipping purge")

    notif_url = service_config.get_notifications_url()
    if notif_url:
        _purge_downstream(notif_url, token, service_config.NOTIFICATIONS_SERVICE)
    else:
        logger.info("jarvis-notifications not resolvable; skipping purge")


def delete_user_account(db: Session, user: models.User, token: str) -> None:
    """Run the guarded, ordered account-deletion flow for ``user``.

    Steps a..d (guards + downstream purge) run BEFORE any local deletion, so a
    guard or purge failure leaves the account fully intact. Steps e..h are
    wrapped so a failure rolls back.

    Raises HTTPException (409 guard / 502 downstream) instead of deleting on
    failure. The caller must have already verified the password (step a).
    """
    user_id = user.id

    # b. NODES GUARD
    if _has_active_node(db, user_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot delete account with nodes registered to it",
        )

    # c. HOUSEHOLD GUARD: block ONLY if the user is the sole admin of a household
    # that has other members (it would be orphaned). Solo households are auto-
    # deleted below; shared households with another admin are fine.
    if _blocking_shared_household(db, user_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Cannot delete your account while you are the only admin of a "
                "household with other members. Make another member an admin first."
            ),
        )

    # d. DOWNSTREAM PURGE (before any local deletion)
    _purge_all_downstream(token)

    # e..h. Local deletion, wrapped so a failure rolls back.
    try:
        # e. user-scoped settings
        db.query(models.Setting).filter(
            models.Setting.user_id == user_id
        ).delete(synchronize_session=False)

        # f. memberships, auto-deleting any household left with no members
        _remove_memberships_and_solo_households(db, user_id)

        # g. the user (refresh tokens cascade via FK). Re-fetch in THIS session:
        # the `user` from get_current_user may be attached to a different session
        # (its own get_db instance), and db.delete() requires an instance owned by
        # `db`. db.get() returns the already-loaded instance when sessions match.
        db_user = db.get(models.User, user_id)
        if db_user is not None:
            db.delete(db_user)

        # h. commit
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Local account deletion failed for user %s", user_id)
        raise
