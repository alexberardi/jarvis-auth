"""Superuser views for cross-household admin tooling.

These endpoints return data spanning every household and node, which
the regular user-scoped routes (``/households``, ``/households/{id}/nodes``)
deliberately don't expose. Auth is JWT + ``is_superuser`` — the existing
``/admin/*`` endpoints use a shared ``X-Jarvis-Admin-Token`` instead, but the
admin UI authenticates as a real superuser user and shouldn't need that token.
"""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from jarvis_auth.app.api.deps import get_db, require_superuser
from jarvis_auth.app.core import security
from jarvis_auth.app.core.logging import get_logger
from jarvis_auth.app.core.settings import settings
from jarvis_auth.app.db import models
from jarvis_auth.app.schemas import node as node_schema
from jarvis_auth.app.services import token_revocation

router = APIRouter(dependencies=[Depends(require_superuser)])


class SuperuserHouseholdListItem(BaseModel):
    id: str
    name: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


@router.get("/superuser/households", response_model=list[SuperuserHouseholdListItem])
def list_all_households(db: Session = Depends(get_db)):
    """List every household in the system (superuser only)."""
    return db.query(models.Household).order_by(models.Household.name.asc()).all()


class UserHouseholdInfo(BaseModel):
    household_id: str
    household_name: str
    role: models.HouseholdRole


class SuperuserUserListItem(BaseModel):
    id: int
    email: str
    username: str
    is_active: bool
    is_superuser: bool
    must_change_password: bool
    created_at: datetime
    updated_at: datetime | None = None
    households: list[UserHouseholdInfo] = []

    model_config = {"from_attributes": True}


@router.get("/superuser/users", response_model=list[SuperuserUserListItem])
def list_all_users(db: Session = Depends(get_db)):
    """List every user in the system with their household memberships (superuser only)."""
    users = db.query(models.User).order_by(models.User.email.asc()).all()
    memberships = (
        db.query(models.HouseholdMembership)
        .join(models.Household, models.HouseholdMembership.household_id == models.Household.id)
        .all()
    )
    by_user: dict[int, list[UserHouseholdInfo]] = {}
    for m in memberships:
        by_user.setdefault(m.user_id, []).append(
            UserHouseholdInfo(
                household_id=m.household_id,
                household_name=m.household.name,
                role=m.role,
            )
        )
    items = []
    for user in users:
        item = SuperuserUserListItem.model_validate(user)
        item.households = by_user.get(user.id, [])
        items.append(item)
    return items


class TempPasswordRequest(BaseModel):
    # Omitted → server generates a readable one-time password (preferred).
    temp_password: str | None = Field(default=None, min_length=8, max_length=255)
    expires_in_hours: int | None = Field(default=None, ge=1, le=168)


class TempPasswordResponse(BaseModel):
    temp_password: str
    expires_at: datetime
    must_change_password: bool = True


@router.post("/superuser/users/{user_id}/temp-password", response_model=TempPasswordResponse)
def set_temp_password(
    user_id: int,
    payload: TempPasswordRequest | None = None,
    db: Session = Depends(get_db),
    acting_superuser: models.User = Depends(require_superuser),
):
    """Issue a temporary password for a user (superuser only).

    The plaintext is returned ONCE in this response and never stored or
    logged. All of the user's existing sessions are revoked; their next
    login (with the temp password) forces a change via /auth/change-password.
    """
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    # Login rejects inactive users, so the temp password could never be used —
    # fail loudly instead of handing the admin a show-once credential that
    # silently doesn't work. (Superuser-gated, so the detail leaks nothing.)
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User is deactivated; reactivate the account before issuing a temporary password",
        )

    payload = payload or TempPasswordRequest()
    temp_password = payload.temp_password or security.generate_temp_password()
    expires_hours = payload.expires_in_hours or settings.temp_password_expire_hours
    expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_hours)

    user.password_hash = security.hash_password(temp_password)
    user.must_change_password = True
    user.temp_password_expires_at = expires_at
    revoked = token_revocation.revoke_user_refresh_tokens(db, user.id)
    db.commit()

    # Audit via JarvisLogger so the event reaches jarvis-logs (a stdlib module
    # logger drops the fields and, at default levels, the whole record).
    # Never log the plaintext.
    get_logger().info(
        "temp_password_issued",
        target_user_id=user.id,
        acting_user_id=acting_superuser.id,
        expires_at=expires_at.isoformat(),
        revoked_tokens=revoked,
    )
    return TempPasswordResponse(temp_password=temp_password, expires_at=expires_at)


@router.get("/superuser/nodes", response_model=list[node_schema.NodeListItem])
def list_all_nodes(db: Session = Depends(get_db)):
    """List every registered node across all households (superuser only)."""
    nodes = (
        db.query(models.NodeRegistration)
        .order_by(models.NodeRegistration.name.asc())
        .all()
    )
    return [
        node_schema.NodeListItem(
            node_id=node.node_id,
            name=node.name,
            household_id=node.household_id,
            registered_by_user_id=node.registered_by_user_id,
            is_active=node.is_active,
            created_at=node.created_at,
            updated_at=node.updated_at,
            last_rotated_at=node.last_rotated_at,
            services=[access.service_id for access in node.service_access],
        )
        for node in nodes
    ]
