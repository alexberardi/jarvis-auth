"""Admin endpoints for user management.

These endpoints require the master admin token (`X-Jarvis-Admin-Token`) and are
used by trusted infrastructure for administrative operations like managing
superuser status. They are NOT app-to-app callable: granting superuser is a
fleet-wide privilege-escalation primitive, so it must not be reachable with the
app credentials every service holds.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from jarvis_auth.app.api.dependencies.admin_auth import require_admin_token
from jarvis_auth.app.api.deps import get_db
from jarvis_auth.app.db import models


router = APIRouter(dependencies=[Depends(require_admin_token)])


class SuperuserUpdateRequest(BaseModel):
    """Request body for updating superuser status."""

    is_superuser: bool


class SuperuserUpdateResponse(BaseModel):
    """Response for superuser status update."""

    success: bool
    user_id: int
    email: str
    is_superuser: bool
    message: str


class UserAdminResponse(BaseModel):
    """Admin view of a user."""

    id: int
    email: str
    username: str
    is_active: bool
    is_superuser: bool


@router.put(
    "/admin/users/{user_id}/superuser",
    response_model=SuperuserUpdateResponse,
)
def update_superuser_status(
    user_id: int,
    payload: SuperuserUpdateRequest,
    db: Annotated[Session, Depends(get_db)],
) -> SuperuserUpdateResponse:
    """Update a user's superuser status.

    Requires the master admin token. This is an administrative endpoint
    for managing which users have superuser access.
    """
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found",
        )

    previous_status = user.is_superuser
    user.is_superuser = payload.is_superuser
    db.commit()
    db.refresh(user)

    action = "granted" if payload.is_superuser else "revoked"
    message = f"Superuser access {action} for user {user.email}"
    if previous_status == payload.is_superuser:
        message = f"User {user.email} already has is_superuser={payload.is_superuser}"

    return SuperuserUpdateResponse(
        success=True,
        user_id=user.id,
        email=user.email,
        is_superuser=user.is_superuser,
        message=message,
    )


@router.get(
    "/admin/users/{user_id}",
    response_model=UserAdminResponse,
)
def get_user_admin(
    user_id: int,
    db: Annotated[Session, Depends(get_db)],
) -> UserAdminResponse:
    """Get admin view of a user.

    Requires the master admin token.
    """
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found",
        )

    return UserAdminResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        is_active=user.is_active,
        is_superuser=user.is_superuser,
    )


@router.get(
    "/admin/users/by-email/{email}",
    response_model=UserAdminResponse,
)
def get_user_by_email_admin(
    email: str,
    db: Annotated[Session, Depends(get_db)],
) -> UserAdminResponse:
    """Get admin view of a user by email.

    Requires the master admin token.
    """
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with email {email} not found",
        )

    return UserAdminResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        is_active=user.is_active,
        is_superuser=user.is_superuser,
    )
