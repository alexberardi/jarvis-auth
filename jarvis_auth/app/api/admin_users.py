"""Admin endpoints for user management.

These endpoints require app-to-app authentication and are used for
administrative operations like managing superuser status.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from jarvis_auth.app.api.dependencies.app_auth import require_app_client
from jarvis_auth.app.api.deps import get_db
from jarvis_auth.app.db import models


router = APIRouter()


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
    _app_client: Annotated[models.AppClient, Depends(require_app_client)],
) -> SuperuserUpdateResponse:
    """Update a user's superuser status.

    Requires app-to-app authentication. This is an administrative endpoint
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
    _app_client: Annotated[models.AppClient, Depends(require_app_client)],
) -> UserAdminResponse:
    """Get admin view of a user.

    Requires app-to-app authentication.
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
    _app_client: Annotated[models.AppClient, Depends(require_app_client)],
) -> UserAdminResponse:
    """Get admin view of a user by email.

    Requires app-to-app authentication.
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
