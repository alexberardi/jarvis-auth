from datetime import datetime, timezone
from typing import Optional

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from jarvis_auth.app.core import security
from jarvis_auth.app.db import models
from jarvis_auth.app.db.models import HouseholdRole
from jarvis_auth.app.schemas import auth as auth_schema
from jarvis_auth.app.services import user_service


def _get_user_household_id(db: Session, user_id: int) -> str | None:
    """Look up the user's primary (first) household membership."""
    membership = (
        db.query(models.HouseholdMembership)
        .filter(models.HouseholdMembership.user_id == user_id)
        .first()
    )
    return str(membership.household_id) if membership else None


def register_user(
    db: Session,
    payload: auth_schema.RegisterRequest,
    household_id: str | None = None,
) -> tuple[models.User, str]:
    """
    Register a new user and assign to a household.

    If household_id is provided, joins that household as a member.
    If not provided, creates a new household and makes user admin.

    Returns tuple of (user, household_id).
    """
    if user_service.get_user_by_email(db, payload.email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    if payload.username and user_service.get_user_by_username(db, payload.username):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")

    now = datetime.now(timezone.utc)
    hashed_password = security.hash_password(payload.password)
    user = models.User(
        email=payload.email,
        username=payload.username,
        password_hash=hashed_password,
        is_active=True,
    )
    db.add(user)
    db.flush()  # Get user.id before creating membership

    if household_id:
        # Join existing household (invitation flow)
        household = db.query(models.Household).filter(
            models.Household.id == household_id
        ).first()
        if not household:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Household not found",
            )
        role = HouseholdRole.MEMBER
    else:
        # Create new household for user
        household = models.Household(
            name="My Home",
            created_at=now,
        )
        db.add(household)
        db.flush()
        household_id = household.id
        role = HouseholdRole.ADMIN

    # Create membership
    membership = models.HouseholdMembership(
        household_id=household_id,
        user_id=user.id,
        role=role,
        created_at=now,
    )
    db.add(membership)
    db.commit()
    db.refresh(user)

    return user, household_id


def authenticate_user(db: Session, email: str, password: str) -> Optional[models.User]:
    user = user_service.get_user_by_email(db, email)
    if not user or not security.verify_password(password, user.password_hash):
        return None
    return user

