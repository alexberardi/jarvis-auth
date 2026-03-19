from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from jarvis_auth.app.core import security
from jarvis_auth.app.db.session import SessionLocal
from jarvis_auth.app.db import models
from jarvis_auth.app.db.models import HouseholdRole
from jarvis_auth.app.schemas import auth as auth_schema
from jarvis_auth.app.schemas import user as user_schema
from jarvis_auth.app.api.deps import get_current_user
from jarvis_auth.app.api.invites import _get_valid_invite
from jarvis_auth.app.services.auth_service import _get_user_household_id

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _ensure_username(email: str, username: str | None) -> str:
    if username:
        return username
    return email.split("@")[0]


def _build_jwt_claims(db: Session, user: models.User) -> dict:
    """Build JWT claims dict including household_id if available."""
    claims = {
        "sub": str(user.id),
        "email": user.email,
        "is_superuser": user.is_superuser,
    }
    household_id = _get_user_household_id(db, user.id)
    if household_id:
        claims["household_id"] = household_id
    return claims


def _create_tokens(db: Session, user: models.User) -> tuple[str, str]:
    access_token = security.create_access_token(_build_jwt_claims(db, user))
    refresh_token_plain, refresh_hash = security.generate_refresh_token_pair()
    expires_at = security.refresh_token_expiry()

    record = models.RefreshToken(
        user_id=user.id,
        token_hash=refresh_hash,
        expires_at=expires_at,
        revoked=False,
    )
    db.add(record)
    db.commit()
    return access_token, refresh_token_plain


def _assign_household(
    db: Session,
    user: models.User,
    household_id: str | None,
    role_override: HouseholdRole | None = None,
) -> str:
    """Assign user to a household, creating one if needed.

    If household_id is provided, joins that household (as role_override or MEMBER).
    If not provided, creates a new "My Home" household and makes user admin.

    Returns the household_id.
    """
    now = datetime.now(timezone.utc)

    if household_id:
        household = db.query(models.Household).filter(
            models.Household.id == household_id
        ).first()
        if not household:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Household not found",
            )
        role = role_override or HouseholdRole.MEMBER
    else:
        household = models.Household(name="My Home", created_at=now)
        db.add(household)
        db.flush()
        household_id = household.id
        role = HouseholdRole.ADMIN

    membership = models.HouseholdMembership(
        household_id=household_id,
        user_id=user.id,
        role=role,
        created_at=now,
    )
    db.add(membership)
    return household_id


@router.post("/auth/register", response_model=auth_schema.RegisterResponse, status_code=status.HTTP_201_CREATED)
def register(
    payload: auth_schema.RegisterRequest,
    db: Annotated[Session, Depends(get_db)],
    x_household_id: str | None = Header(None, alias="X-Household-Id"),
):
    """Register a new user and return tokens (auto-login).

    Priority: invite_code > X-Household-Id header > create new household.
    """
    existing = db.query(models.User).filter(models.User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    # Resolve invite code to household_id + role
    invite: models.HouseholdInvite | None = None
    invite_role: HouseholdRole | None = None
    if payload.invite_code:
        invite = _get_valid_invite(db, payload.invite_code.upper())
        if not invite:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired invite code",
            )
        x_household_id = invite.household_id
        invite_role = invite.default_role

    hashed_pw = security.hash_password(payload.password)
    username = _ensure_username(payload.email, payload.username)
    user = models.User(email=payload.email, username=username, password_hash=hashed_pw, is_active=True)
    db.add(user)
    db.flush()

    household_id = _assign_household(db, user, x_household_id, invite_role)

    # Increment invite use count atomically
    if invite:
        invite.use_count += 1

    db.commit()
    db.refresh(user)

    access_token, refresh_token = _create_tokens(db, user)
    return auth_schema.RegisterResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=user_schema.UserOut.model_validate(user),
        household_id=household_id,
    )


@router.post("/auth/login", response_model=auth_schema.TokenResponse)
def login(payload: auth_schema.LoginRequest, db: Annotated[Session, Depends(get_db)]):
    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if not user or not security.verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    access_token, refresh_token = _create_tokens(db, user)
    return auth_schema.TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=user_schema.UserOut.model_validate(user),
    )


@router.post("/auth/refresh", response_model=auth_schema.TokenResponse)
def refresh(payload: auth_schema.RefreshRequest, db: Annotated[Session, Depends(get_db)]):
    refresh_hash = security.hash_refresh_token(payload.refresh_token)
    record = (
        db.query(models.RefreshToken)
        .filter(models.RefreshToken.token_hash == refresh_hash, models.RefreshToken.revoked == False)
        .first()
    )
    if not record:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    if record.is_expired:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")

    user = db.query(models.User).filter(models.User.id == record.user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    access_token = security.create_access_token(_build_jwt_claims(db, user))
    # For simplicity, reuse refresh token (rotation optional)
    return auth_schema.TokenResponse(
        access_token=access_token,
        refresh_token=payload.refresh_token,
        user=user_schema.UserOut.model_validate(user),
    )


@router.get("/auth/me", response_model=user_schema.UserOut)
def me(current_user: models.User = Depends(get_current_user)):
    return user_schema.UserOut.model_validate(current_user)


@router.get("/auth/setup-status")
def setup_status(db: Annotated[Session, Depends(get_db)]):
    """Check if initial setup is needed (no superusers exist)."""
    has_superuser = db.query(models.User).filter(
        models.User.is_superuser == True
    ).first() is not None
    return {"needs_setup": not has_superuser}


@router.post("/auth/setup", response_model=auth_schema.RegisterResponse, status_code=status.HTTP_201_CREATED)
def initial_setup(payload: auth_schema.RegisterRequest, db: Annotated[Session, Depends(get_db)]):
    """Create the first superuser. Only works when no superusers exist."""
    has_superuser = db.query(models.User).filter(
        models.User.is_superuser == True
    ).first() is not None
    if has_superuser:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Setup already completed")

    existing = db.query(models.User).filter(models.User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    hashed_pw = security.hash_password(payload.password)
    username = _ensure_username(payload.email, payload.username)
    user = models.User(
        email=payload.email, username=username, password_hash=hashed_pw,
        is_active=True, is_superuser=True,
    )
    db.add(user)
    db.flush()

    household_id = _assign_household(db, user, None)
    db.commit()
    db.refresh(user)

    access_token, refresh_token = _create_tokens(db, user)
    return auth_schema.RegisterResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=user_schema.UserOut.model_validate(user),
        household_id=household_id,
    )


class SwitchHouseholdRequest(auth_schema.BaseModel):
    household_id: str


class SwitchHouseholdResponse(auth_schema.BaseModel):
    access_token: str
    household_id: str


@router.post("/auth/switch-household", response_model=SwitchHouseholdResponse)
def switch_household(
    payload: SwitchHouseholdRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Switch active household. Re-issues JWT with the requested household_id."""
    membership = db.query(models.HouseholdMembership).filter(
        models.HouseholdMembership.household_id == payload.household_id,
        models.HouseholdMembership.user_id == current_user.id,
    ).first()
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not a member of this household",
        )

    claims = {
        "sub": str(current_user.id),
        "email": current_user.email,
        "is_superuser": current_user.is_superuser,
        "household_id": payload.household_id,
    }
    access_token = security.create_access_token(claims)
    return SwitchHouseholdResponse(
        access_token=access_token,
        household_id=payload.household_id,
    )

