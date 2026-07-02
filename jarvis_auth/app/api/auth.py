import logging
from datetime import datetime, timezone
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status
from sqlalchemy.orm import Session

from jarvis_auth.app.core import refresh_cache, security
from jarvis_auth.app.core.logging import get_logger
from jarvis_auth.app.core.settings import settings
from jarvis_auth.app.db import models
from jarvis_auth.app.db.models import HouseholdRole
from jarvis_auth.app.schemas import auth as auth_schema
from jarvis_auth.app.schemas import user as user_schema
# get_db MUST be deps.get_db, not a module-local duplicate: get_current_user
# resolves deps.get_db, and FastAPI caches dependencies by callable identity.
# A second callable means a second Session, so endpoints that mutate
# current_user would commit the wrong session and silently lose the writes.
from jarvis_auth.app.api.deps import get_current_user, get_db, oauth2_scheme
from jarvis_auth.app.api.invites import _get_valid_invite
from jarvis_auth.app.services import account_deletion, token_revocation
from jarvis_auth.app.services.auth_service import _get_user_household_id

router = APIRouter()
logger = logging.getLogger(__name__)


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
        family_id=str(uuid4()),
        parent_id=None,
        rotated_at=None,
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
    # Same message as bad credentials so account state isn't probeable.
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    if user.must_change_password and user.temp_password_expired:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Temporary password expired. Ask your administrator for a new one.",
        )

    access_token, refresh_token = _create_tokens(db, user)
    return auth_schema.TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=user_schema.UserOut.model_validate(user),
        must_change_password=user.must_change_password,
    )


@router.post("/auth/refresh", response_model=auth_schema.TokenResponse)
def refresh(payload: auth_schema.RefreshRequest, db: Annotated[Session, Depends(get_db)]):
    refresh_hash = security.hash_refresh_token(payload.refresh_token)
    # Do NOT pre-filter revoked — we need to inspect rotated_at/revoked to
    # distinguish reuse from a never-seen token.
    record = (
        db.query(models.RefreshToken)
        .filter(models.RefreshToken.token_hash == refresh_hash)
        .first()
    )
    if not record:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    if record.is_expired:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")

    # Lock the user row so rotation serializes with revoke-all (logout,
    # change-password, admin reset). Without it, a rotation straddling a
    # revocation can mint an unrevoked successor and resurrect the session.
    # No-op on SQLite (tests).
    user = (
        db.query(models.User)
        .filter(models.User.id == record.user_id)
        .with_for_update()
        .first()
    )
    # Generic detail: account state must not be probeable via refresh.
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    if user.must_change_password and user.temp_password_expired:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Temporary password expired. Ask your administrator for a new one.",
        )
    # Re-read the token row under the lock — a concurrent revocation may have
    # flipped `revoked` after our unlocked SELECT above.
    db.refresh(record)

    now = datetime.now(timezone.utc)

    if record.revoked or record.rotated_at is not None:
        # Grace window: the same parent token was just rotated within the
        # last `refresh_token_grace_seconds`. Return the successor we already
        # minted (cached in-process, keyed by the parent token row id). Never
        # serve it for a revoked row — revocation purges the cache, but the
        # strict on-reuse family nuke doesn't, and a racing refresh can
        # re-populate it after the purge.
        if not record.revoked and record.rotated_at is not None:
            rotated_at = record.rotated_at
            if rotated_at.tzinfo is None:
                rotated_at = rotated_at.replace(tzinfo=timezone.utc)
            if (now - rotated_at).total_seconds() <= settings.refresh_token_grace_seconds:
                cached_plain = refresh_cache.get(record.id)
                if cached_plain:
                    access_token = security.create_access_token(_build_jwt_claims(db, user))
                    return auth_schema.TokenResponse(
                        access_token=access_token,
                        refresh_token=cached_plain,
                        user=user_schema.UserOut.model_validate(user),
                        must_change_password=user.must_change_password,
                    )
                # Cache miss inside the grace window = process restart after
                # rotation (the in-process cache is volatile). We can't serve
                # the successor, but this is far more likely a benign replay
                # than theft — fall through to a plain 401 WITHOUT nuking the
                # family below.

        # Stale replay of an already-rotated (or revoked) token. Reject THIS
        # request, but by default do NOT revoke the family: the live tail of
        # the chain is the token the client is actually using, and a mobile
        # client over a flaky cloud link legitimately replays a just-rotated
        # token (two refresh paths, a lost response, or an auth restart that
        # wiped the grace cache) far more often than a token is truly stolen.
        # Revoking the family here is what turned a harmless replay into a full
        # sign-out of an active 14-day session. Opt back into strict
        # theft-detection with REFRESH_TOKEN_REVOKE_FAMILY_ON_REUSE=true.
        logger.warning(
            "refresh_token_reuse_detected",
            extra={
                "family_id": record.family_id,
                "user_id": record.user_id,
                "presented_token_id": record.id,
                "revoked_family": settings.refresh_token_revoke_family_on_reuse,
            },
        )
        if settings.refresh_token_revoke_family_on_reuse:
            db.query(models.RefreshToken).filter(
                models.RefreshToken.family_id == record.family_id
            ).update({"revoked": True})
            db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    # Happy path: rotate. Mint successor, chain to parent, mark parent rotated.
    new_plain, new_hash = security.generate_refresh_token_pair()
    new_record = models.RefreshToken(
        user_id=record.user_id,
        token_hash=new_hash,
        expires_at=security.refresh_token_expiry(),
        revoked=False,
        family_id=record.family_id,
        parent_id=record.id,
        rotated_at=None,
    )
    db.add(new_record)
    record.rotated_at = now
    db.commit()
    # Key is the parent (just-consumed) token row id, so a retry of the
    # parent within the grace window finds the cached successor.
    refresh_cache.set(record.id, new_plain, settings.refresh_token_grace_seconds)

    access_token = security.create_access_token(_build_jwt_claims(db, user))
    return auth_schema.TokenResponse(
        access_token=access_token,
        refresh_token=new_plain,
        user=user_schema.UserOut.model_validate(user),
        must_change_password=user.must_change_password,
    )


@router.post("/auth/change-password", response_model=auth_schema.TokenResponse)
def change_password(
    payload: auth_schema.ChangePasswordRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Change the caller's password (also clears an admin-issued temp password).

    Revokes every existing refresh token — a password change must invalidate
    all other sessions — and returns a fresh token pair for this one, which
    the client MUST adopt.
    """
    if not security.verify_password(payload.current_password, current_user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect password")
    if payload.new_password == payload.current_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from the current password",
        )

    current_user.password_hash = security.hash_password(payload.new_password)
    current_user.must_change_password = False
    current_user.temp_password_expires_at = None
    revoked = token_revocation.revoke_user_refresh_tokens(db, current_user.id)
    db.commit()

    # Audit events go through JarvisLogger so they reach jarvis-logs; the
    # stdlib module logger only feeds the console (and drops `extra` fields).
    get_logger().info("password_changed", user_id=current_user.id, revoked_tokens=revoked)

    access_token, refresh_token = _create_tokens(db, current_user)
    return auth_schema.TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=user_schema.UserOut.model_validate(current_user),
        must_change_password=False,
    )


@router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(payload: auth_schema.LogoutRequest, db: Annotated[Session, Depends(get_db)]) -> Response:
    """Revoke the presented refresh token's session (or all of the user's).

    Authenticates with the refresh token itself — no Bearer header — because
    logout must work when the access token has already expired. Always 204:
    an unknown/already-revoked token reveals nothing and the outcome (that
    token no longer works) is identical.
    """
    refresh_hash = security.hash_refresh_token(payload.refresh_token)
    record = (
        db.query(models.RefreshToken)
        .filter(models.RefreshToken.token_hash == refresh_hash)
        .first()
    )
    if record:
        if payload.all_devices:
            revoked = token_revocation.revoke_user_refresh_tokens(db, record.user_id)
        else:
            revoked = token_revocation.revoke_family(db, record.family_id, record.user_id)
        db.commit()
        get_logger().info(
            "user_logged_out",
            user_id=record.user_id,
            all_devices=payload.all_devices,
            revoked_tokens=revoked,
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/auth/me", response_model=user_schema.UserOut)
def me(current_user: models.User = Depends(get_current_user)):
    return user_schema.UserOut.model_validate(current_user)


@router.delete("/auth/me", status_code=status.HTTP_204_NO_CONTENT)
def delete_me(
    payload: auth_schema.AccountDeleteRequest,
    current_user: models.User = Depends(get_current_user),
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> Response:
    """Delete the current user's account and purge downstream user data.

    Guards (nodes / household-admin) and the downstream purge fan-out run BEFORE
    any local deletion, so a failure leaves the account fully intact. The user's
    raw Bearer token is forwarded to downstream services for self-scoped purge.
    """
    # a. verify password
    if not security.verify_password(payload.password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password",
        )

    # b..h. guards, downstream purge, then local deletion.
    account_deletion.delete_user_account(db, current_user, token)

    return Response(status_code=status.HTTP_204_NO_CONTENT)


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

