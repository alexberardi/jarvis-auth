import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from jarvis_auth.app.api.deps import get_current_user, get_db
from jarvis_auth.app.api.households import _get_membership, _require_membership
from jarvis_auth.app.db import models
from jarvis_auth.app.db.models import HouseholdRole
from jarvis_auth.app.schemas import invite as invite_schema

router = APIRouter()

# No ambiguous chars: 0/O/1/I/L removed
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def _generate_invite_code() -> str:
    return "".join(secrets.choice(_CODE_ALPHABET) for _ in range(8))


def _get_valid_invite(db: Session, code: str) -> models.HouseholdInvite | None:
    """Get an invite that is valid (not revoked, not expired, not max-used)."""
    invite = db.query(models.HouseholdInvite).filter(
        models.HouseholdInvite.code == code,
    ).first()
    if not invite:
        return None
    if invite.revoked:
        return None
    now = datetime.now(timezone.utc)
    expires = invite.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if now >= expires:
        return None
    if invite.max_uses is not None and invite.use_count >= invite.max_uses:
        return None
    return invite


# ─── Household-scoped endpoints ──────────────────────────────────────────


@router.post(
    "/households/{household_id}/invites",
    response_model=invite_schema.InviteResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_invite(
    household_id: str,
    payload: invite_schema.InviteCreateRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create an invite code. Requires power_user or admin."""
    _require_membership(db, household_id, current_user.id, HouseholdRole.POWER_USER)

    if payload.default_role == HouseholdRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invite codes cannot assign admin role",
        )

    code = _generate_invite_code()
    # Ensure uniqueness (extremely unlikely collision)
    while db.query(models.HouseholdInvite).filter(models.HouseholdInvite.code == code).first():
        code = _generate_invite_code()

    now = datetime.now(timezone.utc)
    invite = models.HouseholdInvite(
        household_id=household_id,
        code=code,
        created_by_user_id=current_user.id,
        default_role=payload.default_role,
        max_uses=payload.max_uses,
        expires_at=now + timedelta(days=payload.expires_in_days),
        created_at=now,
    )
    db.add(invite)
    db.commit()
    db.refresh(invite)
    return invite


@router.get(
    "/households/{household_id}/invites",
    response_model=list[invite_schema.InviteResponse],
)
def list_invites(
    household_id: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List active (non-revoked) invites for a household. Requires membership."""
    _require_membership(db, household_id, current_user.id)

    invites = db.query(models.HouseholdInvite).filter(
        models.HouseholdInvite.household_id == household_id,
        models.HouseholdInvite.revoked == False,
    ).order_by(models.HouseholdInvite.created_at.desc()).all()
    return invites


@router.delete(
    "/households/{household_id}/invites/{invite_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def revoke_invite(
    household_id: str,
    invite_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revoke an invite. Requires power_user or admin."""
    _require_membership(db, household_id, current_user.id, HouseholdRole.POWER_USER)

    invite = db.query(models.HouseholdInvite).filter(
        models.HouseholdInvite.id == invite_id,
        models.HouseholdInvite.household_id == household_id,
    ).first()
    if not invite:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invite not found")

    invite.revoked = True
    db.commit()
    return None


# ─── Public validation endpoint ──────────────────────────────────────────


@router.get(
    "/invites/{code}/validate",
    response_model=invite_schema.InviteValidateResponse,
)
def validate_invite(code: str, db: Session = Depends(get_db)):
    """Validate an invite code. Public endpoint — returns generic invalid for any failure."""
    invite = _get_valid_invite(db, code.upper())
    if not invite:
        return invite_schema.InviteValidateResponse(valid=False)

    household = db.query(models.Household).filter(
        models.Household.id == invite.household_id,
    ).first()
    return invite_schema.InviteValidateResponse(
        valid=True,
        household_name=household.name if household else None,
    )


# ─── Join household via invite ───────────────────────────────────────────


@router.post(
    "/households/join",
    response_model=invite_schema.JoinHouseholdResponse,
)
def join_household(
    payload: invite_schema.JoinHouseholdRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Join a household using an invite code. Requires authentication."""
    invite = _get_valid_invite(db, payload.invite_code.upper())
    if not invite:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired invite code",
        )

    # Check if already a member
    existing = _get_membership(db, invite.household_id, current_user.id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Already a member of this household",
        )

    household = db.query(models.Household).filter(
        models.Household.id == invite.household_id,
    ).first()
    if not household:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired invite code",
        )

    now = datetime.now(timezone.utc)
    membership = models.HouseholdMembership(
        household_id=invite.household_id,
        user_id=current_user.id,
        role=invite.default_role,
        created_at=now,
    )
    db.add(membership)
    invite.use_count += 1
    db.commit()

    return invite_schema.JoinHouseholdResponse(
        household_id=invite.household_id,
        household_name=household.name,
        role=invite.default_role,
    )
