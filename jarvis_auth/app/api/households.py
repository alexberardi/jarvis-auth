from datetime import datetime, timezone
import secrets

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from jarvis_auth.app.api.deps import get_current_user, get_db
from jarvis_auth.app.core.security import hash_password
from jarvis_auth.app.db import models
from jarvis_auth.app.db.models import HouseholdRole
from jarvis_auth.app.schemas import household as household_schema
from jarvis_auth.app.schemas import node as node_schema

router = APIRouter()


def _get_membership(
    db: Session,
    household_id: str,
    user_id: int,
) -> models.HouseholdMembership | None:
    """Get a user's membership in a household."""
    return db.query(models.HouseholdMembership).filter(
        models.HouseholdMembership.household_id == household_id,
        models.HouseholdMembership.user_id == user_id,
    ).first()


def _require_membership(
    db: Session,
    household_id: str,
    user_id: int,
    required_role: HouseholdRole | None = None,
) -> models.HouseholdMembership:
    """Require user to be a member of the household with optional role check."""
    membership = _get_membership(db, household_id, user_id)
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not a member of this household",
        )
    if required_role and not HouseholdRole.has_permission(membership.role, required_role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires {required_role.value} role or higher",
        )
    return membership


# ============================================================
# Household CRUD Endpoints
# ============================================================


@router.post(
    "/households",
    response_model=household_schema.HouseholdCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_household(
    payload: household_schema.HouseholdCreateRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a new household. The creator becomes admin."""
    now = datetime.now(timezone.utc)

    household = models.Household(
        name=payload.name,
        created_at=now,
    )
    db.add(household)
    db.flush()

    # Creator becomes admin
    membership = models.HouseholdMembership(
        household_id=household.id,
        user_id=current_user.id,
        role=HouseholdRole.ADMIN,
        created_at=now,
    )
    db.add(membership)
    db.commit()
    db.refresh(household)

    return household_schema.HouseholdCreateResponse(
        id=household.id,
        name=household.name,
        created_at=household.created_at,
    )


@router.get("/households", response_model=list[household_schema.HouseholdListItem])
def list_households(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List households the current user is a member of."""
    memberships = db.query(models.HouseholdMembership).filter(
        models.HouseholdMembership.user_id == current_user.id,
    ).all()

    result = []
    for membership in memberships:
        household = db.query(models.Household).filter(
            models.Household.id == membership.household_id
        ).first()
        if household:
            result.append(household_schema.HouseholdListItem(
                id=household.id,
                name=household.name,
                role=membership.role,
                created_at=household.created_at,
            ))
    return result


@router.get("/households/{household_id}", response_model=household_schema.HouseholdResponse)
def get_household(
    household_id: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get household details. Requires membership."""
    _require_membership(db, household_id, current_user.id)

    household = db.query(models.Household).filter(
        models.Household.id == household_id
    ).first()
    if not household:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Household not found",
        )

    return household_schema.HouseholdResponse(
        id=household.id,
        name=household.name,
        created_at=household.created_at,
        updated_at=household.updated_at,
    )


@router.patch("/households/{household_id}", response_model=household_schema.HouseholdResponse)
def update_household(
    household_id: str,
    payload: household_schema.HouseholdUpdateRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update household. Requires admin role."""
    _require_membership(db, household_id, current_user.id, HouseholdRole.ADMIN)

    household = db.query(models.Household).filter(
        models.Household.id == household_id
    ).first()
    if not household:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Household not found",
        )

    household.name = payload.name
    db.commit()
    db.refresh(household)

    return household_schema.HouseholdResponse(
        id=household.id,
        name=household.name,
        created_at=household.created_at,
        updated_at=household.updated_at,
    )


@router.delete("/households/{household_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_household(
    household_id: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete household. Requires admin role."""
    _require_membership(db, household_id, current_user.id, HouseholdRole.ADMIN)

    household = db.query(models.Household).filter(
        models.Household.id == household_id
    ).first()
    if not household:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Household not found",
        )

    db.delete(household)
    db.commit()
    return None


# ============================================================
# Member Management Endpoints
# ============================================================


@router.get(
    "/households/{household_id}/members",
    response_model=list[household_schema.MemberListItem],
)
def list_members(
    household_id: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List household members. Requires membership."""
    _require_membership(db, household_id, current_user.id)

    memberships = db.query(models.HouseholdMembership).filter(
        models.HouseholdMembership.household_id == household_id,
    ).all()

    result = []
    for membership in memberships:
        user = db.query(models.User).filter(
            models.User.id == membership.user_id
        ).first()
        if user:
            result.append(household_schema.MemberListItem(
                user_id=user.id,
                username=user.username,
                email=user.email,
                role=membership.role,
                created_at=membership.created_at,
            ))
    return result


@router.post(
    "/households/{household_id}/members",
    response_model=household_schema.MemberResponse,
    status_code=status.HTTP_201_CREATED,
)
def add_member(
    household_id: str,
    payload: household_schema.MemberAddRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Add a member to the household. Requires admin role."""
    _require_membership(db, household_id, current_user.id, HouseholdRole.ADMIN)

    # Verify household exists
    household = db.query(models.Household).filter(
        models.Household.id == household_id
    ).first()
    if not household:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Household not found",
        )

    # Verify user exists
    user = db.query(models.User).filter(models.User.id == payload.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Check if already a member
    existing = _get_membership(db, household_id, payload.user_id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is already a member of this household",
        )

    now = datetime.now(timezone.utc)
    membership = models.HouseholdMembership(
        household_id=household_id,
        user_id=payload.user_id,
        role=payload.role,
        created_at=now,
    )
    db.add(membership)
    db.commit()
    db.refresh(membership)

    return household_schema.MemberResponse(
        user_id=user.id,
        username=user.username,
        email=user.email,
        role=membership.role,
        created_at=membership.created_at,
    )


@router.patch(
    "/households/{household_id}/members/{user_id}",
    response_model=household_schema.MemberResponse,
)
def update_member(
    household_id: str,
    user_id: int,
    payload: household_schema.MemberUpdateRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update a member's role. Requires admin role."""
    _require_membership(db, household_id, current_user.id, HouseholdRole.ADMIN)

    # Prevent self-demotion (admin cannot demote themselves)
    if user_id == current_user.id and payload.role != HouseholdRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot demote yourself",
        )

    membership = _get_membership(db, household_id, user_id)
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Member not found",
        )

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    membership.role = payload.role
    db.commit()
    db.refresh(membership)

    return household_schema.MemberResponse(
        user_id=user.id,
        username=user.username,
        email=user.email,
        role=membership.role,
        created_at=membership.created_at,
    )


@router.delete(
    "/households/{household_id}/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def remove_member(
    household_id: str,
    user_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Remove a member from the household. Requires admin role."""
    _require_membership(db, household_id, current_user.id, HouseholdRole.ADMIN)

    # Prevent self-removal
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove yourself from the household",
        )

    membership = _get_membership(db, household_id, user_id)
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Member not found",
        )

    db.delete(membership)
    db.commit()
    return None


# ============================================================
# Household-Scoped Node Endpoints
# ============================================================


def _generate_node_key_and_hash() -> tuple[str, str]:
    raw_key = secrets.token_urlsafe(48)
    key_hash = hash_password(raw_key)
    return raw_key, key_hash


def _get_node_services(node: models.NodeRegistration) -> list[str]:
    return [access.service_id for access in node.service_access]


@router.get(
    "/households/{household_id}/nodes",
    response_model=list[node_schema.NodeListItem],
)
def list_household_nodes(
    household_id: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List nodes in a household. Requires membership."""
    _require_membership(db, household_id, current_user.id)

    nodes = db.query(models.NodeRegistration).filter(
        models.NodeRegistration.household_id == household_id,
    ).all()

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
            services=_get_node_services(node),
        )
        for node in nodes
    ]


@router.post(
    "/households/{household_id}/nodes",
    response_model=node_schema.NodeCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
def register_household_node(
    household_id: str,
    payload: node_schema.NodeCreateRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Register a node to a household. Requires power_user or admin role."""
    _require_membership(db, household_id, current_user.id, HouseholdRole.POWER_USER)

    # Verify household matches
    if payload.household_id != household_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Household ID in payload must match URL",
        )

    # Check if node_id already exists
    existing = db.query(models.NodeRegistration).filter(
        models.NodeRegistration.node_id == payload.node_id
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="node_id already exists",
        )

    raw_key, key_hash = _generate_node_key_and_hash()
    now = datetime.now(timezone.utc)

    node = models.NodeRegistration(
        node_id=payload.node_id,
        household_id=household_id,
        registered_by_user_id=current_user.id,
        node_key_hash=key_hash,
        name=payload.name,
        is_active=True,
        created_at=now,
    )
    db.add(node)
    db.flush()

    # Grant service access if specified
    services = payload.services or []
    for service_id in services:
        access = models.NodeServiceAccess(
            node_id=payload.node_id,
            service_id=service_id,
            granted_at=now,
            granted_by=current_user.id,
        )
        db.add(access)

    db.commit()
    db.refresh(node)

    return node_schema.NodeCreateResponse(
        node_id=node.node_id,
        name=node.name,
        household_id=node.household_id,
        registered_by_user_id=node.registered_by_user_id,
        node_key=raw_key,
        created_at=node.created_at,
        services=services,
    )
