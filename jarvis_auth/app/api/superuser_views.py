"""Read-only superuser views for cross-household admin tooling.

These endpoints return data spanning every household and node, which
the regular user-scoped routes (``/households``, ``/households/{id}/nodes``)
deliberately don't expose. Auth is JWT + ``is_superuser`` — the existing
``/admin/*`` endpoints use a shared ``X-Jarvis-Admin-Token`` instead, but the
admin UI authenticates as a real superuser user and shouldn't need that token.
"""

from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from jarvis_auth.app.api.deps import get_db, require_superuser
from jarvis_auth.app.db import models
from jarvis_auth.app.schemas import node as node_schema

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
