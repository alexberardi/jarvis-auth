from datetime import datetime, timezone
import secrets

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from jarvis_auth.app.api.dependencies.app_auth import require_app_client
from jarvis_auth.app.core.security import hash_password, verify_password
from jarvis_auth.app.db import models
from jarvis_auth.app.db.session import SessionLocal
from jarvis_auth.app.schemas import node as node_schema

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _generate_node_key_and_hash() -> tuple[str, str]:
    raw_key = secrets.token_urlsafe(48)
    key_hash = hash_password(raw_key)
    return raw_key, key_hash


@router.get("/internal/app-ping")
def app_ping(app_client: models.AppClient = Depends(require_app_client)):
    return {"app_id": app_client.app_id, "name": app_client.name}


@router.post("/internal/validate-node", response_model=node_schema.NodeValidateResponse)
def validate_node(
    payload: node_schema.NodeValidateRequest,
    app_client: models.AppClient = Depends(require_app_client),
    db: Session = Depends(get_db),
):
    """Validate node credentials for a specific service.

    Called by services to verify that a node has valid credentials
    and is authorized to access the requesting service.
    """
    # Find node
    node = db.query(models.NodeRegistration).filter(
        models.NodeRegistration.node_id == payload.node_id
    ).first()

    if not node:
        return node_schema.NodeValidateResponse(
            valid=False,
            reason="Node not found",
        )

    if not node.is_active:
        return node_schema.NodeValidateResponse(
            valid=False,
            reason="Node is inactive",
        )

    # Verify node key
    if not verify_password(payload.node_key, node.node_key_hash):
        return node_schema.NodeValidateResponse(
            valid=False,
            reason="Invalid node credentials",
        )

    # Check service access
    access = db.query(models.NodeServiceAccess).filter(
        models.NodeServiceAccess.node_id == payload.node_id,
        models.NodeServiceAccess.service_id == payload.service_id,
    ).first()

    if not access:
        return node_schema.NodeValidateResponse(
            valid=False,
            reason=f"Node is not authorized to access service '{payload.service_id}'",
        )

    return node_schema.NodeValidateResponse(
        valid=True,
        node_id=node.node_id,
        user_id=node.user_id,
    )


@router.post(
    "/internal/nodes/register",
    response_model=node_schema.NodeRegisterInternalResponse,
    status_code=status.HTTP_201_CREATED,
)
def register_node(
    payload: node_schema.NodeRegisterInternalRequest,
    app_client: models.AppClient = Depends(require_app_client),
    db: Session = Depends(get_db),
):
    """Register a new node on behalf of a user.

    The calling service (identified by app_client) automatically gets access
    to the new node. Additional services can be specified in the services list.
    """
    # Check if node_id already exists
    existing = db.query(models.NodeRegistration).filter(
        models.NodeRegistration.node_id == payload.node_id
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="node_id already exists",
        )

    # Verify user exists
    user = db.query(models.User).filter(models.User.id == payload.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    raw_key, key_hash = _generate_node_key_and_hash()
    now = datetime.now(timezone.utc)

    node = models.NodeRegistration(
        node_id=payload.node_id,
        user_id=payload.user_id,
        node_key_hash=key_hash,
        name=payload.name,
        is_active=True,
        created_at=now,
    )
    db.add(node)
    db.flush()

    # Always grant access to the calling service
    services_to_grant = set(payload.services or [])
    services_to_grant.add(app_client.app_id)

    for service_id in services_to_grant:
        access = models.NodeServiceAccess(
            node_id=payload.node_id,
            service_id=service_id,
            granted_at=now,
            granted_by=None,
        )
        db.add(access)

    db.commit()

    return node_schema.NodeRegisterInternalResponse(
        node_id=node.node_id,
        node_key=raw_key,
    )


@router.post(
    "/internal/nodes/{node_id}/services",
    response_model=node_schema.ServiceAccessResponse,
    status_code=status.HTTP_201_CREATED,
)
def grant_service_access_internal(
    node_id: str,
    payload: node_schema.ServiceAccessRequest,
    app_client: models.AppClient = Depends(require_app_client),
    db: Session = Depends(get_db),
):
    """Grant a node access to an additional service."""
    node = db.query(models.NodeRegistration).filter(
        models.NodeRegistration.node_id == node_id
    ).first()
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Node not found",
        )

    # Check if access already exists
    existing = db.query(models.NodeServiceAccess).filter(
        models.NodeServiceAccess.node_id == node_id,
        models.NodeServiceAccess.service_id == payload.service_id,
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Node already has access to this service",
        )

    now = datetime.now(timezone.utc)
    access = models.NodeServiceAccess(
        node_id=node_id,
        service_id=payload.service_id,
        granted_at=now,
        granted_by=None,
    )
    db.add(access)
    db.commit()
    db.refresh(access)

    return node_schema.ServiceAccessResponse(
        node_id=access.node_id,
        service_id=access.service_id,
        granted_at=access.granted_at,
    )


@router.delete("/internal/nodes/{node_id}/services/{service_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_service_access_internal(
    node_id: str,
    service_id: str,
    app_client: models.AppClient = Depends(require_app_client),
    db: Session = Depends(get_db),
):
    """Revoke a node's access to a service."""
    access = db.query(models.NodeServiceAccess).filter(
        models.NodeServiceAccess.node_id == node_id,
        models.NodeServiceAccess.service_id == service_id,
    ).first()
    if not access:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Service access not found",
        )

    db.delete(access)
    db.commit()
    return None

