from datetime import datetime, timezone
import secrets

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from jarvis_auth.app.api.dependencies.admin_auth import require_admin_token
from jarvis_auth.app.core.security import hash_password
from jarvis_auth.app.db import models
from jarvis_auth.app.db.session import SessionLocal
from jarvis_auth.app.schemas import node as node_schema

router = APIRouter(dependencies=[Depends(require_admin_token)])


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


def _get_node_services(node: models.NodeRegistration) -> list[str]:
    return [access.service_id for access in node.service_access]


@router.post("/admin/nodes", response_model=node_schema.NodeCreateResponse, status_code=status.HTTP_201_CREATED)
def create_node(payload: node_schema.NodeCreateRequest, db: Session = Depends(get_db)):
    # Check if node_id already exists
    existing = db.query(models.NodeRegistration).filter(
        models.NodeRegistration.node_id == payload.node_id
    ).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="node_id already exists")

    # Verify user exists
    user = db.query(models.User).filter(models.User.id == payload.user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

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

    # Grant service access if specified
    services = payload.services or []
    for service_id in services:
        access = models.NodeServiceAccess(
            node_id=payload.node_id,
            service_id=service_id,
            granted_at=now,
            granted_by=None,
        )
        db.add(access)

    db.commit()
    db.refresh(node)

    return node_schema.NodeCreateResponse(
        node_id=node.node_id,
        name=node.name,
        user_id=node.user_id,
        node_key=raw_key,
        created_at=node.created_at,
        services=services,
    )


@router.get("/admin/nodes", response_model=list[node_schema.NodeListItem])
def list_nodes(db: Session = Depends(get_db)):
    nodes = db.query(models.NodeRegistration).all()
    return [
        node_schema.NodeListItem(
            node_id=node.node_id,
            name=node.name,
            user_id=node.user_id,
            is_active=node.is_active,
            created_at=node.created_at,
            updated_at=node.updated_at,
            last_rotated_at=node.last_rotated_at,
            services=_get_node_services(node),
        )
        for node in nodes
    ]


@router.get("/admin/nodes/{node_id}", response_model=node_schema.NodeDetailResponse)
def get_node(node_id: str, db: Session = Depends(get_db)):
    node = db.query(models.NodeRegistration).filter(
        models.NodeRegistration.node_id == node_id
    ).first()
    if not node:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")

    return node_schema.NodeDetailResponse(
        node_id=node.node_id,
        name=node.name,
        user_id=node.user_id,
        is_active=node.is_active,
        created_at=node.created_at,
        updated_at=node.updated_at,
        last_rotated_at=node.last_rotated_at,
        services=[
            node_schema.ServiceAccessItem(
                service_id=access.service_id,
                granted_at=access.granted_at,
                granted_by=access.granted_by,
            )
            for access in node.service_access
        ],
    )


@router.delete("/admin/nodes/{node_id}", response_model=node_schema.NodeDeactivateResponse)
def deactivate_node(node_id: str, db: Session = Depends(get_db)):
    node = db.query(models.NodeRegistration).filter(
        models.NodeRegistration.node_id == node_id
    ).first()
    if not node:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")

    node.is_active = False
    db.add(node)
    db.commit()

    return node_schema.NodeDeactivateResponse(node_id=node.node_id, is_active=node.is_active)


@router.post("/admin/nodes/{node_id}/rotate-key", response_model=node_schema.NodeRotateKeyResponse)
def rotate_node_key(node_id: str, db: Session = Depends(get_db)):
    node = db.query(models.NodeRegistration).filter(
        models.NodeRegistration.node_id == node_id
    ).first()
    if not node:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")

    raw_key, key_hash = _generate_node_key_and_hash()
    now = datetime.now(timezone.utc)

    node.node_key_hash = key_hash
    node.last_rotated_at = now
    db.add(node)
    db.commit()
    db.refresh(node)

    return node_schema.NodeRotateKeyResponse(
        node_id=node.node_id,
        node_key=raw_key,
        last_rotated_at=node.last_rotated_at,
    )


@router.post("/admin/nodes/{node_id}/services", response_model=node_schema.ServiceAccessResponse, status_code=status.HTTP_201_CREATED)
def grant_service_access(node_id: str, payload: node_schema.ServiceAccessRequest, db: Session = Depends(get_db)):
    node = db.query(models.NodeRegistration).filter(
        models.NodeRegistration.node_id == node_id
    ).first()
    if not node:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")

    # Check if access already exists
    existing = db.query(models.NodeServiceAccess).filter(
        models.NodeServiceAccess.node_id == node_id,
        models.NodeServiceAccess.service_id == payload.service_id,
    ).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Node already has access to this service")

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


@router.delete("/admin/nodes/{node_id}/services/{service_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_service_access(node_id: str, service_id: str, db: Session = Depends(get_db)):
    access = db.query(models.NodeServiceAccess).filter(
        models.NodeServiceAccess.node_id == node_id,
        models.NodeServiceAccess.service_id == service_id,
    ).first()
    if not access:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service access not found")

    db.delete(access)
    db.commit()
    return None
