from datetime import datetime, timezone
import secrets

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from jarvis_auth.app.api.dependencies.admin_auth import require_admin_token
from jarvis_auth.app.core.security import hash_password
from jarvis_auth.app.db import models
from jarvis_auth.app.db.session import SessionLocal
from jarvis_auth.app.schemas import app_client as app_client_schema

router = APIRouter(dependencies=[Depends(require_admin_token)])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _generate_key_and_hash() -> tuple[str, str]:
    raw_key = secrets.token_urlsafe(48)
    key_hash = hash_password(raw_key)
    return raw_key, key_hash


@router.post("/admin/app-clients", response_model=app_client_schema.AppClientCreateResponse, status_code=status.HTTP_201_CREATED)
def create_app_client(payload: app_client_schema.AppClientCreateRequest, db: Session = Depends(get_db)):
    existing = db.query(models.AppClient).filter(models.AppClient.app_id == payload.app_id).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="app_id already exists")

    raw_key, key_hash = _generate_key_and_hash()
    now = datetime.now(timezone.utc)
    app_client = models.AppClient(
        app_id=payload.app_id,
        name=payload.name,
        key_hash=key_hash,
        is_active=True,
        created_at=now,
        last_rotated_at=None,
    )
    db.add(app_client)
    db.commit()
    db.refresh(app_client)
    return app_client_schema.AppClientCreateResponse(
        app_id=app_client.app_id,
        name=app_client.name,
        key=raw_key,
        created_at=app_client.created_at,
        last_rotated_at=app_client.last_rotated_at,
    )


@router.post("/admin/app-clients/{app_id}/rotate", response_model=app_client_schema.AppClientRotateResponse)
def rotate_app_client(app_id: str, db: Session = Depends(get_db)):
    app_client = db.query(models.AppClient).filter(models.AppClient.app_id == app_id).first()
    if not app_client:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="App client not found")

    raw_key, key_hash = _generate_key_and_hash()
    now = datetime.now(timezone.utc)
    app_client.key_hash = key_hash
    app_client.last_rotated_at = now
    app_client.is_active = True
    db.add(app_client)
    db.commit()
    db.refresh(app_client)
    return app_client_schema.AppClientRotateResponse(app_id=app_client.app_id, key=raw_key, last_rotated_at=app_client.last_rotated_at)


@router.post("/admin/app-clients/{app_id}/revoke", response_model=app_client_schema.AppClientRevokeResponse)
def revoke_app_client(app_id: str, db: Session = Depends(get_db)):
    app_client = db.query(models.AppClient).filter(models.AppClient.app_id == app_id).first()
    if not app_client:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="App client not found")

    app_client.is_active = False
    db.add(app_client)
    db.commit()
    return app_client_schema.AppClientRevokeResponse(app_id=app_client.app_id, is_active=app_client.is_active)


@router.get("/admin/app-clients", response_model=list[app_client_schema.AppClientListItem])
def list_app_clients(db: Session = Depends(get_db)):
    clients = db.query(models.AppClient).all()
    return [app_client_schema.AppClientListItem.model_validate(c) for c in clients]

