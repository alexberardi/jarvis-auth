from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from jarvis_auth.app.core.security import verify_password
from jarvis_auth.app.db import models
from jarvis_auth.app.db.session import SessionLocal


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def require_app_client(
    x_jarvis_app_id: str | None = Header(None),
    x_jarvis_app_key: str | None = Header(None),
    db: Session = Depends(get_db),
) -> models.AppClient:
    if not x_jarvis_app_id or not x_jarvis_app_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing app credentials")

    app_client = db.query(models.AppClient).filter(models.AppClient.app_id == x_jarvis_app_id).first()
    if not app_client or not app_client.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid app credentials")

    if not verify_password(x_jarvis_app_key, app_client.key_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid app credentials")

    return app_client

