from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from fastapi import HTTPException, status
from jose import JWTError
from sqlalchemy.orm import Session

from jarvis_auth.app.core import security
from jarvis_auth.app.core.config import settings
from jarvis_auth.app.db import models
from jarvis_auth.app.schemas import auth as auth_schema
from jarvis_auth.app.services import user_service


def register_user(db: Session, payload: auth_schema.RegisterRequest) -> models.User:
    if user_service.get_user_by_email(db, payload.email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    if user_service.get_user_by_username(db, payload.username):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")

    hashed_password = security.hash_password(payload.password)
    user = models.User(
        email=payload.email,
        username=payload.username,
        password_hash=hashed_password,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def authenticate_user(db: Session, email: str, password: str) -> Optional[models.User]:
    user = user_service.get_user_by_email(db, email)
    if not user or not security.verify_password(password, user.password_hash):
        return None
    return user


def build_refresh_token() -> tuple[str, str, datetime]:
    refresh_token, refresh_hash = security.generate_refresh_token_pair()
    expires_at = security.refresh_token_expiry()
    return refresh_token, refresh_hash, expires_at


def store_refresh_token(db: Session, user: models.User, token_hash: str, expires_at: datetime) -> models.RefreshToken:
    record = models.RefreshToken(user_id=user.id, token_hash=token_hash, expires_at=expires_at, revoked=False)
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def refresh_access_token(db: Session, refresh_token: str) -> Optional[str]:
    token_hash = security.hash_refresh_token(refresh_token)
    record = db.query(models.RefreshToken).filter(models.RefreshToken.token_hash == token_hash).first()
    if not record or record.revoked or record.is_expired:
        return None

    user = user_service.get_user_by_id(db, record.user_id)
    if not user or not user.is_active:
        return None

    access_token = security.create_access_token(
        data={"sub": str(user.id), "email": user.email},
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes),
    )
    return access_token


def revoke_refresh_token(db: Session, refresh_token: str) -> bool:
    token_hash = security.hash_refresh_token(refresh_token)
    record = db.query(models.RefreshToken).filter(models.RefreshToken.token_hash == token_hash).first()
    if not record:
        return False
    record.revoked = True
    db.add(record)
    db.commit()
    return True

