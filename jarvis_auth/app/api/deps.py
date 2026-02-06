from typing import Any

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.orm import Session

from jarvis_auth.app.core import security
from jarvis_auth.app.db import models
from jarvis_auth.app.db.session import SessionLocal
from jarvis_auth.app.services import user_service

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
oauth2_scheme_optional = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = security.decode_token(token)
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = user_service.get_user_by_id(db, int(user_id))
    if user is None or not user.is_active:
        raise credentials_exception
    return user


def require_superuser(
    user: models.User = Depends(get_current_user),
) -> models.User:
    """Dependency that requires the current user to be a superuser."""
    if not user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser access required",
        )
    return user


def _validate_superuser_jwt(
    token: str,
    db: Session,
) -> dict[str, Any]:
    """Validate a JWT and ensure the user is a superuser.

    Returns dict with auth info on success, raises HTTPException on failure.
    """
    try:
        payload = security.decode_token(token)
        user_id = payload.get("sub")
        is_superuser = payload.get("is_superuser", False)

        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing user ID",
            )

        if not is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Superuser access required",
            )

        # Verify user still exists and is active
        user = user_service.get_user_by_id(db, int(user_id))
        if user is None or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive",
            )

        # Double-check superuser status from DB (in case it was revoked)
        if not user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Superuser access required",
            )

        return {
            "auth_type": "superuser_jwt",
            "user_id": user.id,
            "email": user.email,
        }

    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
        ) from exc


def _validate_app_client(
    app_id: str,
    app_key: str,
    db: Session,
) -> dict[str, Any]:
    """Validate app-to-app credentials.

    Returns dict with auth info on success, raises HTTPException on failure.
    """
    app_client = (
        db.query(models.AppClient)
        .filter(models.AppClient.app_id == app_id)
        .first()
    )
    if not app_client or not app_client.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid app credentials",
        )

    if not security.verify_password(app_key, app_client.key_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid app credentials",
        )

    return {
        "auth_type": "app_client",
        "app_id": app_client.app_id,
        "app_name": app_client.name,
    }


def require_settings_auth(
    authorization: str | None = Header(None),
    x_jarvis_app_id: str | None = Header(None),
    x_jarvis_app_key: str | None = Header(None),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Combined auth dependency for settings endpoints.

    Accepts either:
    - Superuser JWT (Authorization: Bearer <token>)
    - App-to-app credentials (X-Jarvis-App-Id + X-Jarvis-App-Key headers)

    Returns dict with auth info:
    - auth_type: "superuser_jwt" or "app_client"
    - Additional fields depending on auth type
    """
    # Try JWT first (if Authorization header present)
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]  # Strip "Bearer " prefix
        return _validate_superuser_jwt(token, db)

    # Fall back to app-to-app auth
    if x_jarvis_app_id and x_jarvis_app_key:
        return _validate_app_client(x_jarvis_app_id, x_jarvis_app_key, db)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing authentication. Provide either Bearer token or app credentials.",
    )
