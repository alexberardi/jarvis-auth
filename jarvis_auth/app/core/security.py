from datetime import datetime, timedelta, timezone
import hashlib
import logging
import secrets
from typing import Any, Dict, Optional

from jose import ExpiredSignatureError, JWTError, jwt
from jose.exceptions import JWTClaimsError
from passlib.context import CryptContext

from jarvis_auth.app.core.settings import settings

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def _expiry_delta(minutes: int | None = None, days: int | None = None) -> datetime:
    if minutes is not None:
        delta = timedelta(minutes=minutes)
    elif days is not None:
        delta = timedelta(days=days)
    else:
        delta = timedelta(minutes=settings.access_token_expire_minutes)
    return datetime.now(timezone.utc) + delta


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    to_encode.setdefault("jti", secrets.token_urlsafe(8))
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    to_encode.update({"exp": expire, "iat": now})
    return jwt.encode(to_encode, settings.auth_secret_key, algorithm=settings.auth_algorithm)


def create_refresh_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(days=settings.refresh_token_expire_days))
    to_encode.update({"exp": expire, "iat": now})
    return jwt.encode(to_encode, settings.auth_secret_key, algorithm=settings.auth_algorithm)


def decode_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, settings.auth_secret_key, algorithms=[settings.auth_algorithm])
    except ExpiredSignatureError:
        logger.debug("Token has expired")
        raise
    except JWTClaimsError as exc:
        logger.debug("Token claims validation failed: %s", exc)
        raise
    except JWTError as exc:
        logger.debug("Token decode failed: %s", exc)
        raise


def generate_refresh_token_pair() -> tuple[str, str]:
    """Return (plain_refresh_token, hashed_refresh_token)."""
    token = secrets.token_urlsafe(48)
    return token, hash_refresh_token(token)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def refresh_token_expiry() -> datetime:
    return _expiry_delta(days=settings.refresh_token_expire_days)

