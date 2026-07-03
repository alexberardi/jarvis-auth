from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from typing import Any, Dict, Optional

from jose import ExpiredSignatureError, JWTError, jwt
from jose.exceptions import JWTClaimsError
from passlib.context import CryptContext

from jarvis_auth.app.core.logging import get_logger
from jarvis_auth.app.core.settings import settings

logger = get_logger()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# A throwaway hash used to equalize login timing when the email doesn't exist.
# Verifying a supplied password against this costs the same as a real bcrypt
# check, so an attacker can't distinguish registered emails by response time
# (login user-enumeration). Computed once at import so it matches the live cost.
DUMMY_PASSWORD_HASH = pwd_context.hash(secrets.token_urlsafe(32))


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
        logger.debug("Token claims validation failed", error=str(exc))
        raise
    except JWTError as exc:
        logger.debug("Token decode failed", error=str(exc))
        raise


# No 0/O/1/l/I/5/S/8/B — temp passwords get relayed verbally or retyped from a screen.
_TEMP_PASSWORD_ALPHABET = "abcdefghjkmnpqrtuvwxyz234679ACDEFGHJKMNPQRTUVWXYZ"


def generate_temp_password() -> str:
    """Generate a readable one-time password like 'xK4m-Tq9w-Rj2n'."""
    groups = [
        "".join(secrets.choice(_TEMP_PASSWORD_ALPHABET) for _ in range(4))
        for _ in range(3)
    ]
    return "-".join(groups)


def generate_refresh_token_pair() -> tuple[str, str]:
    """Return (plain_refresh_token, hashed_refresh_token)."""
    token = secrets.token_urlsafe(48)
    return token, hash_refresh_token(token)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def refresh_token_expiry() -> datetime:
    return _expiry_delta(days=settings.refresh_token_expire_days)

