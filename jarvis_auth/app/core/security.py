from datetime import datetime, timedelta, timezone
import base64
import binascii
import hashlib
import secrets
from functools import lru_cache
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


# Key material is bound to the algorithm FAMILY, never to one shared variable.
# During the HS256 -> RS256 window this service both mints and verifies, and the
# RSA public half is published at /auth/public-key for anyone to read. If a
# single "the key" variable fed jwt.decode, an attacker could sign a token HS256
# using that published public key as the HMAC secret and be verified. Binding the
# key to the family means such a token is checked against auth_secret_key and
# fails. jarvis-recipes-server's verifier is built the same way on purpose.
SYMMETRIC_ALGORITHMS = frozenset({"HS256"})
ASYMMETRIC_ALGORITHMS = frozenset({"RS256"})
SUPPORTED_ALGORITHMS = SYMMETRIC_ALGORITHMS | ASYMMETRIC_ALGORITHMS


@lru_cache(maxsize=1)
def _private_key_pem() -> str | None:
    """The configured RSA private key as PEM, or None when unset/unusable.

    AUTH_PRIVATE_KEY carries a base64-encoded PKCS#8 PEM (see settings.py for
    why base64). Cached: this is process-lifetime config, not per-request state.
    """
    raw = settings.auth_private_key
    if not raw:
        return None
    try:
        pem = base64.b64decode(raw, validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        logger.error("AUTH_PRIVATE_KEY is not valid base64; RS256 unavailable")
        return None
    if "PRIVATE KEY" not in pem:
        logger.error("AUTH_PRIVATE_KEY does not decode to a PEM private key")
        return None
    return pem


@lru_cache(maxsize=1)
def _public_key_pem() -> str | None:
    """The public half, DERIVED from the private key rather than configured.

    Deriving means the published key can never drift from the signing key, which
    is the failure that would silently reject every RS256 token in the fleet.
    """
    private_pem = _private_key_pem()
    if not private_pem:
        return None
    try:
        from cryptography.hazmat.primitives import serialization

        key = serialization.load_pem_private_key(private_pem.encode(), password=None)
        return key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
    except (ValueError, TypeError) as exc:
        logger.error("AUTH_PRIVATE_KEY could not be parsed", error=str(exc))
        return None


def _signing_algorithm() -> str:
    """Which algorithm to MINT with.

    Read from the settings DB (`auth.algorithm`, 60s cache) so the migration can
    be flipped without a redeploy, falling back to the AUTH_ALGORITHM env var.

    If RS256 is requested but no usable key is configured, this falls back to
    HS256 with a loud error rather than raising. A raise here would take every
    login down the moment someone flipped the knob ahead of provisioning the key;
    HS256 is still a fully valid algorithm that every verifier in the window
    accepts, so degrading is strictly safer than failing. The flip not having
    taken effect is visible in the logs and from /auth/public-key.
    """
    algorithm = settings.auth_algorithm
    try:
        from jarvis_auth.app.services.settings_service import get_settings_service

        configured = get_settings_service().get_str("auth.algorithm", algorithm)
        if configured:
            algorithm = configured
    except Exception as exc:  # settings DB unavailable -> env var still governs
        logger.debug("Falling back to AUTH_ALGORITHM env var", error=str(exc))

    if algorithm not in SUPPORTED_ALGORITHMS:
        logger.error(
            "Unsupported auth.algorithm configured; minting HS256 instead",
            configured=algorithm,
        )
        return "HS256"
    if algorithm in ASYMMETRIC_ALGORITHMS and not _private_key_pem():
        logger.error(
            "auth.algorithm is RS256 but AUTH_PRIVATE_KEY is unset or unusable; "
            "minting HS256 instead"
        )
        return "HS256"
    return algorithm


def _signing_key(algorithm: str) -> str:
    """Key material for MINTING, chosen by family."""
    if algorithm in ASYMMETRIC_ALGORITHMS:
        private_pem = _private_key_pem()
        if not private_pem:
            raise RuntimeError("RS256 requested without a usable AUTH_PRIVATE_KEY")
        return private_pem
    return settings.auth_secret_key


def _verification_key(algorithm: str) -> str:
    """Key material for VERIFYING, chosen by family. See the note above."""
    if algorithm in ASYMMETRIC_ALGORITHMS:
        public_pem = _public_key_pem()
        if not public_pem:
            # Fail CLOSED: an RS256 token we cannot check is not accepted.
            raise JWTError("No RS256 public key available")
        return public_pem
    return settings.auth_secret_key


def reset_key_cache() -> None:
    """Drop the cached key material. For tests and key rotation on restart."""
    _private_key_pem.cache_clear()
    _public_key_pem.cache_clear()


def get_public_key_pem() -> str | None:
    """Public accessor for the published verification key."""
    return _public_key_pem()


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
    algorithm = _signing_algorithm()
    return jwt.encode(to_encode, _signing_key(algorithm), algorithm=algorithm)


def create_refresh_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(days=settings.refresh_token_expire_days))
    to_encode.update({"exp": expire, "iat": now})
    return jwt.encode(to_encode, settings.auth_secret_key, algorithm=settings.auth_algorithm)


def decode_token(token: str) -> Dict[str, Any]:
    """Verify a token, accepting HS256 and RS256 for the migration window.

    The algorithm comes from the token's own header and is checked against an
    allowlist (so "none" and anything exotic is rejected), then the key is chosen
    by FAMILY — never from a single shared variable. auth.algorithm governs only
    what this service MINTS; a verifier that accepted just one algorithm would
    make a staged rollout impossible, since tokens minted before the flip must
    keep working after it.
    """
    try:
        algorithm = jwt.get_unverified_header(token).get("alg")
        if algorithm not in SUPPORTED_ALGORITHMS:
            raise JWTError(f"Unsupported token algorithm: {algorithm!r}")
        return jwt.decode(token, _verification_key(algorithm), algorithms=[algorithm])
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

