"""The HS256 -> RS256 migration: minting, publishing and dual-accept verification.

The point of this whole exercise is a window in which tokens minted under either
algorithm verify everywhere, so services can be rolled forward one at a time. The
tests that matter most here are the ones about the *seam*: a token minted before
the flip must still verify after it, and the published public key must never be
usable to forge a token.
"""
import base64
import hashlib
import hmac
import importlib
import json
import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jose import JWTError, jwt
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

os.environ["AUTH_SECRET_KEY"] = "test-secret"
os.environ["AUTH_ALGORITHM"] = "HS256"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["JARVIS_AUTH_ADMIN_TOKEN"] = "admin-test-token"

# NOTE: every fixture below patches `security.settings`, never
# `settings_module.settings`. Thirteen test modules call importlib.reload on the
# settings module, which rebinds that attribute to a fresh object, while
# security.py bound its own reference at import time (security.py:14). Patching
# the module attribute therefore works in isolation and silently does nothing
# once another module has reloaded after this one.

import jarvis_auth.app.core.settings as settings_module  # noqa: E402

importlib.reload(settings_module)

from jarvis_auth.app.core import security  # noqa: E402
from jarvis_auth.app.db import base  # noqa: E402
from jarvis_auth.app.db import session as session_module  # noqa: E402
from jarvis_auth.app.main import app  # noqa: E402

session_module.engine = create_engine(
    settings_module.settings.database_url,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
session_module.SessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=session_module.engine
)


@pytest.fixture(scope="session", autouse=True)
def setup_db():
    base.Base.metadata.create_all(bind=session_module.engine)
    yield
    base.Base.metadata.drop_all(bind=session_module.engine)


@pytest.fixture
def client():
    return TestClient(app)


def _keypair() -> tuple[str, str]:
    """(private PEM, public PEM)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


@pytest.fixture(autouse=True)
def _clean_key_cache():
    """Key material is process-lifetime cached; don't leak it between tests."""
    security.reset_key_cache()
    yield
    security.reset_key_cache()


@pytest.fixture
def rsa_configured(monkeypatch):
    """Provision AUTH_PRIVATE_KEY the way the installer will: base64 PKCS#8 PEM."""
    private_pem, public_pem = _keypair()
    monkeypatch.setattr(
        security.settings,
        "auth_private_key",
        base64.b64encode(private_pem.encode()).decode(),
    )
    security.reset_key_cache()
    return private_pem, public_pem


@pytest.fixture
def mint_rs256(monkeypatch, rsa_configured):
    """Flip the minting knob, as the settings DB would."""
    monkeypatch.setattr(security, "_signing_algorithm", lambda: "RS256")
    return rsa_configured


class TestPublicKeyEndpoint:
    def test_503_when_no_key_is_provisioned(self, client, monkeypatch):
        """Not 404: the route exists, the key just isn't there yet. A consumer
        must fail closed rather than read the absence as 'no RS256 in play'."""
        monkeypatch.setattr(security.settings, "auth_private_key", "")
        security.reset_key_cache()

        resp = client.get("/auth/public-key")
        assert resp.status_code == 503

    def test_publishes_the_key_without_authentication(self, client, rsa_configured):
        """Verifiers need this BEFORE they can authenticate anything."""
        _, public_pem = rsa_configured

        resp = client.get("/auth/public-key")

        assert resp.status_code == 200
        assert resp.json()["public_key"] == public_pem
        assert resp.json()["algorithm"] == "RS256"

    def test_response_shape_matches_the_existing_consumer(self, client, rsa_configured):
        """jarvis-recipes-server does resp.json().get("public_key"). Renaming that
        field silently breaks RS256 verification across the fleet."""
        body = client.get("/auth/public-key").json()

        assert isinstance(body.get("public_key"), str)
        assert "BEGIN PUBLIC KEY" in body["public_key"]

    def test_never_publishes_the_private_half(self, client, rsa_configured):
        private_pem, _ = rsa_configured

        body = client.get("/auth/public-key").text

        assert "PRIVATE KEY" not in body
        assert private_pem not in body

    def test_published_key_is_derived_from_the_signing_key(self, mint_rs256):
        """Derived, not separately configured, so the two cannot drift — a drift
        would silently reject every RS256 token in the fleet."""
        token = security.create_access_token({"sub": "1"})

        # Verifying with the *published* key must succeed against a token signed
        # by the private key.
        assert jwt.decode(
            token, security.get_public_key_pem(), algorithms=["RS256"]
        )["sub"] == "1"


class TestMinting:
    def test_defaults_to_hs256(self, monkeypatch):
        monkeypatch.setattr(security, "_signing_algorithm", lambda: "HS256")

        token = security.create_access_token({"sub": "1"})

        assert jwt.get_unverified_header(token)["alg"] == "HS256"

    def test_mints_rs256_once_the_knob_is_flipped(self, mint_rs256):
        token = security.create_access_token({"sub": "1"})

        assert jwt.get_unverified_header(token)["alg"] == "RS256"

    def test_rs256_without_a_key_degrades_to_hs256_rather_than_failing(
        self, monkeypatch
    ):
        """A raise here would take every login down the moment the knob was
        flipped ahead of provisioning. HS256 is still valid and still accepted by
        every verifier in the window, so degrading is strictly safer."""
        monkeypatch.setattr(security.settings, "auth_private_key", "")
        monkeypatch.setattr(security.settings, "auth_algorithm", "RS256")
        security.reset_key_cache()

        assert security._signing_algorithm() == "HS256"
        token = security.create_access_token({"sub": "1"})
        assert jwt.get_unverified_header(token)["alg"] == "HS256"

    def test_an_unknown_configured_algorithm_degrades_to_hs256(self, monkeypatch):
        monkeypatch.setattr(security.settings, "auth_algorithm", "HS512")

        assert security._signing_algorithm() == "HS256"

    @pytest.mark.parametrize("garbage", ["not-base64!!", "aGVsbG8="])
    def test_unusable_private_key_material_is_ignored(self, monkeypatch, garbage):
        """Malformed base64, or base64 of something that isn't a PEM."""
        monkeypatch.setattr(security.settings, "auth_private_key", garbage)
        security.reset_key_cache()

        assert security._private_key_pem() is None
        assert security.get_public_key_pem() is None


class TestDualAcceptVerification:
    def test_hs256_tokens_verify(self, monkeypatch):
        monkeypatch.setattr(security, "_signing_algorithm", lambda: "HS256")
        token = security.create_access_token({"sub": "7"})

        assert security.decode_token(token)["sub"] == "7"

    def test_rs256_tokens_verify(self, mint_rs256):
        token = security.create_access_token({"sub": "8"})

        assert security.decode_token(token)["sub"] == "8"

    def test_a_token_minted_before_the_flip_still_verifies_after_it(
        self, monkeypatch, rsa_configured
    ):
        """The entire reason for the dual-accept window."""
        monkeypatch.setattr(security, "_signing_algorithm", lambda: "HS256")
        legacy = security.create_access_token({"sub": "9"})

        monkeypatch.setattr(security, "_signing_algorithm", lambda: "RS256")
        fresh = security.create_access_token({"sub": "10"})

        assert security.decode_token(legacy)["sub"] == "9"
        assert security.decode_token(fresh)["sub"] == "10"

    def test_alg_none_is_rejected(self):
        def b64(obj) -> str:
            return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

        forged = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'sub': '1'})}."

        with pytest.raises(JWTError):
            security.decode_token(forged)

    def test_an_algorithm_outside_the_allowlist_is_rejected(self):
        token = jwt.encode({"sub": "1"}, "test-secret", algorithm="HS512")

        with pytest.raises(JWTError):
            security.decode_token(token)

    def test_hs256_signed_with_the_published_public_key_is_rejected(self, rsa_configured):
        """Algorithm confusion — the hazard the family binding exists to stop.

        The public key is published at /auth/public-key for anyone to read. If one
        variable held "the key", this forgery would verify. python-jose refuses to
        SIGN this way, so the token is built by hand — an attacker won't be using
        python-jose either.
        """
        _, public_pem = rsa_configured

        def b64(raw: bytes) -> str:
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        payload = b64(json.dumps({"sub": "1", "is_superuser": True}).encode())
        sig = b64(
            hmac.new(
                public_pem.encode(), f"{header}.{payload}".encode(), hashlib.sha256
            ).digest()
        )

        with pytest.raises(JWTError):
            security.decode_token(f"{header}.{payload}.{sig}")

    def test_rs256_token_is_rejected_when_no_key_is_available(
        self, monkeypatch, rsa_configured
    ):
        """Fail CLOSED: a token we cannot check is not accepted."""
        monkeypatch.setattr(security, "_signing_algorithm", lambda: "RS256")
        token = security.create_access_token({"sub": "1"})

        monkeypatch.setattr(security.settings, "auth_private_key", "")
        security.reset_key_cache()

        with pytest.raises(JWTError):
            security.decode_token(token)
