"""Brute-force protection on /auth/{login,register,refresh}.

Two layers (see core/rate_limit.py): a global per-IP sliding window, and a
per-(email, IP) failed-login lockout keyed on the pair so it can't be abused to
lock the real user out from a different IP.
"""
import importlib
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

os.environ["AUTH_SECRET_KEY"] = "test-secret"
os.environ["AUTH_ALGORITHM"] = "HS256"
os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"] = "30"
os.environ["REFRESH_TOKEN_EXPIRE_DAYS"] = "14"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["JARVIS_AUTH_ADMIN_TOKEN"] = "admin-test-token"

import jarvis_auth.app.core.settings as settings_module

importlib.reload(settings_module)

from jarvis_auth.app.core import rate_limit
from jarvis_auth.app.core.rate_limit import AuthRateLimiter, client_ip
from jarvis_auth.app.core.settings import settings
from jarvis_auth.app.db import base
from jarvis_auth.app.db import session as session_module
from jarvis_auth.app.main import app

session_module.engine = create_engine(
    settings_module.settings.database_url,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
session_module.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=session_module.engine)

engine = session_module.engine
TestingSessionLocal = session_module.SessionLocal


@pytest.fixture(scope="session", autouse=True)
def setup_db():
    base.Base.metadata.create_all(bind=engine)
    yield
    base.Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db_session():
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture()
def client(db_session):
    from jarvis_auth.app.api import auth as auth_router
    from jarvis_auth.app.api import deps as deps_module

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[auth_router.get_db] = override_get_db
    app.dependency_overrides[deps_module.get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


class _FakeClient:
    def __init__(self, host):
        self.host = host


class _FakeRequest:
    def __init__(self, headers=None, host="1.2.3.4"):
        self.headers = headers or {}
        self.client = _FakeClient(host)


# ---------------- Unit tests: AuthRateLimiter ----------------

class TestAuthRateLimiterUnit:
    def test_check_ip_blocks_over_limit(self):
        rl = AuthRateLimiter()
        assert all(rl.check_ip("ip", limit=3) for _ in range(3))
        assert rl.check_ip("ip", limit=3) is False

    def test_lockout_after_max_failures(self):
        rl = AuthRateLimiter()
        for _ in range(3):
            assert rl.is_locked("a@x.com", "ip", max_failures=3, window=900) is False
            rl.record_failure("a@x.com", "ip", window=900)
        assert rl.is_locked("a@x.com", "ip", max_failures=3, window=900) is True

    def test_lockout_is_keyed_by_email_and_ip(self):
        rl = AuthRateLimiter()
        for _ in range(5):
            rl.record_failure("victim@x.com", "attacker-ip", window=900)
        # Same email from a DIFFERENT ip (the real user) is NOT locked.
        assert rl.is_locked("victim@x.com", "victim-ip", max_failures=3, window=900) is False
        # Different email from the attacker ip is NOT locked.
        assert rl.is_locked("someone@x.com", "attacker-ip", max_failures=3, window=900) is False

    def test_clear_failures_resets(self):
        rl = AuthRateLimiter()
        for _ in range(5):
            rl.record_failure("a@x.com", "ip", window=900)
        rl.clear_failures("a@x.com", "ip")
        assert rl.is_locked("a@x.com", "ip", max_failures=3, window=900) is False

    def test_ip_map_is_bounded(self):
        rl = AuthRateLimiter(max_keys=100)
        for i in range(500):
            rl.check_ip(f"ip-{i}", limit=5)
        assert len(rl._ip) <= 100

    def test_client_ip_prefers_socket_by_default(self):
        req = _FakeRequest(headers={"x-forwarded-for": "9.9.9.9, 8.8.8.8"}, host="1.2.3.4")
        assert client_ip(req, trust_forwarded_for=False) == "1.2.3.4"

    def test_client_ip_uses_rightmost_xff_when_trusted(self):
        req = _FakeRequest(headers={"x-forwarded-for": "9.9.9.9, 8.8.8.8"}, host="1.2.3.4")
        assert client_ip(req, trust_forwarded_for=True) == "8.8.8.8"


# ---------------- Integration: endpoint wiring ----------------

class TestAuthRateLimitEndpoints:
    def test_ip_flood_returns_429(self, client):
        limit = settings.auth_rate_limit_ip_per_minute
        # Exhaust the per-IP window for the TestClient's socket IP.
        for _ in range(limit):
            rate_limit.rate_limiter.check_ip("testclient", limit)
        resp = client.post("/auth/login", json={"email": "x@example.com", "password": "y"})
        assert resp.status_code == 429

    def test_login_lockout_after_repeated_failures(self, client):
        client.post("/auth/register", json={"email": "lockme@example.com", "password": "password123"})
        for _ in range(settings.auth_login_max_failures):
            r = client.post("/auth/login", json={"email": "lockme@example.com", "password": "wrong"})
            assert r.status_code == 401
        # Even the CORRECT password is now refused with 429.
        r = client.post("/auth/login", json={"email": "lockme@example.com", "password": "password123"})
        assert r.status_code == 429

    def test_lockout_does_not_block_a_different_email(self, client):
        client.post("/auth/register", json={"email": "other@example.com", "password": "password123"})
        for _ in range(settings.auth_login_max_failures):
            client.post("/auth/login", json={"email": "attacked@example.com", "password": "wrong"})
        # A different account from the same IP still logs in fine.
        r = client.post("/auth/login", json={"email": "other@example.com", "password": "password123"})
        assert r.status_code == 200

    def test_successful_login_still_works_under_limit(self, client):
        client.post("/auth/register", json={"email": "happy@example.com", "password": "password123"})
        r = client.post("/auth/login", json={"email": "happy@example.com", "password": "password123"})
        assert r.status_code == 200
        assert r.json()["access_token"]
