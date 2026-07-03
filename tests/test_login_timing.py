"""Login must not leak which emails are registered via response timing.

Security (P2.1, enum-equalization half): the login check was
`if not user or not verify_password(...)`. Python short-circuits, so for an
unknown email no bcrypt verification ran — the fast (no-hash) response reveals
which emails exist. Fix: always run a bcrypt verify (against a dummy hash when
the user is missing) so both paths cost the same.
"""
import importlib
import os
from unittest.mock import patch

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

from jarvis_auth.app.core import security
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


def test_dummy_hash_is_a_real_verifiable_bcrypt_hash():
    # Sanity: the dummy is a genuine hash that fails a wrong password (so the
    # unknown-email path never accidentally authenticates).
    assert security.verify_password("anything", security.DUMMY_PASSWORD_HASH) is False


def test_login_runs_bcrypt_even_for_unknown_email(client):
    """The timing-equalizing verify must actually run for a nonexistent email."""
    real_verify = security.verify_password
    with patch.object(
        security, "verify_password", side_effect=real_verify
    ) as spy:
        resp = client.post(
            "/auth/login",
            json={"email": "ghost@example.com", "password": "whatever"},
        )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid email or password"
    # A bcrypt verification ran despite the user not existing, and it used the
    # dummy hash — so timing matches the "user exists, wrong password" path.
    spy.assert_called_once()
    assert spy.call_args.args[1] == security.DUMMY_PASSWORD_HASH


def test_login_wrong_password_same_message_as_unknown_email(client):
    client.post("/auth/register", json={"email": "real@example.com", "password": "password123"})

    unknown = client.post("/auth/login", json={"email": "nobody@example.com", "password": "x"})
    wrong = client.post("/auth/login", json={"email": "real@example.com", "password": "wrong"})

    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json()["detail"] == wrong.json()["detail"] == "Invalid email or password"


def test_login_success_still_works(client):
    client.post("/auth/register", json={"email": "good@example.com", "password": "password123"})
    resp = client.post("/auth/login", json={"email": "good@example.com", "password": "password123"})
    assert resp.status_code == 200
    assert resp.json()["access_token"]
