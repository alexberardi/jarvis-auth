"""Tests for superuser functionality.

Tests:
- is_superuser field in User model
- is_superuser claim in JWT tokens
- require_superuser dependency
- require_settings_auth combined dependency
- admin_users endpoints
"""

import os
import importlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Set env for tests before app import
os.environ["AUTH_SECRET_KEY"] = "test-secret-for-superuser"
os.environ["AUTH_ALGORITHM"] = "HS256"
os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"] = "30"
os.environ["REFRESH_TOKEN_EXPIRE_DAYS"] = "14"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["JARVIS_AUTH_ADMIN_TOKEN"] = "admin-test-token"

import jarvis_auth.app.core.settings as settings_module

importlib.reload(settings_module)

from jarvis_auth.app.core import security
from jarvis_auth.app.db import base, models
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


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    """Create tables for tests."""
    base.Base.metadata.create_all(bind=engine)
    yield
    base.Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db_session():
    """Create a fresh database session for each test."""
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
    """Create test client with database override."""
    from jarvis_auth.app.api import auth as auth_router
    from jarvis_auth.app.api import deps
    from jarvis_auth.app.api.dependencies import app_auth

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[auth_router.get_db] = override_get_db
    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[app_auth.get_db] = override_get_db

    yield TestClient(app)

    app.dependency_overrides.clear()


@pytest.fixture()
def regular_user(client) -> dict:
    """Create a regular (non-superuser) user and return their tokens."""
    resp = client.post(
        "/auth/register",
        json={"email": "regular@example.com", "password": "password123"},
    )
    assert resp.status_code == 201
    return resp.json()


@pytest.fixture()
def superuser(client, db_session) -> dict:
    """Create a superuser and return their tokens."""
    # First register normally
    resp = client.post(
        "/auth/register",
        json={"email": "super@example.com", "password": "password123"},
    )
    assert resp.status_code == 201
    data = resp.json()

    # Now make them a superuser directly in DB
    user = db_session.query(models.User).filter(models.User.email == "super@example.com").first()
    user.is_superuser = True
    db_session.commit()

    # Re-login to get a token with is_superuser claim
    resp = client.post(
        "/auth/login",
        json={"email": "super@example.com", "password": "password123"},
    )
    assert resp.status_code == 200
    return resp.json()


@pytest.fixture()
def app_client_creds(db_session) -> tuple[str, str]:
    """Create app client credentials for app-to-app auth testing."""
    app_id = "test-app-client"
    app_key = "test-app-key-12345"
    key_hash = security.hash_password(app_key)

    app_client = models.AppClient(
        app_id=app_id,
        name="Test App Client",
        key_hash=key_hash,
        is_active=True,
    )
    db_session.add(app_client)
    db_session.commit()

    return app_id, app_key


class TestIsSuperuserInJWT:
    """Test that is_superuser is included in JWT tokens."""

    def test_regular_user_token_has_is_superuser_false(self, regular_user):
        """Regular user's token should have is_superuser=False."""
        token = regular_user["access_token"]
        payload = security.decode_token(token)

        assert "is_superuser" in payload
        assert payload["is_superuser"] is False

    def test_superuser_token_has_is_superuser_true(self, superuser):
        """Superuser's token should have is_superuser=True."""
        token = superuser["access_token"]
        payload = security.decode_token(token)

        assert "is_superuser" in payload
        assert payload["is_superuser"] is True

    def test_refresh_preserves_is_superuser(self, client, superuser):
        """Refreshed token should still have is_superuser claim."""
        refresh_token = superuser["refresh_token"]
        resp = client.post("/auth/refresh", json={"refresh_token": refresh_token})
        assert resp.status_code == 200

        new_access_token = resp.json()["access_token"]
        payload = security.decode_token(new_access_token)

        assert "is_superuser" in payload
        assert payload["is_superuser"] is True


class TestAdminUsersEndpoints:
    """Test admin user management endpoints."""

    def test_update_superuser_status_requires_app_auth(self, client, regular_user):
        """Endpoint should require app-to-app auth."""
        resp = client.put(
            "/admin/users/1/superuser",
            json={"is_superuser": True},
        )
        assert resp.status_code == 401

    def test_update_superuser_status_with_app_auth(self, client, db_session, app_client_creds):
        """Should update superuser status with app-to-app auth."""
        # Create a user to modify
        resp = client.post(
            "/auth/register",
            json={"email": "toupdate@example.com", "password": "password123"},
        )
        user_id = resp.json()["user"]["id"]

        app_id, app_key = app_client_creds
        resp = client.put(
            f"/admin/users/{user_id}/superuser",
            json={"is_superuser": True},
            headers={
                "X-Jarvis-App-Id": app_id,
                "X-Jarvis-App-Key": app_key,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["is_superuser"] is True
        assert "granted" in data["message"]

    def test_update_superuser_status_user_not_found(self, client, app_client_creds):
        """Should return 404 for non-existent user."""
        app_id, app_key = app_client_creds
        resp = client.put(
            "/admin/users/99999/superuser",
            json={"is_superuser": True},
            headers={
                "X-Jarvis-App-Id": app_id,
                "X-Jarvis-App-Key": app_key,
            },
        )
        assert resp.status_code == 404

    def test_get_user_admin(self, client, app_client_creds, regular_user):
        """Should get admin view of user."""
        user_id = regular_user["user"]["id"]
        app_id, app_key = app_client_creds

        resp = client.get(
            f"/admin/users/{user_id}",
            headers={
                "X-Jarvis-App-Id": app_id,
                "X-Jarvis-App-Key": app_key,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == user_id
        assert data["email"] == "regular@example.com"
        assert "is_superuser" in data
        assert "is_active" in data


class TestRequireSettingsAuth:
    """Test combined settings auth dependency."""

    def test_settings_with_superuser_jwt(self, client, superuser):
        """Settings endpoint should accept superuser JWT."""
        token = superuser["access_token"]
        resp = client.get(
            "/settings/",
            headers={"Authorization": f"Bearer {token}"},
        )
        # Should not be 401/403 - actual status depends on settings service setup
        assert resp.status_code != 401
        assert resp.status_code != 403

    def test_settings_with_regular_user_jwt(self, client, regular_user):
        """Settings endpoint should reject regular user JWT."""
        token = regular_user["access_token"]
        resp = client.get(
            "/settings/",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    def test_settings_with_app_auth(self, client, app_client_creds):
        """Settings endpoint should accept app-to-app auth."""
        app_id, app_key = app_client_creds
        resp = client.get(
            "/settings/",
            headers={
                "X-Jarvis-App-Id": app_id,
                "X-Jarvis-App-Key": app_key,
            },
        )
        # Should not be 401 - actual status depends on settings service setup
        assert resp.status_code != 401

    def test_settings_without_auth(self, client):
        """Settings endpoint should reject requests without auth."""
        resp = client.get("/settings/")
        assert resp.status_code == 401


class TestUserModelSuperuser:
    """Test is_superuser field in User model."""

    def test_new_user_is_not_superuser_by_default(self, db_session):
        """New users should not be superusers by default."""
        user = models.User(
            email="newuser@example.com",
            username="newuser",
            password_hash=security.hash_password("password"),
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        assert user.is_superuser is False

    def test_can_set_superuser_flag(self, db_session):
        """Should be able to set is_superuser flag."""
        user = models.User(
            email="willbesuper@example.com",
            username="willbesuper",
            password_hash=security.hash_password("password"),
            is_active=True,
            is_superuser=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        assert user.is_superuser is True
