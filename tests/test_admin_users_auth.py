"""Admin user-management endpoints must require the master admin token.

Security finding (svc-trust #5): `/admin/users/{id}/superuser` (and the admin
user-read endpoints) gated only on app-to-app credentials via
`require_app_client`. Every service in the fleet holds app credentials, so ANY
compromised/curious service could grant itself (or any user) superuser — a
fleet-wide privilege-escalation primitive. These endpoints are documented as
`X-Jarvis-Admin-Token`-gated and are only meant for trusted infrastructure.

Fix: gate the whole router on `require_admin_token`, matching sibling
`admin_nodes.py` / `admin_app_clients.py`. App credentials must be rejected.
"""
import importlib
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Test env (mirrors test_node_auth.py)
os.environ["AUTH_SECRET_KEY"] = "test-secret"
os.environ["AUTH_ALGORITHM"] = "HS256"
os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"] = "30"
os.environ["REFRESH_TOKEN_EXPIRE_DAYS"] = "14"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["JARVIS_AUTH_ADMIN_TOKEN"] = "admin-test-token"

import jarvis_auth.app.core.settings as settings_module

importlib.reload(settings_module)

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
    from jarvis_auth.app.api import deps
    from jarvis_auth.app.api import admin_app_clients
    from jarvis_auth.app.api.dependencies import app_auth

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[admin_app_clients.get_db] = override_get_db
    app.dependency_overrides[app_auth.get_db] = override_get_db

    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture()
def target_user(db_session):
    from jarvis_auth.app.db import models
    from jarvis_auth.app.core.security import hash_password

    user = models.User(
        email="victim@example.com",
        username="victim",
        password_hash=hash_password("password123"),
        is_active=True,
        is_superuser=False,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture()
def app_client_creds(client):
    """App-to-app credentials — the auth a hostile service would present."""
    resp = client.post(
        "/admin/app-clients",
        json={"app_id": "some-service", "name": "Some Service"},
        headers=_admin_headers(),
    )
    assert resp.status_code == 201
    return {"app_id": "some-service", "key": resp.json()["key"]}


def _admin_headers():
    return {"X-Jarvis-Admin-Token": "admin-test-token"}


def _app_headers(creds: dict):
    return {"X-Jarvis-App-Id": creds["app_id"], "X-Jarvis-App-Key": creds["key"]}


class TestSuperuserUpdateAuth:
    def test_app_client_cannot_grant_superuser(self, client, target_user, app_client_creds):
        """The core privilege-escalation vector: app creds must NOT work."""
        resp = client.put(
            f"/admin/users/{target_user.id}/superuser",
            json={"is_superuser": True},
            headers=_app_headers(app_client_creds),
        )
        assert resp.status_code == 401

    def test_admin_token_can_grant_superuser(self, client, target_user):
        resp = client.put(
            f"/admin/users/{target_user.id}/superuser",
            json={"is_superuser": True},
            headers=_admin_headers(),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["is_superuser"] is True
        assert body["user_id"] == target_user.id

    def test_no_auth_rejected(self, client, target_user):
        resp = client.put(
            f"/admin/users/{target_user.id}/superuser",
            json={"is_superuser": True},
        )
        assert resp.status_code == 401


class TestAdminUserReadAuth:
    def test_app_client_cannot_read_user(self, client, target_user, app_client_creds):
        resp = client.get(
            f"/admin/users/{target_user.id}",
            headers=_app_headers(app_client_creds),
        )
        assert resp.status_code == 401

    def test_admin_token_can_read_user(self, client, target_user):
        resp = client.get(
            f"/admin/users/{target_user.id}",
            headers=_admin_headers(),
        )
        assert resp.status_code == 200
        assert resp.json()["email"] == "victim@example.com"

    def test_app_client_cannot_read_user_by_email(self, client, target_user, app_client_creds):
        resp = client.get(
            "/admin/users/by-email/victim@example.com",
            headers=_app_headers(app_client_creds),
        )
        assert resp.status_code == 401

    def test_admin_token_can_read_user_by_email(self, client, target_user):
        resp = client.get(
            "/admin/users/by-email/victim@example.com",
            headers=_admin_headers(),
        )
        assert resp.status_code == 200
        assert resp.json()["id"] == target_user.id
