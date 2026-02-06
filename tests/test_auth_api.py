import os
import importlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Set env for tests before app import
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


def test_register_returns_tokens(client):
    resp = client.post("/auth/register", json={"email": "user@example.com", "password": "password123"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["access_token"]
    assert data["refresh_token"]
    assert data["token_type"] == "bearer"
    assert data["user"]["email"] == "user@example.com"


def test_login_returns_tokens(client):
    client.post("/auth/register", json={"email": "user2@example.com", "password": "password123"})
    resp = client.post("/auth/login", json={"email": "user2@example.com", "password": "password123"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["access_token"]
    assert data["refresh_token"]
    assert data["user"]["email"] == "user2@example.com"


def test_invalid_login(client):
    client.post("/auth/register", json={"email": "user3@example.com", "password": "password123"})
    resp = client.post("/auth/login", json={"email": "user3@example.com", "password": "wrong"})
    assert resp.status_code == 401
    assert "detail" in resp.json()


def test_refresh_returns_new_access_token(client):
    register = client.post("/auth/register", json={"email": "user4@example.com", "password": "password123"})
    tokens = register.json()
    refresh_token = tokens["refresh_token"]
    resp = client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert resp.status_code == 200
    new_access = resp.json()["access_token"]
    assert new_access
    payload = security.decode_token(new_access)
    assert payload["sub"]
    assert "exp" in payload


def test_register_includes_is_superuser(client):
    resp = client.post("/auth/register", json={"email": "su_test1@example.com", "password": "password123"})
    assert resp.status_code == 201
    data = resp.json()
    assert "is_superuser" in data["user"]
    assert data["user"]["is_superuser"] is False


def test_login_includes_is_superuser(client):
    client.post("/auth/register", json={"email": "su_test2@example.com", "password": "password123"})
    resp = client.post("/auth/login", json={"email": "su_test2@example.com", "password": "password123"})
    assert resp.status_code == 200
    data = resp.json()
    assert "is_superuser" in data["user"]
    assert data["user"]["is_superuser"] is False


def test_refresh_includes_is_superuser(client):
    register = client.post("/auth/register", json={"email": "su_test3@example.com", "password": "password123"})
    tokens = register.json()
    resp = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert resp.status_code == 200
    data = resp.json()
    assert "is_superuser" in data["user"]
    assert data["user"]["is_superuser"] is False


def test_auth_me_returns_current_user(client):
    register = client.post("/auth/register", json={"email": "me_test@example.com", "password": "password123"})
    tokens = register.json()
    access_token = tokens["access_token"]
    resp = client.get("/auth/me", headers={"Authorization": f"Bearer {access_token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == "me_test@example.com"
    assert "is_superuser" in data
    assert data["is_superuser"] is False


def test_auth_me_requires_auth(client):
    resp = client.get("/auth/me")
    assert resp.status_code == 401


def test_cors_headers_present(client):
    resp = client.options(
        "/auth/login",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert resp.headers.get("access-control-allow-origin") is not None

