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


def test_setup_status_needs_setup_on_empty_db(client):
    resp = client.get("/auth/setup-status")
    assert resp.status_code == 200
    assert resp.json() == {"needs_setup": True}


def test_setup_creates_superuser(client):
    resp = client.post("/auth/setup", json={
        "email": "admin@example.com",
        "username": "admin",
        "password": "password123",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["access_token"]
    assert data["refresh_token"]
    assert data["user"]["email"] == "admin@example.com"
    assert data["user"]["username"] == "admin"
    assert data["user"]["is_superuser"] is True
    assert data["household_id"]


def test_setup_status_false_after_setup(client):
    # Create a superuser first
    client.post("/auth/setup", json={
        "email": "admin2@example.com",
        "password": "password123",
    })
    resp = client.get("/auth/setup-status")
    assert resp.status_code == 200
    assert resp.json() == {"needs_setup": False}


def test_setup_returns_409_when_superuser_exists(client):
    # Create a superuser first
    client.post("/auth/setup", json={
        "email": "admin3@example.com",
        "password": "password123",
    })
    # Try again — should be locked out
    resp = client.post("/auth/setup", json={
        "email": "another@example.com",
        "password": "password123",
    })
    assert resp.status_code == 409
    assert resp.json()["detail"] == "Setup already completed"


def test_setup_user_can_access_superuser_endpoints(client):
    resp = client.post("/auth/setup", json={
        "email": "admin4@example.com",
        "password": "password123",
    })
    assert resp.status_code == 201
    token = resp.json()["access_token"]

    # /auth/me should work and show is_superuser
    me_resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["is_superuser"] is True
