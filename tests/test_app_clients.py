import os
import importlib
import secrets

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Test env
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
from jarvis_auth.app.api.dependencies import app_auth

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
    from jarvis_auth.app.api import admin_app_clients
    from jarvis_auth.app.api import internal

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    # override for user auth routes
    from jarvis_auth.app.api import deps

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[admin_app_clients.get_db] = override_get_db
    app.dependency_overrides[app_auth.get_db] = override_get_db

    return TestClient(app)


def _admin_headers():
    return {"X-Jarvis-Admin-Token": "admin-test-token"}


def test_admin_create_rotate_revoke(client):
    # create
    resp = client.post(
        "/admin/app-clients",
        json={"app_id": "llm-proxy", "name": "LLM Proxy"},
        headers=_admin_headers(),
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["app_id"] == "llm-proxy"
    assert body["key"]

    # rotate
    resp_rotate = client.post("/admin/app-clients/llm-proxy/rotate", headers=_admin_headers())
    assert resp_rotate.status_code == 200
    rotate_body = resp_rotate.json()
    assert rotate_body["key"]
    assert rotate_body["app_id"] == "llm-proxy"

    # revoke
    resp_revoke = client.post("/admin/app-clients/llm-proxy/revoke", headers=_admin_headers())
    assert resp_revoke.status_code == 200
    assert resp_revoke.json()["is_active"] is False

    # list
    resp_list = client.get("/admin/app-clients", headers=_admin_headers())
    assert resp_list.status_code == 200
    assert any(item["app_id"] == "llm-proxy" for item in resp_list.json())


def test_require_app_client_success_and_failure(client):
    # create client
    create_resp = client.post(
        "/admin/app-clients",
        json={"app_id": "service-a", "name": "Service A"},
        headers=_admin_headers(),
    )
    assert create_resp.status_code == 201
    key = create_resp.json()["key"]

    # success on protected endpoint
    ok = client.get(
        "/internal/app-ping",
        headers={"X-Jarvis-App-Id": "service-a", "X-Jarvis-App-Key": key},
    )
    assert ok.status_code == 200
    assert ok.json()["app_id"] == "service-a"

    # missing creds
    miss = client.get("/internal/app-ping")
    assert miss.status_code == 401
    assert miss.json()["detail"] == "Missing app credentials"

    # invalid key
    bad = client.get(
        "/internal/app-ping",
        headers={"X-Jarvis-App-Id": "service-a", "X-Jarvis-App-Key": "wrong"},
    )
    assert bad.status_code == 401
    assert bad.json()["detail"] == "Invalid app credentials"

