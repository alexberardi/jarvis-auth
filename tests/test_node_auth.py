import importlib
import os

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
    from jarvis_auth.app.api import admin_nodes
    from jarvis_auth.app.api import internal
    from jarvis_auth.app.api.dependencies import app_auth

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[admin_app_clients.get_db] = override_get_db
    app.dependency_overrides[admin_nodes.get_db] = override_get_db
    app.dependency_overrides[internal.get_db] = override_get_db
    app.dependency_overrides[app_auth.get_db] = override_get_db

    return TestClient(app)


@pytest.fixture()
def test_user(db_session):
    """Create a test user for node registration."""
    from jarvis_auth.app.db import models
    from jarvis_auth.app.core.security import hash_password

    user = models.User(
        email="test@example.com",
        username="testuser",
        password_hash=hash_password("password123"),
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture()
def app_client_creds(client):
    """Create an app client for internal endpoint testing."""
    resp = client.post(
        "/admin/app-clients",
        json={"app_id": "command-center", "name": "Command Center"},
        headers=_admin_headers(),
    )
    assert resp.status_code == 201
    return {"app_id": "command-center", "key": resp.json()["key"]}


def _admin_headers():
    return {"X-Jarvis-Admin-Token": "admin-test-token"}


def _app_headers(creds: dict):
    return {"X-Jarvis-App-Id": creds["app_id"], "X-Jarvis-App-Key": creds["key"]}


# ============================================================
# Admin Node Endpoints Tests
# ============================================================


class TestAdminNodeCreate:
    def test_create_node_success(self, client, test_user):
        resp = client.post(
            "/admin/nodes",
            json={
                "node_id": "kitchen-pi",
                "user_id": test_user.id,
                "name": "Kitchen Node",
                "services": ["command-center"],
            },
            headers=_admin_headers(),
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["node_id"] == "kitchen-pi"
        assert body["name"] == "Kitchen Node"
        assert body["user_id"] == test_user.id
        assert "node_key" in body
        assert len(body["node_key"]) > 20
        assert body["services"] == ["command-center"]

    def test_create_node_without_services(self, client, test_user):
        resp = client.post(
            "/admin/nodes",
            json={"node_id": "living-room-pi", "user_id": test_user.id, "name": "Living Room"},
            headers=_admin_headers(),
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["services"] == []

    def test_create_node_duplicate_id(self, client, test_user):
        client.post(
            "/admin/nodes",
            json={"node_id": "dup-node", "user_id": test_user.id, "name": "First"},
            headers=_admin_headers(),
        )
        resp = client.post(
            "/admin/nodes",
            json={"node_id": "dup-node", "user_id": test_user.id, "name": "Second"},
            headers=_admin_headers(),
        )
        assert resp.status_code == 400
        assert "already exists" in resp.json()["detail"]

    def test_create_node_invalid_user(self, client):
        resp = client.post(
            "/admin/nodes",
            json={"node_id": "orphan-node", "user_id": 9999, "name": "Orphan"},
            headers=_admin_headers(),
        )
        assert resp.status_code == 404
        assert "User not found" in resp.json()["detail"]

    def test_create_node_requires_admin(self, client, test_user):
        resp = client.post(
            "/admin/nodes",
            json={"node_id": "unauth-node", "user_id": test_user.id, "name": "Unauthorized"},
        )
        assert resp.status_code == 401


class TestAdminNodeList:
    def test_list_nodes_empty(self, client):
        resp = client.get("/admin/nodes", headers=_admin_headers())
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_list_nodes_with_data(self, client, test_user):
        client.post(
            "/admin/nodes",
            json={"node_id": "node-a", "user_id": test_user.id, "name": "Node A", "services": ["svc1"]},
            headers=_admin_headers(),
        )
        client.post(
            "/admin/nodes",
            json={"node_id": "node-b", "user_id": test_user.id, "name": "Node B"},
            headers=_admin_headers(),
        )

        resp = client.get("/admin/nodes", headers=_admin_headers())
        assert resp.status_code == 200
        nodes = resp.json()
        assert len(nodes) >= 2
        node_ids = [n["node_id"] for n in nodes]
        assert "node-a" in node_ids
        assert "node-b" in node_ids


class TestAdminNodeDetail:
    def test_get_node_success(self, client, test_user):
        create_resp = client.post(
            "/admin/nodes",
            json={"node_id": "detail-node", "user_id": test_user.id, "name": "Detail Node", "services": ["svc1", "svc2"]},
            headers=_admin_headers(),
        )
        assert create_resp.status_code == 201

        resp = client.get("/admin/nodes/detail-node", headers=_admin_headers())
        assert resp.status_code == 200
        body = resp.json()
        assert body["node_id"] == "detail-node"
        assert body["name"] == "Detail Node"
        assert body["is_active"] is True
        assert len(body["services"]) == 2

    def test_get_node_not_found(self, client):
        resp = client.get("/admin/nodes/nonexistent", headers=_admin_headers())
        assert resp.status_code == 404


class TestAdminNodeDeactivate:
    def test_deactivate_node(self, client, test_user):
        client.post(
            "/admin/nodes",
            json={"node_id": "deactivate-me", "user_id": test_user.id, "name": "To Deactivate"},
            headers=_admin_headers(),
        )

        resp = client.delete("/admin/nodes/deactivate-me", headers=_admin_headers())
        assert resp.status_code == 200
        body = resp.json()
        assert body["node_id"] == "deactivate-me"
        assert body["is_active"] is False

        # Verify node is deactivated
        detail_resp = client.get("/admin/nodes/deactivate-me", headers=_admin_headers())
        assert detail_resp.json()["is_active"] is False

    def test_deactivate_node_not_found(self, client):
        resp = client.delete("/admin/nodes/nonexistent", headers=_admin_headers())
        assert resp.status_code == 404


class TestAdminNodeRotateKey:
    def test_rotate_key_success(self, client, test_user):
        create_resp = client.post(
            "/admin/nodes",
            json={"node_id": "rotate-node", "user_id": test_user.id, "name": "Rotate Node"},
            headers=_admin_headers(),
        )
        original_key = create_resp.json()["node_key"]

        resp = client.post("/admin/nodes/rotate-node/rotate-key", headers=_admin_headers())
        assert resp.status_code == 200
        body = resp.json()
        assert body["node_id"] == "rotate-node"
        assert "node_key" in body
        assert body["node_key"] != original_key
        assert "last_rotated_at" in body

    def test_rotate_key_not_found(self, client):
        resp = client.post("/admin/nodes/nonexistent/rotate-key", headers=_admin_headers())
        assert resp.status_code == 404


class TestAdminServiceAccess:
    def test_grant_service_access(self, client, test_user):
        client.post(
            "/admin/nodes",
            json={"node_id": "grant-access-node", "user_id": test_user.id, "name": "Grant Access Node"},
            headers=_admin_headers(),
        )

        resp = client.post(
            "/admin/nodes/grant-access-node/services",
            json={"service_id": "jarvis-logs"},
            headers=_admin_headers(),
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["node_id"] == "grant-access-node"
        assert body["service_id"] == "jarvis-logs"

    def test_grant_duplicate_access(self, client, test_user):
        client.post(
            "/admin/nodes",
            json={"node_id": "dup-access-node", "user_id": test_user.id, "name": "Dup Access Node", "services": ["svc1"]},
            headers=_admin_headers(),
        )

        resp = client.post(
            "/admin/nodes/dup-access-node/services",
            json={"service_id": "svc1"},
            headers=_admin_headers(),
        )
        assert resp.status_code == 400
        assert "already has access" in resp.json()["detail"]

    def test_revoke_service_access(self, client, test_user):
        client.post(
            "/admin/nodes",
            json={"node_id": "revoke-access-node", "user_id": test_user.id, "name": "Revoke Access Node", "services": ["svc1"]},
            headers=_admin_headers(),
        )

        resp = client.delete("/admin/nodes/revoke-access-node/services/svc1", headers=_admin_headers())
        assert resp.status_code == 204

        # Verify access was revoked
        detail = client.get("/admin/nodes/revoke-access-node", headers=_admin_headers())
        services = [s["service_id"] for s in detail.json()["services"]]
        assert "svc1" not in services

    def test_revoke_nonexistent_access(self, client, test_user):
        client.post(
            "/admin/nodes",
            json={"node_id": "no-access-node", "user_id": test_user.id, "name": "No Access Node"},
            headers=_admin_headers(),
        )

        resp = client.delete("/admin/nodes/no-access-node/services/nonexistent", headers=_admin_headers())
        assert resp.status_code == 404


# ============================================================
# Internal Node Endpoints Tests
# ============================================================


class TestInternalValidateNode:
    def test_validate_node_success(self, client, test_user, app_client_creds):
        # Create node with access to command-center
        create_resp = client.post(
            "/admin/nodes",
            json={
                "node_id": "validate-node",
                "user_id": test_user.id,
                "name": "Validate Node",
                "services": ["command-center"],
            },
            headers=_admin_headers(),
        )
        node_key = create_resp.json()["node_key"]

        resp = client.post(
            "/internal/validate-node",
            json={"node_id": "validate-node", "node_key": node_key, "service_id": "command-center"},
            headers=_app_headers(app_client_creds),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["valid"] is True
        assert body["node_id"] == "validate-node"
        assert body["user_id"] == test_user.id

    def test_validate_node_invalid_key(self, client, test_user, app_client_creds):
        client.post(
            "/admin/nodes",
            json={"node_id": "bad-key-node", "user_id": test_user.id, "name": "Bad Key Node", "services": ["command-center"]},
            headers=_admin_headers(),
        )

        resp = client.post(
            "/internal/validate-node",
            json={"node_id": "bad-key-node", "node_key": "wrong-key", "service_id": "command-center"},
            headers=_app_headers(app_client_creds),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["valid"] is False
        assert "Invalid node credentials" in body["reason"]

    def test_validate_node_no_service_access(self, client, test_user, app_client_creds):
        create_resp = client.post(
            "/admin/nodes",
            json={"node_id": "no-access", "user_id": test_user.id, "name": "No Access", "services": []},
            headers=_admin_headers(),
        )
        node_key = create_resp.json()["node_key"]

        resp = client.post(
            "/internal/validate-node",
            json={"node_id": "no-access", "node_key": node_key, "service_id": "command-center"},
            headers=_app_headers(app_client_creds),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["valid"] is False
        assert "not authorized" in body["reason"].lower()

    def test_validate_node_inactive(self, client, test_user, app_client_creds):
        create_resp = client.post(
            "/admin/nodes",
            json={"node_id": "inactive-node", "user_id": test_user.id, "name": "Inactive", "services": ["command-center"]},
            headers=_admin_headers(),
        )
        node_key = create_resp.json()["node_key"]

        # Deactivate node
        client.delete("/admin/nodes/inactive-node", headers=_admin_headers())

        resp = client.post(
            "/internal/validate-node",
            json={"node_id": "inactive-node", "node_key": node_key, "service_id": "command-center"},
            headers=_app_headers(app_client_creds),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["valid"] is False
        assert "inactive" in body["reason"].lower() or "not found" in body["reason"].lower()

    def test_validate_node_not_found(self, client, app_client_creds):
        resp = client.post(
            "/internal/validate-node",
            json={"node_id": "nonexistent", "node_key": "any-key", "service_id": "command-center"},
            headers=_app_headers(app_client_creds),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["valid"] is False

    def test_validate_node_requires_app_auth(self, client):
        resp = client.post(
            "/internal/validate-node",
            json={"node_id": "any", "node_key": "any", "service_id": "any"},
        )
        assert resp.status_code == 401


class TestInternalRegisterNode:
    def test_register_node_success(self, client, test_user, app_client_creds):
        resp = client.post(
            "/internal/nodes/register",
            json={"node_id": "new-node", "user_id": test_user.id, "name": "New Node", "services": ["command-center"]},
            headers=_app_headers(app_client_creds),
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["node_id"] == "new-node"
        assert "node_key" in body

        # Verify node was created with calling service's access
        detail = client.get("/admin/nodes/new-node", headers=_admin_headers())
        services = [s["service_id"] for s in detail.json()["services"]]
        assert "command-center" in services

    def test_register_node_auto_grants_caller_access(self, client, test_user, app_client_creds):
        """The registering service automatically gets access."""
        resp = client.post(
            "/internal/nodes/register",
            json={"node_id": "auto-access-node", "user_id": test_user.id, "name": "Auto Access"},
            headers=_app_headers(app_client_creds),
        )
        assert resp.status_code == 201

        # Verify calling service (command-center) has access
        detail = client.get("/admin/nodes/auto-access-node", headers=_admin_headers())
        services = [s["service_id"] for s in detail.json()["services"]]
        assert "command-center" in services

    def test_register_node_duplicate(self, client, test_user, app_client_creds):
        client.post(
            "/internal/nodes/register",
            json={"node_id": "dup-register", "user_id": test_user.id, "name": "First"},
            headers=_app_headers(app_client_creds),
        )

        resp = client.post(
            "/internal/nodes/register",
            json={"node_id": "dup-register", "user_id": test_user.id, "name": "Second"},
            headers=_app_headers(app_client_creds),
        )
        assert resp.status_code == 400

    def test_register_node_requires_app_auth(self, client, test_user):
        resp = client.post(
            "/internal/nodes/register",
            json={"node_id": "no-auth-node", "user_id": test_user.id, "name": "No Auth"},
        )
        assert resp.status_code == 401


class TestInternalServiceAccess:
    def test_grant_service_access_via_internal(self, client, test_user, app_client_creds):
        # Create node
        create_resp = client.post(
            "/internal/nodes/register",
            json={"node_id": "svc-access-node", "user_id": test_user.id, "name": "Service Access Node"},
            headers=_app_headers(app_client_creds),
        )
        assert create_resp.status_code == 201

        # Grant additional service access
        resp = client.post(
            "/internal/nodes/svc-access-node/services",
            json={"service_id": "jarvis-logs"},
            headers=_app_headers(app_client_creds),
        )
        assert resp.status_code == 201
        assert resp.json()["service_id"] == "jarvis-logs"

    def test_revoke_service_access_via_internal(self, client, test_user, app_client_creds):
        # Create node with jarvis-logs access
        client.post(
            "/internal/nodes/register",
            json={"node_id": "revoke-svc-node", "user_id": test_user.id, "name": "Revoke Svc Node", "services": ["jarvis-logs"]},
            headers=_app_headers(app_client_creds),
        )

        # Revoke access
        resp = client.delete(
            "/internal/nodes/revoke-svc-node/services/jarvis-logs",
            headers=_app_headers(app_client_creds),
        )
        assert resp.status_code == 204
