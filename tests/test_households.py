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
    from jarvis_auth.app.api import auth as auth_module
    from jarvis_auth.app.api import admin_app_clients
    from jarvis_auth.app.api import admin_nodes
    from jarvis_auth.app.api import households
    from jarvis_auth.app.api import internal
    from jarvis_auth.app.api.dependencies import app_auth

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[auth_module.get_db] = override_get_db
    app.dependency_overrides[admin_app_clients.get_db] = override_get_db
    app.dependency_overrides[admin_nodes.get_db] = override_get_db
    app.dependency_overrides[households.get_db] = override_get_db
    app.dependency_overrides[internal.get_db] = override_get_db
    app.dependency_overrides[app_auth.get_db] = override_get_db

    return TestClient(app)


@pytest.fixture()
def test_user(db_session):
    """Create a test user."""
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
def second_user(db_session):
    """Create a second test user."""
    from jarvis_auth.app.db import models
    from jarvis_auth.app.core.security import hash_password

    user = models.User(
        email="user2@example.com",
        username="user2",
        password_hash=hash_password("password123"),
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture()
def auth_headers(client, test_user):
    """Get auth headers for test user."""
    resp = client.post("/auth/login", json={"email": "test@example.com", "password": "password123"})
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def second_user_auth_headers(client, second_user):
    """Get auth headers for second user."""
    resp = client.post("/auth/login", json={"email": "user2@example.com", "password": "password123"})
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def app_client_creds(client):
    """Create an app client for internal endpoint testing."""
    resp = client.post(
        "/admin/app-clients",
        json={"app_id": "command-center", "name": "Command Center"},
        headers={"X-Jarvis-Admin-Token": "admin-test-token"},
    )
    assert resp.status_code == 201
    return {"app_id": "command-center", "key": resp.json()["key"]}


def _app_headers(creds: dict):
    return {"X-Jarvis-App-Id": creds["app_id"], "X-Jarvis-App-Key": creds["key"]}


# ============================================================
# Household CRUD Tests
# ============================================================


class TestHouseholdCreate:
    def test_create_household_success(self, client, auth_headers):
        resp = client.post(
            "/households",
            json={"name": "My House"},
            headers=auth_headers,
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["name"] == "My House"
        assert "id" in body
        assert "created_at" in body

    def test_create_household_requires_auth(self, client):
        resp = client.post("/households", json={"name": "My House"})
        assert resp.status_code == 401

    def test_creator_becomes_admin(self, client, auth_headers, test_user):
        resp = client.post(
            "/households",
            json={"name": "Admin Test House"},
            headers=auth_headers,
        )
        assert resp.status_code == 201
        household_id = resp.json()["id"]

        # Check that creator is admin
        members_resp = client.get(
            f"/households/{household_id}/members",
            headers=auth_headers,
        )
        assert members_resp.status_code == 200
        members = members_resp.json()
        assert len(members) == 1
        assert members[0]["user_id"] == test_user.id
        assert members[0]["role"] == "admin"


class TestHouseholdList:
    def test_list_households_empty(self, client, auth_headers):
        resp = client.get("/households", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_households_with_data(self, client, auth_headers):
        # Create two households
        client.post("/households", json={"name": "House 1"}, headers=auth_headers)
        client.post("/households", json={"name": "House 2"}, headers=auth_headers)

        resp = client.get("/households", headers=auth_headers)
        assert resp.status_code == 200
        households = resp.json()
        assert len(households) == 2
        names = [h["name"] for h in households]
        assert "House 1" in names
        assert "House 2" in names
        # All should have admin role since we created them
        for h in households:
            assert h["role"] == "admin"


class TestHouseholdGet:
    def test_get_household_success(self, client, auth_headers):
        create_resp = client.post(
            "/households",
            json={"name": "Get Test House"},
            headers=auth_headers,
        )
        household_id = create_resp.json()["id"]

        resp = client.get(f"/households/{household_id}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["name"] == "Get Test House"

    def test_get_household_not_member(self, client, auth_headers, second_user_auth_headers):
        # User 1 creates household
        create_resp = client.post(
            "/households",
            json={"name": "Private House"},
            headers=auth_headers,
        )
        household_id = create_resp.json()["id"]

        # User 2 tries to access
        resp = client.get(f"/households/{household_id}", headers=second_user_auth_headers)
        assert resp.status_code == 403


class TestHouseholdUpdate:
    def test_update_household_success(self, client, auth_headers):
        create_resp = client.post(
            "/households",
            json={"name": "Original Name"},
            headers=auth_headers,
        )
        household_id = create_resp.json()["id"]

        resp = client.patch(
            f"/households/{household_id}",
            json={"name": "New Name"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "New Name"

    def test_update_household_requires_admin(self, client, auth_headers, second_user_auth_headers, second_user):
        # Create household and add second user as member
        create_resp = client.post(
            "/households",
            json={"name": "Admin Only Update"},
            headers=auth_headers,
        )
        household_id = create_resp.json()["id"]

        # Add second user as member (not admin)
        client.post(
            f"/households/{household_id}/members",
            json={"user_id": second_user.id, "role": "member"},
            headers=auth_headers,
        )

        # Second user tries to update
        resp = client.patch(
            f"/households/{household_id}",
            json={"name": "Attempted Update"},
            headers=second_user_auth_headers,
        )
        assert resp.status_code == 403


class TestHouseholdDelete:
    def test_delete_household_success(self, client, auth_headers):
        create_resp = client.post(
            "/households",
            json={"name": "Delete Me"},
            headers=auth_headers,
        )
        household_id = create_resp.json()["id"]

        resp = client.delete(f"/households/{household_id}", headers=auth_headers)
        assert resp.status_code == 204

        # Verify deleted
        get_resp = client.get(f"/households/{household_id}", headers=auth_headers)
        assert get_resp.status_code == 403  # No longer a member (household gone)


# ============================================================
# Member Management Tests
# ============================================================


class TestMemberList:
    def test_list_members(self, client, auth_headers, test_user):
        create_resp = client.post(
            "/households",
            json={"name": "Members Test"},
            headers=auth_headers,
        )
        household_id = create_resp.json()["id"]

        resp = client.get(f"/households/{household_id}/members", headers=auth_headers)
        assert resp.status_code == 200
        members = resp.json()
        assert len(members) == 1
        assert members[0]["username"] == test_user.username
        assert members[0]["role"] == "admin"


class TestMemberAdd:
    def test_add_member_success(self, client, auth_headers, second_user):
        create_resp = client.post(
            "/households",
            json={"name": "Add Member Test"},
            headers=auth_headers,
        )
        household_id = create_resp.json()["id"]

        resp = client.post(
            f"/households/{household_id}/members",
            json={"user_id": second_user.id, "role": "power_user"},
            headers=auth_headers,
        )
        assert resp.status_code == 201
        assert resp.json()["role"] == "power_user"

    def test_add_member_duplicate(self, client, auth_headers, second_user):
        create_resp = client.post(
            "/households",
            json={"name": "Dup Member Test"},
            headers=auth_headers,
        )
        household_id = create_resp.json()["id"]

        # Add once
        client.post(
            f"/households/{household_id}/members",
            json={"user_id": second_user.id, "role": "member"},
            headers=auth_headers,
        )

        # Try to add again
        resp = client.post(
            f"/households/{household_id}/members",
            json={"user_id": second_user.id, "role": "admin"},
            headers=auth_headers,
        )
        assert resp.status_code == 400
        assert "already a member" in resp.json()["detail"]


class TestMemberUpdate:
    def test_update_member_role(self, client, auth_headers, second_user):
        create_resp = client.post(
            "/households",
            json={"name": "Role Update Test"},
            headers=auth_headers,
        )
        household_id = create_resp.json()["id"]

        # Add member
        client.post(
            f"/households/{household_id}/members",
            json={"user_id": second_user.id, "role": "member"},
            headers=auth_headers,
        )

        # Update role
        resp = client.patch(
            f"/households/{household_id}/members/{second_user.id}",
            json={"role": "power_user"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["role"] == "power_user"

    def test_cannot_demote_self(self, client, auth_headers, test_user):
        create_resp = client.post(
            "/households",
            json={"name": "Self Demote Test"},
            headers=auth_headers,
        )
        household_id = create_resp.json()["id"]

        resp = client.patch(
            f"/households/{household_id}/members/{test_user.id}",
            json={"role": "member"},
            headers=auth_headers,
        )
        assert resp.status_code == 400
        assert "demote yourself" in resp.json()["detail"]


class TestMemberRemove:
    def test_remove_member_success(self, client, auth_headers, second_user):
        create_resp = client.post(
            "/households",
            json={"name": "Remove Member Test"},
            headers=auth_headers,
        )
        household_id = create_resp.json()["id"]

        # Add member
        client.post(
            f"/households/{household_id}/members",
            json={"user_id": second_user.id, "role": "member"},
            headers=auth_headers,
        )

        # Remove member
        resp = client.delete(
            f"/households/{household_id}/members/{second_user.id}",
            headers=auth_headers,
        )
        assert resp.status_code == 204

    def test_cannot_remove_self(self, client, auth_headers, test_user):
        create_resp = client.post(
            "/households",
            json={"name": "Self Remove Test"},
            headers=auth_headers,
        )
        household_id = create_resp.json()["id"]

        resp = client.delete(
            f"/households/{household_id}/members/{test_user.id}",
            headers=auth_headers,
        )
        assert resp.status_code == 400
        assert "remove yourself" in resp.json()["detail"]


# ============================================================
# Household Node Tests
# ============================================================


class TestHouseholdNodes:
    def test_list_household_nodes_empty(self, client, auth_headers):
        create_resp = client.post(
            "/households",
            json={"name": "Node Test House"},
            headers=auth_headers,
        )
        household_id = create_resp.json()["id"]

        resp = client.get(f"/households/{household_id}/nodes", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_register_node_success(self, client, auth_headers, test_user):
        create_resp = client.post(
            "/households",
            json={"name": "Register Node House"},
            headers=auth_headers,
        )
        household_id = create_resp.json()["id"]

        resp = client.post(
            f"/households/{household_id}/nodes",
            json={
                "node_id": "kitchen-node",
                "household_id": household_id,
                "name": "Kitchen Node",
                "services": ["command-center"],
            },
            headers=auth_headers,
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["node_id"] == "kitchen-node"
        assert body["household_id"] == household_id
        assert body["registered_by_user_id"] == test_user.id
        assert "node_key" in body

    def test_register_node_requires_power_user(self, client, auth_headers, second_user_auth_headers, second_user):
        create_resp = client.post(
            "/households",
            json={"name": "Power User Node House"},
            headers=auth_headers,
        )
        household_id = create_resp.json()["id"]

        # Add second user as member (not power_user)
        client.post(
            f"/households/{household_id}/members",
            json={"user_id": second_user.id, "role": "member"},
            headers=auth_headers,
        )

        # Member tries to register node
        resp = client.post(
            f"/households/{household_id}/nodes",
            json={
                "node_id": "member-node",
                "household_id": household_id,
                "name": "Member Node",
            },
            headers=second_user_auth_headers,
        )
        assert resp.status_code == 403

    def test_power_user_can_register_node(self, client, auth_headers, second_user_auth_headers, second_user):
        create_resp = client.post(
            "/households",
            json={"name": "Power User Can Register"},
            headers=auth_headers,
        )
        household_id = create_resp.json()["id"]

        # Add second user as power_user
        client.post(
            f"/households/{household_id}/members",
            json={"user_id": second_user.id, "role": "power_user"},
            headers=auth_headers,
        )

        # Power user registers node
        resp = client.post(
            f"/households/{household_id}/nodes",
            json={
                "node_id": "power-user-node",
                "household_id": household_id,
                "name": "Power User Node",
            },
            headers=second_user_auth_headers,
        )
        assert resp.status_code == 201


# ============================================================
# Internal Validation Endpoint Tests
# ============================================================


class TestInternalValidateHouseholdAccess:
    def test_validate_success(self, client, auth_headers, test_user, app_client_creds):
        create_resp = client.post(
            "/households",
            json={"name": "Validate House"},
            headers=auth_headers,
        )
        household_id = create_resp.json()["id"]

        resp = client.post(
            "/internal/validate-household-access",
            json={
                "user_id": test_user.id,
                "household_id": household_id,
                "required_role": "admin",
            },
            headers=_app_headers(app_client_creds),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["valid"] is True
        assert body["role"] == "admin"

    def test_validate_insufficient_role(self, client, auth_headers, second_user, app_client_creds):
        create_resp = client.post(
            "/households",
            json={"name": "Insufficient Role House"},
            headers=auth_headers,
        )
        household_id = create_resp.json()["id"]

        # Add as member
        client.post(
            f"/households/{household_id}/members",
            json={"user_id": second_user.id, "role": "member"},
            headers=auth_headers,
        )

        resp = client.post(
            "/internal/validate-household-access",
            json={
                "user_id": second_user.id,
                "household_id": household_id,
                "required_role": "power_user",
            },
            headers=_app_headers(app_client_creds),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["valid"] is False
        assert "requires power_user" in body["reason"]

    def test_validate_not_member(self, client, auth_headers, second_user, app_client_creds):
        create_resp = client.post(
            "/households",
            json={"name": "Not Member House"},
            headers=auth_headers,
        )
        household_id = create_resp.json()["id"]

        resp = client.post(
            "/internal/validate-household-access",
            json={
                "user_id": second_user.id,
                "household_id": household_id,
                "required_role": "member",
            },
            headers=_app_headers(app_client_creds),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["valid"] is False
        assert "not a member" in body["reason"]

    def test_role_hierarchy(self, client, auth_headers, test_user, app_client_creds):
        """Admin should satisfy power_user requirement."""
        create_resp = client.post(
            "/households",
            json={"name": "Hierarchy Test House"},
            headers=auth_headers,
        )
        household_id = create_resp.json()["id"]

        # User is admin, check if they satisfy power_user requirement
        resp = client.post(
            "/internal/validate-household-access",
            json={
                "user_id": test_user.id,
                "household_id": household_id,
                "required_role": "power_user",
            },
            headers=_app_headers(app_client_creds),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["valid"] is True
        assert body["role"] == "admin"


class TestInternalValidateNodeHousehold:
    def test_validate_node_success(self, client, auth_headers, app_client_creds):
        create_resp = client.post(
            "/households",
            json={"name": "Node Validate House"},
            headers=auth_headers,
        )
        household_id = create_resp.json()["id"]

        # Register node
        node_resp = client.post(
            f"/households/{household_id}/nodes",
            json={
                "node_id": "validate-node",
                "household_id": household_id,
                "name": "Validate Node",
            },
            headers=auth_headers,
        )
        assert node_resp.status_code == 201

        resp = client.post(
            "/internal/validate-node-household",
            json={
                "node_id": "validate-node",
                "household_id": household_id,
            },
            headers=_app_headers(app_client_creds),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["valid"] is True
        assert body["node_id"] == "validate-node"
        assert body["household_id"] == household_id

    def test_validate_node_wrong_household(self, client, auth_headers, app_client_creds):
        # Create two households
        house1_resp = client.post(
            "/households",
            json={"name": "House 1"},
            headers=auth_headers,
        )
        household1_id = house1_resp.json()["id"]

        house2_resp = client.post(
            "/households",
            json={"name": "House 2"},
            headers=auth_headers,
        )
        household2_id = house2_resp.json()["id"]

        # Register node to house 1
        client.post(
            f"/households/{household1_id}/nodes",
            json={
                "node_id": "house1-node",
                "household_id": household1_id,
                "name": "House 1 Node",
            },
            headers=auth_headers,
        )

        # Try to validate with house 2
        resp = client.post(
            "/internal/validate-node-household",
            json={
                "node_id": "house1-node",
                "household_id": household2_id,
            },
            headers=_app_headers(app_client_creds),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["valid"] is False
        assert "does not belong" in body["reason"]

    def test_validate_node_not_found(self, client, app_client_creds):
        resp = client.post(
            "/internal/validate-node-household",
            json={
                "node_id": "nonexistent-node",
                "household_id": "00000000-0000-0000-0000-000000000000",
            },
            headers=_app_headers(app_client_creds),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["valid"] is False
        assert "not found" in body["reason"]
