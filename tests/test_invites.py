import os
import importlib
from datetime import datetime, timedelta, timezone

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
from jarvis_auth.app.db import models
from jarvis_auth.app.db.models import HouseholdRole
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


def _register_user(client: TestClient, email: str, password: str = "Password1", **kwargs) -> dict:
    resp = client.post("/auth/register", json={"email": email, "password": password, **kwargs})
    assert resp.status_code == 201, resp.json()
    return resp.json()


def _auth_headers(data: dict) -> dict:
    return {"Authorization": f"Bearer {data['access_token']}"}


def _create_household_and_admin(client: TestClient, email: str = "admin@test.com") -> tuple[dict, str]:
    """Register a user (gets a new household as admin), return (register_data, household_id)."""
    data = _register_user(client, email)
    return data, data["household_id"]


def _promote_user(db_session, user_id: int, household_id: str, role: HouseholdRole):
    """Promote a user to a specific role in a household."""
    membership = db_session.query(models.HouseholdMembership).filter(
        models.HouseholdMembership.user_id == user_id,
        models.HouseholdMembership.household_id == household_id,
    ).first()
    membership.role = role
    db_session.commit()


def _create_invite(client: TestClient, headers: dict, household_id: str, **kwargs) -> dict:
    resp = client.post(
        f"/households/{household_id}/invites",
        json={"default_role": "member", "expires_in_days": 7, **kwargs},
        headers=headers,
    )
    assert resp.status_code == 201, resp.json()
    return resp.json()


# ─── Tests ────────────────────────────────────────────────────────────────


def test_create_invite_power_user_succeeds_member_rejected(client, db_session):
    """Create invite — power_user+ succeeds, member rejected (403)."""
    admin_data, hid = _create_household_and_admin(client, "inv1_admin@test.com")

    # Admin can create
    invite = _create_invite(client, _auth_headers(admin_data), hid)
    assert len(invite["code"]) == 8
    assert invite["default_role"] == "member"

    # Register member via invite
    member_data = _register_user(client, "inv1_member@test.com", invite_code=invite["code"])

    # Member cannot create invite
    resp = client.post(
        f"/households/{hid}/invites",
        json={"default_role": "member", "expires_in_days": 7},
        headers=_auth_headers(member_data),
    )
    assert resp.status_code == 403

    # Power user can create
    _promote_user(db_session, member_data["user"]["id"], hid, HouseholdRole.POWER_USER)
    resp = client.post(
        f"/households/{hid}/invites",
        json={"default_role": "member", "expires_in_days": 7},
        headers=_auth_headers(member_data),
    )
    assert resp.status_code == 201


def test_validate_invite_valid_code(client):
    """Validate invite — valid code returns household name."""
    admin_data, hid = _create_household_and_admin(client, "val1@test.com")
    invite = _create_invite(client, _auth_headers(admin_data), hid)

    resp = client.get(f"/invites/{invite['code']}/validate")
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["household_name"] == "My Home"


def test_validate_invite_expired_revoked_maxuses(client, db_session):
    """Validate invite — expired/revoked/max-uses all return invalid."""
    admin_data, hid = _create_household_and_admin(client, "val2@test.com")

    # Expired invite
    invite = _create_invite(client, _auth_headers(admin_data), hid, expires_in_days=1)
    inv_record = db_session.query(models.HouseholdInvite).filter(
        models.HouseholdInvite.code == invite["code"]
    ).first()
    inv_record.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
    db_session.commit()
    resp = client.get(f"/invites/{invite['code']}/validate")
    assert resp.json()["valid"] is False

    # Revoked invite
    invite2 = _create_invite(client, _auth_headers(admin_data), hid)
    client.delete(f"/households/{hid}/invites/{invite2['id']}", headers=_auth_headers(admin_data))
    resp = client.get(f"/invites/{invite2['code']}/validate")
    assert resp.json()["valid"] is False

    # Max uses reached
    invite3 = _create_invite(client, _auth_headers(admin_data), hid, max_uses=1)
    inv_record3 = db_session.query(models.HouseholdInvite).filter(
        models.HouseholdInvite.code == invite3["code"]
    ).first()
    inv_record3.use_count = 1
    db_session.commit()
    resp = client.get(f"/invites/{invite3['code']}/validate")
    assert resp.json()["valid"] is False

    # Nonexistent code
    resp = client.get("/invites/ZZZZZZZZ/validate")
    assert resp.json()["valid"] is False


def test_join_household_existing_user(client):
    """Join household — existing user gets membership with correct role."""
    admin_data, hid = _create_household_and_admin(client, "join1_admin@test.com")
    invite = _create_invite(client, _auth_headers(admin_data), hid, default_role="power_user")

    # Register a second user in their own household
    user2_data = _register_user(client, "join1_user@test.com")

    resp = client.post(
        "/households/join",
        json={"invite_code": invite["code"]},
        headers=_auth_headers(user2_data),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["household_id"] == hid
    assert data["role"] == "power_user"


def test_join_household_already_member(client):
    """Join household — already a member returns 400."""
    admin_data, hid = _create_household_and_admin(client, "join2_admin@test.com")
    invite = _create_invite(client, _auth_headers(admin_data), hid)

    # Admin tries to join their own household
    resp = client.post(
        "/households/join",
        json={"invite_code": invite["code"]},
        headers=_auth_headers(admin_data),
    )
    assert resp.status_code == 400
    assert "Already a member" in resp.json()["detail"]


def test_register_with_invite_joins_household(client):
    """Register with invite — joins household instead of creating new one."""
    admin_data, hid = _create_household_and_admin(client, "reg1_admin@test.com")
    invite = _create_invite(client, _auth_headers(admin_data), hid)

    new_user = _register_user(client, "reg1_new@test.com", invite_code=invite["code"])
    assert new_user["household_id"] == hid


def test_register_without_invite_creates_household(client):
    """Register without invite — still creates new household (backward compat)."""
    data = _register_user(client, "reg2_new@test.com")
    assert data["household_id"]
    # Should be a new household, not empty
    resp = client.get("/households", headers=_auth_headers(data))
    assert resp.status_code == 200
    households = resp.json()
    assert len(households) >= 1


def test_revoke_invite(client):
    """Revoke invite — power_user+ can revoke, subsequent validate fails."""
    admin_data, hid = _create_household_and_admin(client, "rev1@test.com")
    invite = _create_invite(client, _auth_headers(admin_data), hid)

    # Validate before revoke
    resp = client.get(f"/invites/{invite['code']}/validate")
    assert resp.json()["valid"] is True

    # Revoke
    resp = client.delete(
        f"/households/{hid}/invites/{invite['id']}",
        headers=_auth_headers(admin_data),
    )
    assert resp.status_code == 204

    # Validate after revoke
    resp = client.get(f"/invites/{invite['code']}/validate")
    assert resp.json()["valid"] is False


def test_switch_household(client):
    """Switch household — returns new JWT with requested household_id."""
    admin_data, hid1 = _create_household_and_admin(client, "sw1@test.com")

    # Create second household
    resp = client.post(
        "/households",
        json={"name": "Vacation Home"},
        headers=_auth_headers(admin_data),
    )
    assert resp.status_code == 201
    hid2 = resp.json()["id"]

    # Switch to second household
    resp = client.post(
        "/auth/switch-household",
        json={"household_id": hid2},
        headers=_auth_headers(admin_data),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["household_id"] == hid2
    assert data["access_token"]


def test_switch_household_non_member(client):
    """Switch household — non-member returns 403."""
    admin_data, _ = _create_household_and_admin(client, "sw2@test.com")
    other_data, other_hid = _create_household_and_admin(client, "sw2_other@test.com")

    resp = client.post(
        "/auth/switch-household",
        json={"household_id": other_hid},
        headers=_auth_headers(admin_data),
    )
    assert resp.status_code == 403


def test_list_invites(client):
    """List invites — returns only non-revoked for the household."""
    admin_data, hid = _create_household_and_admin(client, "list1@test.com")

    inv1 = _create_invite(client, _auth_headers(admin_data), hid)
    inv2 = _create_invite(client, _auth_headers(admin_data), hid)

    # Revoke one
    client.delete(f"/households/{hid}/invites/{inv1['id']}", headers=_auth_headers(admin_data))

    resp = client.get(f"/households/{hid}/invites", headers=_auth_headers(admin_data))
    assert resp.status_code == 200
    invites = resp.json()
    codes = [i["code"] for i in invites]
    assert inv2["code"] in codes
    assert inv1["code"] not in codes


def test_invite_code_cannot_assign_admin(client):
    """Invite code can't assign admin role."""
    admin_data, hid = _create_household_and_admin(client, "noadmin@test.com")

    resp = client.post(
        f"/households/{hid}/invites",
        json={"default_role": "admin", "expires_in_days": 7},
        headers=_auth_headers(admin_data),
    )
    assert resp.status_code == 400
    assert "admin" in resp.json()["detail"].lower()
