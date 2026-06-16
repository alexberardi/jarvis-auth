import importlib
import os
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Set env for tests before app import
os.environ["AUTH_SECRET_KEY"] = "test-secret"
os.environ["AUTH_ALGORITHM"] = "HS256"
os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"] = "30"
os.environ["REFRESH_TOKEN_EXPIRE_DAYS"] = "14"
os.environ["REFRESH_TOKEN_GRACE_SECONDS"] = "10"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["JARVIS_AUTH_ADMIN_TOKEN"] = "admin-test-token"

import jarvis_auth.app.core.settings as settings_module

importlib.reload(settings_module)

from jarvis_auth.app.core.security import hash_password
from jarvis_auth.app.db import base
from jarvis_auth.app.db import models
from jarvis_auth.app.db import session as session_module
from jarvis_auth.app.db.models import HouseholdRole
from jarvis_auth.app.main import app

session_module.engine = create_engine(
    settings_module.settings.database_url,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
session_module.SessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=session_module.engine
)

engine = session_module.engine
TestingSessionLocal = session_module.SessionLocal


# SQLite leaves FK enforcement off by default, so ON DELETE SET NULL / CASCADE
# never fire — mirror Postgres (prod) behavior so the audit-pointer SET NULL and
# refresh-token CASCADE invariants are actually exercised.
@event.listens_for(engine, "connect")
def _enable_sqlite_fk(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


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


@pytest.fixture(autouse=True)
def no_downstream(monkeypatch):
    """Default: no downstream services resolvable, so the purge is a no-op.

    Individual tests override this to assert on the fan-out. This also guards
    against any accidental real network call.
    """
    from jarvis_auth.app.core import service_config

    monkeypatch.setattr(service_config, "get_command_center_url", lambda: None)
    monkeypatch.setattr(service_config, "get_notifications_url", lambda: None)


@pytest.fixture()
def make_user(db_session):
    def _make(email: str, password: str = "password123") -> models.User:
        user = models.User(
            email=email,
            username=email.split("@")[0],
            password_hash=hash_password(password),
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        return user

    return _make


def _login(client, email: str, password: str = "password123") -> str:
    resp = client.post("/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _add_membership(
    db_session, user: models.User, role: HouseholdRole, name: str = "Home"
) -> models.Household:
    household = models.Household(name=name)
    db_session.add(household)
    db_session.flush()
    membership = models.HouseholdMembership(
        household_id=household.id, user_id=user.id, role=role
    )
    db_session.add(membership)
    db_session.commit()
    db_session.refresh(household)
    return household


def _add_member_to(
    db_session, household: models.Household, user: models.User, role: HouseholdRole
) -> None:
    """Add an existing user to an existing household (to build SHARED households
    that survive the deletion of one member)."""
    membership = models.HouseholdMembership(
        household_id=household.id, user_id=user.id, role=role
    )
    db_session.add(membership)
    db_session.commit()


# ---------------------------------------------------------------------------
# 204 success
# ---------------------------------------------------------------------------


def test_delete_me_success_removes_user_tokens_memberships_and_settings(
    client, db_session, make_user
):
    user = make_user("del_ok@example.com")
    token = _login(client, "del_ok@example.com")
    user_id = user.id

    # A non-admin membership in a SHARED household (allowed; only the membership
    # is removed, the household survives because another admin remains).
    household = _add_membership(db_session, user, HouseholdRole.MEMBER, name="Shared")
    other = make_user("del_ok_other@example.com")
    _add_member_to(db_session, household, other, HouseholdRole.ADMIN)

    # A user-scoped setting (must be purged).
    setting = models.Setting(
        key="some_pref",
        value="x",
        value_type="string",
        category="general",
        user_id=user_id,
    )
    db_session.add(setting)
    db_session.commit()

    resp = client.request(
        "DELETE", "/auth/me", json={"password": "password123"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204, resp.text
    assert resp.content == b""

    db_session.expire_all()
    assert db_session.query(models.User).filter_by(id=user_id).first() is None
    assert (
        db_session.query(models.RefreshToken).filter_by(user_id=user_id).count() == 0
    )
    assert (
        db_session.query(models.HouseholdMembership)
        .filter_by(user_id=user_id)
        .count()
        == 0
    )
    assert (
        db_session.query(models.Setting).filter_by(user_id=user_id).count() == 0
    )
    # The SHARED household survives (another admin remains).
    assert (
        db_session.query(models.Household).filter_by(id=household.id).first()
        is not None
    )


def test_delete_me_sets_authored_audit_pointers_null_not_deleted(
    client, db_session, make_user
):
    """Authored audit pointers (e.g. household_invites.created_by_user_id) are
    SET NULL on delete; the referenced rows are NOT deleted."""
    user = make_user("del_audit@example.com")
    token = _login(client, "del_audit@example.com")
    user_id = user.id

    # Non-admin membership in a SHARED household so the household (and the invite
    # below) survive; only then is the SET NULL audit-pointer behavior observable.
    household = _add_membership(db_session, user, HouseholdRole.MEMBER, name="Audit")
    other = make_user("del_audit_other@example.com")
    _add_member_to(db_session, household, other, HouseholdRole.ADMIN)

    # An invite authored by the user being deleted (created_by_user_id is a
    # SET NULL FK in models.py).
    from datetime import datetime, timedelta, timezone

    invite = models.HouseholdInvite(
        household_id=household.id,
        code="AUDIT123",
        created_by_user_id=user_id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    db_session.add(invite)
    db_session.commit()

    resp = client.request(
        "DELETE", "/auth/me", json={"password": "password123"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204, resp.text

    db_session.expire_all()
    surviving = (
        db_session.query(models.HouseholdInvite).filter_by(code="AUDIT123").first()
    )
    assert surviving is not None  # invite NOT deleted
    assert surviving.created_by_user_id is None  # pointer SET NULL


# ---------------------------------------------------------------------------
# wrong password 401
# ---------------------------------------------------------------------------


def test_delete_me_wrong_password_returns_401_and_keeps_account(
    client, db_session, make_user
):
    user = make_user("del_wrongpw@example.com")
    token = _login(client, "del_wrongpw@example.com")
    user_id = user.id

    resp = client.request(
        "DELETE", "/auth/me", json={"password": "not-the-password"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Incorrect password"

    db_session.expire_all()
    assert db_session.query(models.User).filter_by(id=user_id).first() is not None


def test_delete_me_requires_auth(client):
    resp = client.request("DELETE", "/auth/me", json={"password": "password123"})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# active-node 409
# ---------------------------------------------------------------------------


def test_delete_me_with_active_node_returns_409(client, db_session, make_user):
    user = make_user("del_node@example.com")
    token = _login(client, "del_node@example.com")
    user_id = user.id

    household = _add_membership(db_session, user, HouseholdRole.MEMBER, name="NodeHome")
    node = models.NodeRegistration(
        node_id="active-node-1",
        household_id=household.id,
        registered_by_user_id=user_id,
        node_key_hash="hash",
        name="Active Node",
        is_active=True,
    )
    db_session.add(node)
    db_session.commit()

    resp = client.request(
        "DELETE", "/auth/me", json={"password": "password123"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 409
    assert resp.json()["detail"] == "Cannot delete account with nodes registered to it"

    db_session.expire_all()
    assert db_session.query(models.User).filter_by(id=user_id).first() is not None


def test_delete_me_with_inactive_node_is_allowed(client, db_session, make_user):
    user = make_user("del_inactive_node@example.com")
    token = _login(client, "del_inactive_node@example.com")
    user_id = user.id

    # SHARED household so it (and the inactive node) survive; the node's author
    # pointer is SET NULL rather than the row being deleted.
    household = _add_membership(
        db_session, user, HouseholdRole.MEMBER, name="InactiveHome"
    )
    other = make_user("del_inactive_other@example.com")
    _add_member_to(db_session, household, other, HouseholdRole.ADMIN)
    node = models.NodeRegistration(
        node_id="inactive-node-1",
        household_id=household.id,
        registered_by_user_id=user_id,
        node_key_hash="hash",
        name="Inactive Node",
        is_active=False,
    )
    db_session.add(node)
    db_session.commit()

    resp = client.request(
        "DELETE", "/auth/me", json={"password": "password123"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204, resp.text

    db_session.expire_all()
    assert db_session.query(models.User).filter_by(id=user_id).first() is None
    # Inactive node survives with its author pointer nulled.
    surviving = (
        db_session.query(models.NodeRegistration)
        .filter_by(node_id="inactive-node-1")
        .first()
    )
    assert surviving is not None
    assert surviving.registered_by_user_id is None


# ---------------------------------------------------------------------------
# sole admin of a SHARED household -> 409 (would orphan it)
# ---------------------------------------------------------------------------


def test_delete_me_sole_admin_of_shared_household_returns_409(
    client, db_session, make_user
):
    user = make_user("del_admin@example.com")
    token = _login(client, "del_admin@example.com")
    user_id = user.id

    # Only admin, but another member remains -> deletion would orphan the household.
    household = _add_membership(
        db_session, user, HouseholdRole.ADMIN, name="AdminHome"
    )
    member = make_user("del_admin_member@example.com")
    _add_member_to(db_session, household, member, HouseholdRole.MEMBER)

    resp = client.request(
        "DELETE", "/auth/me", json={"password": "password123"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 409
    assert "only admin" in resp.json()["detail"]

    db_session.expire_all()
    # Nothing deleted: account and household both intact.
    assert db_session.query(models.User).filter_by(id=user_id).first() is not None
    assert (
        db_session.query(models.Household).filter_by(id=household.id).first()
        is not None
    )


def test_delete_me_admin_with_co_admin_of_shared_household_is_allowed(
    client, db_session, make_user
):
    """Admin of a shared household where ANOTHER admin remains can delete: the
    household keeps an admin, so it is not orphaned."""
    user = make_user("del_coadmin@example.com")
    token = _login(client, "del_coadmin@example.com")
    user_id = user.id

    household = _add_membership(
        db_session, user, HouseholdRole.ADMIN, name="CoAdminHome"
    )
    co_admin = make_user("del_coadmin_other@example.com")
    _add_member_to(db_session, household, co_admin, HouseholdRole.ADMIN)

    resp = client.request(
        "DELETE", "/auth/me", json={"password": "password123"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204, resp.text

    db_session.expire_all()
    assert db_session.query(models.User).filter_by(id=user_id).first() is None
    # Shared household survives with the co-admin.
    assert (
        db_session.query(models.Household).filter_by(id=household.id).first()
        is not None
    )
    assert (
        db_session.query(models.HouseholdMembership)
        .filter_by(user_id=user_id)
        .count()
        == 0
    )


def test_delete_me_solo_household_is_auto_deleted(client, db_session, make_user):
    """A household where the deleting user is the ONLY member is deleted with the
    account (cascading its invites/nodes), mirroring leave_household."""
    from datetime import datetime, timedelta, timezone

    user = make_user("del_solo@example.com")
    token = _login(client, "del_solo@example.com")
    user_id = user.id

    # Sole admin AND sole member -> solo household.
    household = _add_membership(
        db_session, user, HouseholdRole.ADMIN, name="SoloHome"
    )
    household_id = household.id
    invite = models.HouseholdInvite(
        household_id=household_id,
        code="SOLO123",
        created_by_user_id=user_id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    db_session.add(invite)
    db_session.commit()

    resp = client.request(
        "DELETE", "/auth/me", json={"password": "password123"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204, resp.text

    db_session.expire_all()
    assert db_session.query(models.User).filter_by(id=user_id).first() is None
    # The solo household and its invite are gone (cascade).
    assert (
        db_session.query(models.Household).filter_by(id=household_id).first() is None
    )
    assert (
        db_session.query(models.HouseholdInvite).filter_by(code="SOLO123").first()
        is None
    )


# ---------------------------------------------------------------------------
# non-admin member ALLOWED
# ---------------------------------------------------------------------------


def test_delete_me_non_admin_member_is_allowed(client, db_session, make_user):
    user = make_user("del_member@example.com")
    token = _login(client, "del_member@example.com")
    user_id = user.id

    # SHARED household (another admin remains) so it survives the member leaving.
    household = _add_membership(
        db_session, user, HouseholdRole.MEMBER, name="MemberHome"
    )
    other = make_user("del_member_other@example.com")
    _add_member_to(db_session, household, other, HouseholdRole.ADMIN)

    resp = client.request(
        "DELETE", "/auth/me", json={"password": "password123"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204, resp.text

    db_session.expire_all()
    assert db_session.query(models.User).filter_by(id=user_id).first() is None
    # Membership removed, shared household preserved.
    assert (
        db_session.query(models.HouseholdMembership)
        .filter_by(user_id=user_id)
        .count()
        == 0
    )
    assert (
        db_session.query(models.Household).filter_by(id=household.id).first()
        is not None
    )


def test_delete_me_power_user_member_is_allowed(client, db_session, make_user):
    user = make_user("del_power@example.com")
    token = _login(client, "del_power@example.com")
    user_id = user.id

    _add_membership(db_session, user, HouseholdRole.POWER_USER, name="PowerHome")

    resp = client.request(
        "DELETE", "/auth/me", json={"password": "password123"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204, resp.text
    db_session.expire_all()
    assert db_session.query(models.User).filter_by(id=user_id).first() is None


# ---------------------------------------------------------------------------
# downstream purge fan-out (httpx mocked — no real network)
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, status_code: int):
        self.status_code = status_code


def test_delete_me_forwards_bearer_token_to_both_downstream(
    client, db_session, make_user, monkeypatch
):
    from jarvis_auth.app.core import service_config
    from jarvis_auth.app.services import account_deletion

    monkeypatch.setattr(
        service_config, "get_command_center_url", lambda: "http://cc.test"
    )
    monkeypatch.setattr(
        service_config, "get_notifications_url", lambda: "http://notif.test"
    )

    make_user("del_fanout@example.com")
    token = _login(client, "del_fanout@example.com")

    calls: list[dict] = []

    def fake_request(method, url, headers=None, timeout=None):
        calls.append({"method": method, "url": url, "headers": headers or {}})
        return _FakeResponse(204)

    monkeypatch.setattr(account_deletion.httpx, "request", fake_request)

    resp = client.request(
        "DELETE", "/auth/me", json={"password": "password123"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204, resp.text

    assert [c["url"] for c in calls] == [
        "http://cc.test/api/v0/me/data",
        "http://notif.test/api/v0/me/data",
    ]
    for call in calls:
        assert call["method"] == "DELETE"
        assert call["headers"]["Authorization"] == f"Bearer {token}"


def test_delete_me_downstream_404_treated_as_success(
    client, db_session, make_user, monkeypatch
):
    from jarvis_auth.app.core import service_config
    from jarvis_auth.app.services import account_deletion

    monkeypatch.setattr(
        service_config, "get_command_center_url", lambda: "http://cc.test"
    )
    monkeypatch.setattr(service_config, "get_notifications_url", lambda: None)

    user = make_user("del_404@example.com")
    token = _login(client, "del_404@example.com")
    user_id = user.id

    monkeypatch.setattr(
        account_deletion.httpx,
        "request",
        lambda *a, **k: _FakeResponse(404),
    )

    resp = client.request(
        "DELETE", "/auth/me", json={"password": "password123"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204, resp.text
    db_session.expire_all()
    assert db_session.query(models.User).filter_by(id=user_id).first() is None


def test_delete_me_downstream_connection_error_continues(
    client, db_session, make_user, monkeypatch
):
    from jarvis_auth.app.core import service_config
    from jarvis_auth.app.services import account_deletion

    monkeypatch.setattr(
        service_config, "get_command_center_url", lambda: "http://cc.test"
    )
    monkeypatch.setattr(service_config, "get_notifications_url", lambda: None)

    user = make_user("del_connerr@example.com")
    token = _login(client, "del_connerr@example.com")
    user_id = user.id

    def boom(*a, **k):
        raise httpx.ConnectError("unreachable")

    monkeypatch.setattr(account_deletion.httpx, "request", boom)

    resp = client.request(
        "DELETE", "/auth/me", json={"password": "password123"},
        headers={"Authorization": f"Bearer {token}"},
    )
    # Best effort: unreachable downstream is skipped, deletion proceeds.
    assert resp.status_code == 204, resp.text
    db_session.expire_all()
    assert db_session.query(models.User).filter_by(id=user_id).first() is None


def test_delete_me_downstream_5xx_aborts_and_keeps_account(
    client, db_session, make_user, monkeypatch
):
    from jarvis_auth.app.core import service_config
    from jarvis_auth.app.services import account_deletion

    monkeypatch.setattr(
        service_config, "get_command_center_url", lambda: "http://cc.test"
    )
    monkeypatch.setattr(service_config, "get_notifications_url", lambda: None)

    user = make_user("del_5xx@example.com")
    token = _login(client, "del_5xx@example.com")
    user_id = user.id

    monkeypatch.setattr(
        account_deletion.httpx,
        "request",
        lambda *a, **k: _FakeResponse(500),
    )

    resp = client.request(
        "DELETE", "/auth/me", json={"password": "password123"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 502
    assert (
        resp.json()["detail"]
        == "Could not complete account deletion. Please try again."
    )

    # Nothing deleted locally.
    db_session.expire_all()
    assert db_session.query(models.User).filter_by(id=user_id).first() is not None


def test_delete_me_5xx_does_not_call_second_downstream_after_abort(
    client, db_session, make_user, monkeypatch
):
    """CC 5xx aborts before notifications is contacted (fail-fast, atomic)."""
    from jarvis_auth.app.core import service_config
    from jarvis_auth.app.services import account_deletion

    monkeypatch.setattr(
        service_config, "get_command_center_url", lambda: "http://cc.test"
    )
    monkeypatch.setattr(
        service_config, "get_notifications_url", lambda: "http://notif.test"
    )

    make_user("del_5xx_order@example.com")
    token = _login(client, "del_5xx_order@example.com")

    urls: list[str] = []

    def fake_request(method, url, headers=None, timeout=None):
        urls.append(url)
        return _FakeResponse(500)

    monkeypatch.setattr(account_deletion.httpx, "request", fake_request)

    resp = client.request(
        "DELETE", "/auth/me", json={"password": "password123"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 502
    assert urls == ["http://cc.test/api/v0/me/data"]


# ---------------------------------------------------------------------------
# service_config resolution (env override + config-service discovery)
# ---------------------------------------------------------------------------


# NOTE: these call get_service_url() directly (the `no_downstream` autouse
# fixture only patches the get_command_center_url/get_notifications_url wrappers).


def test_service_config_prefers_env_override(monkeypatch):
    from jarvis_auth.app.core import service_config
    from jarvis_auth.app.core.settings import settings as auth_settings

    monkeypatch.setattr(
        auth_settings, "command_center_url", "http://override.cc:7703"
    )
    assert (
        service_config.get_service_url(service_config.COMMAND_CENTER_SERVICE)
        == "http://override.cc:7703"
    )


def test_service_config_discovers_from_config_service(monkeypatch):
    from jarvis_auth.app.core import service_config
    from jarvis_auth.app.core.settings import settings as auth_settings

    monkeypatch.setattr(auth_settings, "notifications_url", None)
    monkeypatch.setattr(auth_settings, "config_url", "http://config.test:7700")

    class _Resp:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "services": [
                    {"name": "jarvis-notifications", "url": "http://notif.discovered:7712"},
                ]
            }

    monkeypatch.setattr(service_config.httpx, "get", lambda *a, **k: _Resp())
    assert (
        service_config.get_service_url(service_config.NOTIFICATIONS_SERVICE)
        == "http://notif.discovered:7712"
    )


def test_service_config_returns_none_when_unresolvable(monkeypatch):
    from jarvis_auth.app.core import service_config
    from jarvis_auth.app.core.settings import settings as auth_settings

    monkeypatch.setattr(auth_settings, "command_center_url", None)
    monkeypatch.setattr(auth_settings, "config_url", None)
    assert (
        service_config.get_service_url(service_config.COMMAND_CENTER_SERVICE)
        is None
    )
