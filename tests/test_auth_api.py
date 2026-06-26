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
os.environ["REFRESH_TOKEN_GRACE_SECONDS"] = "10"
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
    from jarvis_auth.app.services import settings_service as settings_service_module
    from jarvis_auth.app.db.models import Setting
    from jarvis_settings_client import SettingsService

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[auth_router.get_db] = override_get_db
    app.dependency_overrides[deps_module.get_db] = override_get_db

    # The settings service opens its own session via SessionLocal() and closes
    # it after every read. Under the StaticPool single-connection test setup,
    # that close() issues a ROLLBACK on the *shared* connection, discarding the
    # request's pending writes (e.g. refresh-token rotation) and raising
    # StaleDataError. Bind the global service to the test session with a no-op
    # close so its reads share the request transaction instead of tearing it
    # down. In production each session gets its own pooled connection, so this
    # only matters for the test harness.
    class _NonClosingSession:
        def __init__(self, session):
            self._session = session

        def close(self):  # don't roll back the shared test transaction
            pass

        def __getattr__(self, name):
            return getattr(self._session, name)

    saved_settings_service = settings_service_module._settings_service
    settings_service_module._settings_service = SettingsService(
        definitions=settings_service_module.SETTINGS_DEFINITIONS,
        get_db_session=lambda: _NonClosingSession(db_session),
        setting_model=Setting,
    )

    yield TestClient(app)

    app.dependency_overrides.clear()
    settings_service_module._settings_service = saved_settings_service


def test_register_returns_tokens(client):
    resp = client.post("/auth/register", json={"email": "user@example.com", "password": "password123"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["access_token"]
    assert data["refresh_token"]
    assert data["token_type"] == "bearer"
    assert data["user"]["email"] == "user@example.com"


def test_register_auto_creates_household(client):
    resp = client.post("/auth/register", json={"email": "household_auto@example.com", "password": "password123"})
    assert resp.status_code == 201
    data = resp.json()
    assert "household_id" in data
    assert data["household_id"]  # non-empty

    # Verify user is admin of the auto-created household
    token = data["access_token"]
    households_resp = client.get("/households", headers={"Authorization": f"Bearer {token}"})
    assert households_resp.status_code == 200
    households = households_resp.json()
    assert len(households) == 1
    assert households[0]["name"] == "My Home"
    assert households[0]["role"] == "admin"
    assert households[0]["id"] == data["household_id"]


def test_register_joins_existing_household(client, db_session):
    from jarvis_auth.app.db import models

    # Create a household first
    household = models.Household(name="Existing Home")
    db_session.add(household)
    db_session.commit()
    db_session.refresh(household)

    resp = client.post(
        "/auth/register",
        json={"email": "household_join@example.com", "password": "password123"},
        headers={"X-Household-Id": household.id},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["household_id"] == household.id

    # Verify user is member (not admin) of the existing household
    token = data["access_token"]
    households_resp = client.get("/households", headers={"Authorization": f"Bearer {token}"})
    assert households_resp.status_code == 200
    households_list = households_resp.json()
    assert len(households_list) == 1
    assert households_list[0]["role"] == "member"


def test_register_invalid_household_id(client):
    resp = client.post(
        "/auth/register",
        json={"email": "bad_household@example.com", "password": "password123"},
        headers={"X-Household-Id": "00000000-0000-0000-0000-000000000000"},
    )
    assert resp.status_code == 400
    assert "Household not found" in resp.json()["detail"]


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


# ---------------------------------------------------------------------------
# Refresh-token rotation + reuse detection (jarvis-roadmap#5)
# ---------------------------------------------------------------------------

import logging
from datetime import datetime, timedelta, timezone

from jarvis_auth.app.db import models


def _refresh_token_row(db, plain):
    return (
        db.query(models.RefreshToken)
        .filter_by(token_hash=security.hash_refresh_token(plain))
        .one()
    )


def _register(client, email):
    resp = client.post("/auth/register", json={"email": email, "password": "password123"})
    assert resp.status_code == 201, resp.text
    return resp.json()


# Happy path -----------------------------------------------------------------


def test_refresh_rotates_returns_new_refresh_token(client):
    tokens = _register(client, "rot_happy1@example.com")
    r1 = tokens["refresh_token"]
    resp = client.post("/auth/refresh", json={"refresh_token": r1})
    assert resp.status_code == 200
    data = resp.json()
    assert data["refresh_token"]
    assert data["refresh_token"] != r1
    assert data["access_token"]
    payload = security.decode_token(data["access_token"])
    assert payload["sub"]
    assert "exp" in payload


def test_refresh_marks_old_rotated_and_chains_new(client, db_session):
    tokens = _register(client, "rot_chain@example.com")
    r1 = tokens["refresh_token"]
    resp = client.post("/auth/refresh", json={"refresh_token": r1})
    assert resp.status_code == 200
    r2 = resp.json()["refresh_token"]

    old = _refresh_token_row(db_session, r1)
    new = _refresh_token_row(db_session, r2)
    assert old.rotated_at is not None
    assert old.revoked is False
    assert new.parent_id == old.id
    assert new.family_id == old.family_id
    assert new.rotated_at is None
    assert new.revoked is False


def test_register_creates_root_token_with_family_id_and_null_parent(client, db_session):
    tokens = _register(client, "rot_root_reg@example.com")
    row = _refresh_token_row(db_session, tokens["refresh_token"])
    assert row.family_id
    assert row.parent_id is None
    assert row.rotated_at is None


def test_login_creates_root_token_with_family_id_and_null_parent(client, db_session):
    email = "rot_root_login@example.com"
    reg = _register(client, email)
    reg_row = _refresh_token_row(db_session, reg["refresh_token"])

    resp = client.post("/auth/login", json={"email": email, "password": "password123"})
    assert resp.status_code == 200
    login_row = _refresh_token_row(db_session, resp.json()["refresh_token"])
    assert login_row.parent_id is None
    assert login_row.rotated_at is None
    assert login_row.family_id != reg_row.family_id


def test_multiple_rotations_keep_same_family_id(client, db_session):
    tokens = _register(client, "rot_multi@example.com")
    r1 = tokens["refresh_token"]
    r2 = client.post("/auth/refresh", json={"refresh_token": r1}).json()["refresh_token"]
    r3 = client.post("/auth/refresh", json={"refresh_token": r2}).json()["refresh_token"]

    row1 = _refresh_token_row(db_session, r1)
    row2 = _refresh_token_row(db_session, r2)
    row3 = _refresh_token_row(db_session, r3)
    assert row1.family_id == row2.family_id == row3.family_id
    assert row1.parent_id is None
    assert row2.parent_id == row1.id
    assert row3.parent_id == row2.id
    assert row1.rotated_at is not None
    assert row2.rotated_at is not None
    assert row3.rotated_at is None


# Edge cases -----------------------------------------------------------------


def test_grace_window_returns_cached_successor(client, db_session):
    from jarvis_auth.app.core import refresh_cache

    refresh_cache.clear()
    tokens = _register(client, "rot_grace_hit@example.com")
    r1 = tokens["refresh_token"]
    r2 = client.post("/auth/refresh", json={"refresh_token": r1}).json()["refresh_token"]

    resp = client.post("/auth/refresh", json={"refresh_token": r1})
    assert resp.status_code == 200
    assert resp.json()["refresh_token"] == r2

    row1 = _refresh_token_row(db_session, r1)
    family_rows = db_session.query(models.RefreshToken).filter_by(family_id=row1.family_id).all()
    assert all(not row.revoked for row in family_rows)


def test_grace_window_cache_miss_treated_as_reuse(client, db_session):
    from jarvis_auth.app.core import refresh_cache

    refresh_cache.clear()
    tokens = _register(client, "rot_grace_miss@example.com")
    r1 = tokens["refresh_token"]
    r2 = client.post("/auth/refresh", json={"refresh_token": r1}).json()["refresh_token"]
    refresh_cache.clear()

    resp = client.post("/auth/refresh", json={"refresh_token": r1})
    assert resp.status_code == 401

    row1 = _refresh_token_row(db_session, r1)
    db_session.expire_all()
    family_rows = db_session.query(models.RefreshToken).filter_by(family_id=row1.family_id).all()
    assert family_rows
    assert all(row.revoked for row in family_rows)


def test_grace_window_expires_then_replay_revokes_family(client, db_session):
    from jarvis_auth.app.core import refresh_cache

    refresh_cache.clear()
    tokens = _register(client, "rot_grace_expired@example.com")
    r1 = tokens["refresh_token"]
    client.post("/auth/refresh", json={"refresh_token": r1})

    row1 = _refresh_token_row(db_session, r1)
    row1.rotated_at = datetime.now(timezone.utc) - timedelta(seconds=120)
    db_session.commit()

    resp = client.post("/auth/refresh", json={"refresh_token": r1})
    assert resp.status_code == 401

    db_session.expire_all()
    family_rows = db_session.query(models.RefreshToken).filter_by(family_id=row1.family_id).all()
    assert all(row.revoked for row in family_rows)


def test_family_revocation_isolated_to_one_session(client, db_session):
    from jarvis_auth.app.core import refresh_cache

    refresh_cache.clear()

    # User A: two separate families (register + login)
    a_reg = _register(client, "rot_iso_a@example.com")
    r_a1 = a_reg["refresh_token"]
    a_login = client.post(
        "/auth/login", json={"email": "rot_iso_a@example.com", "password": "password123"}
    )
    r_a2 = a_login.json()["refresh_token"]

    # User B: independent family
    b_reg = _register(client, "rot_iso_b@example.com")
    r_b1 = b_reg["refresh_token"]

    # Force reuse on user A's first family
    client.post("/auth/refresh", json={"refresh_token": r_a1})
    row_a1 = _refresh_token_row(db_session, r_a1)
    row_a1.rotated_at = datetime.now(timezone.utc) - timedelta(seconds=120)
    db_session.commit()

    bad = client.post("/auth/refresh", json={"refresh_token": r_a1})
    assert bad.status_code == 401

    db_session.expire_all()
    fam_a1 = db_session.query(models.RefreshToken).filter_by(family_id=row_a1.family_id).all()
    assert all(row.revoked for row in fam_a1)

    # Family A2 still rotates fine
    a2_resp = client.post("/auth/refresh", json={"refresh_token": r_a2})
    assert a2_resp.status_code == 200

    # User B's family still rotates fine
    b_resp = client.post("/auth/refresh", json={"refresh_token": r_b1})
    assert b_resp.status_code == 200


# Error / exception flows ----------------------------------------------------


def test_refresh_with_unknown_token_returns_401(client, db_session):
    before = db_session.query(models.RefreshToken).count()
    resp = client.post("/auth/refresh", json={"refresh_token": "totally-not-a-real-token-xyz"})
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid refresh token"
    db_session.expire_all()
    after = db_session.query(models.RefreshToken).count()
    assert before == after


def test_refresh_with_expired_token_returns_401_and_does_not_revoke_family(client, db_session):
    tokens = _register(client, "rot_expired@example.com")
    r1 = tokens["refresh_token"]
    row = _refresh_token_row(db_session, r1)
    row.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    db_session.commit()

    resp = client.post("/auth/refresh", json={"refresh_token": r1})
    assert resp.status_code == 401

    db_session.expire_all()
    fam = db_session.query(models.RefreshToken).filter_by(family_id=row.family_id).all()
    assert all(not r.revoked for r in fam)


def test_refresh_with_revoked_token_returns_401(client, db_session):
    from jarvis_auth.app.core import refresh_cache

    refresh_cache.clear()
    tokens = _register(client, "rot_revoked@example.com")
    r1 = tokens["refresh_token"]
    row = _refresh_token_row(db_session, r1)
    row.revoked = True
    db_session.commit()

    revoked_count_before = (
        db_session.query(models.RefreshToken).filter_by(family_id=row.family_id, revoked=True).count()
    )
    resp = client.post("/auth/refresh", json={"refresh_token": r1})
    assert resp.status_code == 401

    db_session.expire_all()
    revoked_count_after = (
        db_session.query(models.RefreshToken).filter_by(family_id=row.family_id, revoked=True).count()
    )
    assert revoked_count_before == revoked_count_after


def test_reuse_of_rotated_token_revokes_full_family_and_returns_401(client, db_session):
    from jarvis_auth.app.core import refresh_cache

    refresh_cache.clear()
    tokens = _register(client, "rot_reuse_chain@example.com")
    r1 = tokens["refresh_token"]
    r2 = client.post("/auth/refresh", json={"refresh_token": r1}).json()["refresh_token"]
    r3 = client.post("/auth/refresh", json={"refresh_token": r2}).json()["refresh_token"]

    row1 = _refresh_token_row(db_session, r1)
    row1.rotated_at = datetime.now(timezone.utc) - timedelta(seconds=120)
    db_session.commit()

    resp = client.post("/auth/refresh", json={"refresh_token": r1})
    assert resp.status_code == 401

    db_session.expire_all()
    fam = db_session.query(models.RefreshToken).filter_by(family_id=row1.family_id).all()
    assert len(fam) == 3
    assert all(row.revoked for row in fam)


def test_reuse_emits_structured_warning_log(client, db_session, caplog):
    from jarvis_auth.app.core import refresh_cache

    refresh_cache.clear()
    tokens = _register(client, "rot_reuse_log@example.com")
    r1 = tokens["refresh_token"]
    client.post("/auth/refresh", json={"refresh_token": r1})

    row1 = _refresh_token_row(db_session, r1)
    row1.rotated_at = datetime.now(timezone.utc) - timedelta(seconds=120)
    user_id = row1.user_id
    presented_id = row1.id
    family_id = row1.family_id
    db_session.commit()

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="jarvis_auth.app.api.auth"):
        resp = client.post("/auth/refresh", json={"refresh_token": r1})
    assert resp.status_code == 401

    matching = [r for r in caplog.records if "refresh_token_reuse_detected" in r.getMessage()]
    assert len(matching) == 1
    rec = matching[0]
    assert getattr(rec, "family_id", None) == family_id
    assert getattr(rec, "user_id", None) == user_id
    assert getattr(rec, "presented_token_id", None) == presented_id


def test_refresh_after_family_revoked_via_reuse_returns_401_for_legitimate_successor(client, db_session):
    from jarvis_auth.app.core import refresh_cache

    refresh_cache.clear()
    tokens = _register(client, "rot_legit_blocked@example.com")
    r1 = tokens["refresh_token"]
    r2 = client.post("/auth/refresh", json={"refresh_token": r1}).json()["refresh_token"]

    row1 = _refresh_token_row(db_session, r1)
    row1.rotated_at = datetime.now(timezone.utc) - timedelta(seconds=120)
    db_session.commit()

    # Trigger reuse → blows family
    bad = client.post("/auth/refresh", json={"refresh_token": r1})
    assert bad.status_code == 401

    # Legitimate successor is now also dead
    resp = client.post("/auth/refresh", json={"refresh_token": r2})
    assert resp.status_code == 401


def test_deleted_refresh_token_helpers_are_gone():
    from jarvis_auth.app.services import auth_service

    for removed in (
        "build_refresh_token",
        "store_refresh_token",
        "refresh_access_token",
        "revoke_refresh_token",
    ):
        assert not hasattr(auth_service, removed), f"Dead helper {removed!r} reintroduced on auth_service"

    for kept in ("register_user", "authenticate_user", "_get_user_household_id"):
        assert hasattr(auth_service, kept), f"Live helper {kept!r} unexpectedly missing from auth_service"


def test_dead_routes_auth_module_is_removed():
    import importlib

    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("jarvis_auth.app.api.routes.auth")


# ---------------------------------------------------------------------------
# Path (a): refresh-grace window is live DB-tunable (jarvis-roadmap#44)
# ---------------------------------------------------------------------------


def test_rotation_grace_read_through_settings_service(client, db_session):
    """The refresh-rotation read path resolves the grace window through
    get_settings_service(), NOT the @lru_cache'd pydantic Settings — so a DB
    override takes effect without a service restart.

    The env/pydantic window is fixed at 10s (set at module import). We patch the
    settings service the rotation code consults to report a much larger window
    (999s) and replay a token rotated 120s ago: under the frozen 10s cache that
    replay is reuse (401 + family revocation); if the value is sourced from the
    settings service it is a benign retry (200, cached successor, no
    revocation). The differing outcome proves the value came from the service
    and not core/settings.py.
    """
    from unittest.mock import MagicMock, patch
    from jarvis_auth.app.core import refresh_cache

    refresh_cache.clear()

    live_service = MagicMock()
    live_service.get_int.return_value = 999

    with patch("jarvis_auth.app.api.auth.get_settings_service", return_value=live_service):
        tokens = _register(client, "rot_grace_live@example.com")
        r1 = tokens["refresh_token"]
        r2 = client.post("/auth/refresh", json={"refresh_token": r1}).json()["refresh_token"]

        # Move the parent's rotation 120s into the past — far outside the 10s
        # env/pydantic window, but well inside the 999s the service reports.
        row1 = _refresh_token_row(db_session, r1)
        row1.rotated_at = datetime.now(timezone.utc) - timedelta(seconds=120)
        db_session.commit()

        resp = client.post("/auth/refresh", json={"refresh_token": r1})

    assert resp.status_code == 200
    assert resp.json()["refresh_token"] == r2
    # The rotation code actually consulted the settings service for the window.
    live_service.get_int.assert_any_call("auth.token.refresh_grace_seconds", 10)

    db_session.expire_all()
    fam = db_session.query(models.RefreshToken).filter_by(family_id=row1.family_id).all()
    assert all(not row.revoked for row in fam)

    # Inverse: a tight service-reported window treats the same lag as theft,
    # confirming the comparison is driven by the service value (not the cache).
    refresh_cache.clear()
    tight_service = MagicMock()
    tight_service.get_int.return_value = 1

    with patch("jarvis_auth.app.api.auth.get_settings_service", return_value=tight_service):
        tokens_b = _register(client, "rot_grace_tight@example.com")
        r1b = tokens_b["refresh_token"]
        client.post("/auth/refresh", json={"refresh_token": r1b})

        row1b = _refresh_token_row(db_session, r1b)
        row1b.rotated_at = datetime.now(timezone.utc) - timedelta(seconds=5)
        db_session.commit()

        resp_b = client.post("/auth/refresh", json={"refresh_token": r1b})

    assert resp_b.status_code == 401
    db_session.expire_all()
    fam_b = db_session.query(models.RefreshToken).filter_by(family_id=row1b.family_id).all()
    assert all(row.revoked for row in fam_b)

