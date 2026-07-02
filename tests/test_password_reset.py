"""Tests for the admin-driven password reset flow, change-password and logout.

Covers:
- GET  /superuser/users (list + gates)
- POST /superuser/users/{id}/temp-password (issue temp password, revoke sessions)
- POST /auth/login (temp-password flag, expiry, inactive-user rejection)
- POST /auth/change-password (verify, clear flag, revoke other sessions)
- POST /auth/logout (family / all-devices revocation, idempotency)
- Grace-cache purge: a just-rotated parent must NOT re-serve its cached
  successor after logout / change-password / admin reset.
"""

import os
import importlib
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Set env for tests before app import
os.environ["AUTH_SECRET_KEY"] = "test-secret-for-password-reset"
os.environ["AUTH_ALGORITHM"] = "HS256"
os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"] = "30"
os.environ["REFRESH_TOKEN_EXPIRE_DAYS"] = "14"
os.environ["REFRESH_TOKEN_GRACE_SECONDS"] = "10"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["JARVIS_AUTH_ADMIN_TOKEN"] = "admin-test-token"

import jarvis_auth.app.core.settings as settings_module

importlib.reload(settings_module)

from jarvis_auth.app.core import refresh_cache, security
from jarvis_auth.app.db import base, models
from jarvis_auth.app.db import session as session_module
from jarvis_auth.app.main import app
from jarvis_auth.app.services import token_revocation

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
def clean_grace_cache():
    refresh_cache.clear()
    yield
    refresh_cache.clear()


@pytest.fixture()
def regular_user(client) -> dict:
    resp = client.post(
        "/auth/register",
        json={"email": "target@example.com", "password": "password123"},
    )
    assert resp.status_code == 201
    return resp.json()


@pytest.fixture()
def superuser(client, db_session) -> dict:
    resp = client.post(
        "/auth/register",
        json={"email": "admin@example.com", "password": "password123"},
    )
    assert resp.status_code == 201
    user = db_session.query(models.User).filter(models.User.email == "admin@example.com").first()
    user.is_superuser = True
    db_session.commit()
    resp = client.post(
        "/auth/login",
        json={"email": "admin@example.com", "password": "password123"},
    )
    assert resp.status_code == 200
    return resp.json()


def _auth(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def _refresh(client, refresh_token: str):
    return client.post("/auth/refresh", json={"refresh_token": refresh_token})


def _reset(client, superuser: dict, user_id: int, body: dict | None = None):
    return client.post(
        f"/superuser/users/{user_id}/temp-password",
        json=body if body is not None else {},
        headers=_auth(superuser),
    )


# ---------------------------------------------------------------------------
# GET /superuser/users
# ---------------------------------------------------------------------------


class TestListUsers:
    def test_requires_auth(self, client):
        assert client.get("/superuser/users").status_code == 401

    def test_rejects_regular_user(self, client, regular_user):
        resp = client.get("/superuser/users", headers=_auth(regular_user))
        assert resp.status_code == 403

    def test_lists_users_with_flags_and_households(self, client, superuser, regular_user):
        resp = client.get("/superuser/users", headers=_auth(superuser))
        assert resp.status_code == 200
        by_email = {u["email"]: u for u in resp.json()}
        assert "target@example.com" in by_email
        target = by_email["target@example.com"]
        for key in ("id", "username", "is_active", "is_superuser", "must_change_password", "created_at"):
            assert key in target
        assert target["must_change_password"] is False
        # Register auto-creates "My Home" with the user as admin.
        assert len(target["households"]) == 1
        assert target["households"][0]["household_name"] == "My Home"
        assert target["households"][0]["role"] == "admin"


# ---------------------------------------------------------------------------
# POST /superuser/users/{id}/temp-password
# ---------------------------------------------------------------------------


class TestTempPassword:
    def test_requires_auth(self, client, regular_user):
        user_id = regular_user["user"]["id"]
        resp = client.post(f"/superuser/users/{user_id}/temp-password", json={})
        assert resp.status_code == 401

    def test_rejects_regular_user(self, client, regular_user):
        user_id = regular_user["user"]["id"]
        resp = client.post(
            f"/superuser/users/{user_id}/temp-password",
            json={},
            headers=_auth(regular_user),
        )
        assert resp.status_code == 403

    def test_unknown_user_404(self, client, superuser):
        assert _reset(client, superuser, 99999).status_code == 404

    def test_generates_temp_password_and_flags_user(self, client, superuser, regular_user):
        resp = _reset(client, superuser, regular_user["user"]["id"])
        assert resp.status_code == 200
        data = resp.json()
        assert data["temp_password"]
        assert data["expires_at"]
        assert data["must_change_password"] is True

        # Old password no longer works
        old = client.post(
            "/auth/login", json={"email": "target@example.com", "password": "password123"}
        )
        assert old.status_code == 401

        # Temp password logs in with the forced-change flag set
        login = client.post(
            "/auth/login",
            json={"email": "target@example.com", "password": data["temp_password"]},
        )
        assert login.status_code == 200
        body = login.json()
        assert body["must_change_password"] is True
        assert body["user"]["must_change_password"] is True

    def test_accepts_admin_supplied_password(self, client, superuser, regular_user):
        resp = _reset(
            client, superuser, regular_user["user"]["id"], {"temp_password": "custom-temp-99"}
        )
        assert resp.status_code == 200
        assert resp.json()["temp_password"] == "custom-temp-99"
        login = client.post(
            "/auth/login", json={"email": "target@example.com", "password": "custom-temp-99"}
        )
        assert login.status_code == 200

    def test_rejects_short_admin_supplied_password(self, client, superuser, regular_user):
        resp = _reset(client, superuser, regular_user["user"]["id"], {"temp_password": "short"})
        assert resp.status_code == 422

    def test_rejects_inactive_user(self, client, superuser, regular_user, db_session):
        """A temp password for a deactivated user could never be used (login
        rejects inactive) — refuse instead of returning a dud show-once secret."""
        user = db_session.query(models.User).filter_by(id=regular_user["user"]["id"]).one()
        user.is_active = False
        db_session.commit()
        resp = _reset(client, superuser, regular_user["user"]["id"])
        assert resp.status_code == 409

    def test_bodyless_post_generates_password(self, client, superuser, regular_user):
        resp = client.post(
            f"/superuser/users/{regular_user['user']['id']}/temp-password",
            headers=_auth(superuser),
        )
        assert resp.status_code == 200
        assert resp.json()["temp_password"]

    def test_honors_expires_in_hours(self, client, superuser, regular_user, db_session):
        resp = _reset(client, superuser, regular_user["user"]["id"], {"expires_in_hours": 2})
        assert resp.status_code == 200
        user = db_session.query(models.User).filter_by(id=regular_user["user"]["id"]).one()
        db_session.refresh(user)
        expires_at = user.temp_password_expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        delta = expires_at - datetime.now(timezone.utc)
        assert timedelta(hours=1, minutes=55) < delta < timedelta(hours=2, minutes=5)

    def test_revokes_existing_sessions(self, client, superuser, regular_user):
        r1 = regular_user["refresh_token"]
        assert _refresh(client, r1).status_code == 200  # sanity: session alive
        # Re-login to get a fresh live token, then reset.
        live = client.post(
            "/auth/login", json={"email": "target@example.com", "password": "password123"}
        ).json()["refresh_token"]
        assert _reset(client, superuser, regular_user["user"]["id"]).status_code == 200
        assert _refresh(client, live).status_code == 401

    def test_default_expiry_is_24h(self, client, superuser, regular_user, db_session):
        assert _reset(client, superuser, regular_user["user"]["id"]).status_code == 200
        user = db_session.query(models.User).filter_by(id=regular_user["user"]["id"]).one()
        db_session.refresh(user)
        expires_at = user.temp_password_expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        delta = expires_at - datetime.now(timezone.utc)
        assert timedelta(hours=23, minutes=55) < delta < timedelta(hours=24, minutes=5)


# ---------------------------------------------------------------------------
# Login guards
# ---------------------------------------------------------------------------


class TestLoginGuards:
    def test_expired_temp_password_rejected(self, client, superuser, regular_user, db_session):
        resp = _reset(client, superuser, regular_user["user"]["id"])
        temp = resp.json()["temp_password"]
        user = db_session.query(models.User).filter_by(id=regular_user["user"]["id"]).one()
        user.temp_password_expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        db_session.commit()

        login = client.post(
            "/auth/login", json={"email": "target@example.com", "password": temp}
        )
        assert login.status_code == 401
        assert "Temporary password expired" in login.json()["detail"]

    def test_inactive_user_rejected_with_generic_message(self, client, regular_user, db_session):
        user = db_session.query(models.User).filter_by(id=regular_user["user"]["id"]).one()
        user.is_active = False
        db_session.commit()

        login = client.post(
            "/auth/login", json={"email": "target@example.com", "password": "password123"}
        )
        assert login.status_code == 401
        assert login.json()["detail"] == "Invalid email or password"

    def test_normal_login_reports_flag_false(self, client, regular_user):
        login = client.post(
            "/auth/login", json={"email": "target@example.com", "password": "password123"}
        )
        assert login.status_code == 200
        assert login.json()["must_change_password"] is False

    def test_inactive_user_cannot_refresh(self, client, regular_user, db_session):
        """Deactivation must also stop token rotation, or a live session
        outlasts the lockout indefinitely on its 14-day sliding window."""
        r1 = regular_user["refresh_token"]
        user = db_session.query(models.User).filter_by(id=regular_user["user"]["id"]).one()
        user.is_active = False
        db_session.commit()
        resp = _refresh(client, r1)
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid refresh token"

    def test_expired_temp_password_cannot_refresh(self, client, superuser, regular_user, db_session):
        """The TEMP_PASSWORD_EXPIRE_HOURS bound must hold for sessions opened
        inside the window, not just new logins."""
        temp = _reset(client, superuser, regular_user["user"]["id"]).json()["temp_password"]
        login = client.post(
            "/auth/login", json={"email": "target@example.com", "password": temp}
        )
        assert login.status_code == 200

        user = db_session.query(models.User).filter_by(id=regular_user["user"]["id"]).one()
        user.temp_password_expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        db_session.commit()

        resp = _refresh(client, login.json()["refresh_token"])
        assert resp.status_code == 401
        assert "Temporary password expired" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# POST /auth/change-password
# ---------------------------------------------------------------------------


class TestChangePassword:
    def test_requires_auth(self, client):
        resp = client.post(
            "/auth/change-password",
            json={"current_password": "x" * 8, "new_password": "y" * 8},
        )
        assert resp.status_code == 401

    def test_wrong_current_password(self, client, regular_user):
        resp = client.post(
            "/auth/change-password",
            json={"current_password": "wrong-password", "new_password": "newpassword456"},
            headers=_auth(regular_user),
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Incorrect password"

    def test_new_must_differ_from_current(self, client, regular_user):
        resp = client.post(
            "/auth/change-password",
            json={"current_password": "password123", "new_password": "password123"},
            headers=_auth(regular_user),
        )
        assert resp.status_code == 400

    def test_new_password_min_length(self, client, regular_user):
        resp = client.post(
            "/auth/change-password",
            json={"current_password": "password123", "new_password": "short"},
            headers=_auth(regular_user),
        )
        assert resp.status_code == 422

    def test_success_swaps_password_and_revokes_other_sessions(self, client, regular_user):
        old_refresh = regular_user["refresh_token"]
        resp = client.post(
            "/auth/change-password",
            json={"current_password": "password123", "new_password": "newpassword456"},
            headers=_auth(regular_user),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["must_change_password"] is False
        assert data["user"]["must_change_password"] is False

        # Every pre-change session is dead; the returned pair is live.
        assert _refresh(client, old_refresh).status_code == 401
        assert _refresh(client, data["refresh_token"]).status_code == 200
        me = client.get("/auth/me", headers={"Authorization": f"Bearer {data['access_token']}"})
        assert me.status_code == 200

        # Old password rejected, new accepted.
        assert (
            client.post(
                "/auth/login", json={"email": "target@example.com", "password": "password123"}
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/auth/login", json={"email": "target@example.com", "password": "newpassword456"}
            ).status_code
            == 200
        )


# ---------------------------------------------------------------------------
# Full temp-password flow (admin reset → temp login → forced change)
# ---------------------------------------------------------------------------


class TestFullResetFlow:
    def test_end_to_end(self, client, superuser, regular_user):
        user_id = regular_user["user"]["id"]

        temp = _reset(client, superuser, user_id).json()["temp_password"]

        login = client.post(
            "/auth/login", json={"email": "target@example.com", "password": temp}
        )
        assert login.status_code == 200
        assert login.json()["must_change_password"] is True

        # A background refresh must keep reporting the flag (rotate path) —
        # mobile refreshes on a timer and refresh-time state overwrites
        # login-time state in the client.
        rotated = _refresh(client, login.json()["refresh_token"])
        assert rotated.status_code == 200
        assert rotated.json()["must_change_password"] is True
        # ...and so must a grace-window replay (cache-hit path).
        replay = _refresh(client, login.json()["refresh_token"])
        assert replay.status_code == 200
        assert replay.json()["must_change_password"] is True

        change = client.post(
            "/auth/change-password",
            json={"current_password": temp, "new_password": "brand-new-pass-1"},
            headers=_auth(login.json()),
        )
        assert change.status_code == 200
        assert change.json()["must_change_password"] is False

        # The flag stays cleared through refresh after the change.
        refreshed = _refresh(client, change.json()["refresh_token"])
        assert refreshed.status_code == 200
        assert refreshed.json()["must_change_password"] is False

        # Temp password is single-use: dead after the change.
        assert (
            client.post(
                "/auth/login", json={"email": "target@example.com", "password": temp}
            ).status_code
            == 401
        )
        relogin = client.post(
            "/auth/login", json={"email": "target@example.com", "password": "brand-new-pass-1"}
        )
        assert relogin.status_code == 200
        assert relogin.json()["must_change_password"] is False


# ---------------------------------------------------------------------------
# POST /auth/logout
# ---------------------------------------------------------------------------


class TestLogout:
    def test_unknown_token_is_silent_204(self, client):
        resp = client.post("/auth/logout", json={"refresh_token": "not-a-real-token"})
        assert resp.status_code == 204

    def test_logout_is_idempotent(self, client, regular_user):
        r1 = regular_user["refresh_token"]
        assert client.post("/auth/logout", json={"refresh_token": r1}).status_code == 204
        assert client.post("/auth/logout", json={"refresh_token": r1}).status_code == 204

    def test_revokes_own_family_only(self, client, regular_user):
        device_a = regular_user["refresh_token"]
        device_b = client.post(
            "/auth/login", json={"email": "target@example.com", "password": "password123"}
        ).json()["refresh_token"]

        assert client.post("/auth/logout", json={"refresh_token": device_a}).status_code == 204
        assert _refresh(client, device_a).status_code == 401
        assert _refresh(client, device_b).status_code == 200

    def test_all_devices_revokes_everything(self, client, regular_user):
        device_a = regular_user["refresh_token"]
        device_b = client.post(
            "/auth/login", json={"email": "target@example.com", "password": "password123"}
        ).json()["refresh_token"]

        resp = client.post(
            "/auth/logout", json={"refresh_token": device_a, "all_devices": True}
        )
        assert resp.status_code == 204
        assert _refresh(client, device_a).status_code == 401
        assert _refresh(client, device_b).status_code == 401

    def test_revokes_whole_rotation_chain(self, client, regular_user, db_session):
        r1 = regular_user["refresh_token"]
        r2 = _refresh(client, r1).json()["refresh_token"]

        assert client.post("/auth/logout", json={"refresh_token": r2}).status_code == 204
        row = (
            db_session.query(models.RefreshToken)
            .filter_by(token_hash=security.hash_refresh_token(r1))
            .one()
        )
        db_session.expire_all()
        family = db_session.query(models.RefreshToken).filter_by(family_id=row.family_id).all()
        assert len(family) == 2
        assert all(r.revoked for r in family)


# ---------------------------------------------------------------------------
# Grace-cache purge: revocation must also kill the in-process successor cache
# ---------------------------------------------------------------------------


class TestGraceCachePurge:
    @pytest.fixture(autouse=True)
    def pin_grace_settings(self, monkeypatch):
        # Under full-suite runs auth.py holds the Settings object built by the
        # alphabetically-first test module, not this file's env block — pin the
        # values these tests depend on through the reference auth.py uses.
        monkeypatch.setattr("jarvis_auth.app.api.auth.settings.refresh_token_grace_seconds", 10)
        monkeypatch.setattr(
            "jarvis_auth.app.api.auth.settings.refresh_token_revoke_family_on_reuse", False
        )

    def test_logout_blocks_grace_replay(self, client, regular_user):
        r1 = regular_user["refresh_token"]
        rotated = _refresh(client, r1)
        assert rotated.status_code == 200
        r2 = rotated.json()["refresh_token"]
        # r1 is inside its grace window: without logout it would re-serve r2.
        assert client.post("/auth/logout", json={"refresh_token": r2}).status_code == 204
        assert _refresh(client, r1).status_code == 401

    def test_change_password_blocks_grace_replay(self, client, regular_user):
        r1 = regular_user["refresh_token"]
        rotated = _refresh(client, r1)
        assert rotated.status_code == 200
        resp = client.post(
            "/auth/change-password",
            json={"current_password": "password123", "new_password": "newpassword456"},
            headers={"Authorization": f"Bearer {rotated.json()['access_token']}"},
        )
        assert resp.status_code == 200
        assert _refresh(client, r1).status_code == 401

    def test_admin_reset_blocks_grace_replay(self, client, superuser, regular_user):
        r1 = regular_user["refresh_token"]
        assert _refresh(client, r1).status_code == 200
        assert _reset(client, superuser, regular_user["user"]["id"]).status_code == 200
        assert _refresh(client, r1).status_code == 401

    def test_revoked_family_never_serves_cached_successor(self, client, regular_user, db_session):
        """Pins the grace branch's `not record.revoked` check directly: even
        with the successor still sitting in the cache (as after the strict
        on-reuse nuke, or a racing refresh re-populating it post-purge), a
        revoked family must not serve it."""
        r1 = regular_user["refresh_token"]
        assert _refresh(client, r1).status_code == 200
        row = (
            db_session.query(models.RefreshToken)
            .filter_by(token_hash=security.hash_refresh_token(r1))
            .one()
        )
        # Revoke in the DB WITHOUT purging the cache.
        db_session.query(models.RefreshToken).filter_by(family_id=row.family_id).update(
            {"revoked": True}
        )
        db_session.commit()
        assert refresh_cache.get(row.id) is not None  # successor really is cached
        assert _refresh(client, r1).status_code == 401

    def test_revocation_purges_cache_entries(self, client, regular_user, db_session):
        """Pins the purge itself (unit level — the API path above is also
        protected by the revoked check, which would shadow a purge regression)."""
        r1 = regular_user["refresh_token"]
        assert _refresh(client, r1).status_code == 200
        row = (
            db_session.query(models.RefreshToken)
            .filter_by(token_hash=security.hash_refresh_token(r1))
            .one()
        )
        assert refresh_cache.get(row.id) is not None
        token_revocation.revoke_user_refresh_tokens(db_session, row.user_id)
        db_session.commit()
        assert refresh_cache.get(row.id) is None

    def test_grace_window_still_works_without_revocation(self, client, regular_user):
        """Control: the benign double-submit grace path is untouched."""
        r1 = regular_user["refresh_token"]
        r2 = _refresh(client, r1).json()["refresh_token"]
        resp = _refresh(client, r1)
        assert resp.status_code == 200
        assert resp.json()["refresh_token"] == r2


# ---------------------------------------------------------------------------
# Temp password generator + dependency wiring regressions
# ---------------------------------------------------------------------------


class TestGenerateTempPassword:
    def test_shape_and_alphabet(self):
        for _ in range(50):
            p = security.generate_temp_password()
            assert len(p) >= 8
            groups = p.split("-")
            assert len(groups) == 3
            assert all(len(g) == 4 for g in groups)
            # The ambiguity promise: relayed verbally / retyped from a screen.
            assert not set("".join(groups)) & set("0O1lI5S8B")


def test_auth_get_db_is_deps_get_db():
    """get_current_user resolves deps.get_db; if auth.py ever grows its own
    get_db again, FastAPI's per-request dependency cache splits into TWO
    sessions and endpoints that mutate current_user (change-password) commit
    the wrong one — the mutation is silently rolled back in production while
    this suite stays green (fixtures override both with one session)."""
    from jarvis_auth.app.api import auth as auth_module
    from jarvis_auth.app.api import deps as deps_module

    assert auth_module.get_db is deps_module.get_db
