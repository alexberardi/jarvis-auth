"""Tests for the settings service and routes.

These tests cover:
- Type coercion
- Caching behavior
- Environment variable fallback
- Settings definitions
- API routes
"""

import os
import time
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from jarvis_settings_client import SettingDefinition
from jarvis_settings_client.service import coerce_value, SettingsService
from jarvis_settings_client.types import SettingValue

from jarvis_auth.app.services.settings_service import (
    SETTINGS_DEFINITIONS,
    get_settings_service,
)


class TestSettingsDefinitions:
    """Tests for settings definitions."""

    def test_all_definitions_have_required_fields(self):
        """Test that all definitions have required fields."""
        for definition in SETTINGS_DEFINITIONS:
            assert definition.key, f"Missing key for definition"
            assert definition.category, f"Missing category for {definition.key}"
            assert definition.value_type in ("string", "int", "float", "bool", "json"), \
                f"Invalid value_type for {definition.key}: {definition.value_type}"

    def test_no_duplicate_keys(self):
        """Test that there are no duplicate keys."""
        keys = [d.key for d in SETTINGS_DEFINITIONS]
        assert len(keys) == len(set(keys)), "Duplicate keys found in SETTINGS_DEFINITIONS"

    def test_key_format(self):
        """Test that keys follow the expected format."""
        for definition in SETTINGS_DEFINITIONS:
            # Keys should be lowercase with dots
            assert "." in definition.key, f"Key should contain dots: {definition.key}"
            assert definition.key == definition.key.lower(), \
                f"Key should be lowercase: {definition.key}"

    def test_expected_settings_exist(self):
        """Test that expected auth settings are defined."""
        keys = [d.key for d in SETTINGS_DEFINITIONS]
        assert "auth.token.access_expire_minutes" in keys
        assert "auth.token.refresh_expire_days" in keys
        assert "auth.algorithm" in keys


class TestSettingsServiceCache:
    """Tests for SettingsService caching behavior."""

    @pytest.fixture
    def service(self):
        """Create a service instance for testing."""
        return SettingsService(
            definitions=SETTINGS_DEFINITIONS,
            get_db_session=lambda: None,
            setting_model=None,
        )

    def test_cache_hit(self, service):
        """Test that cached values are returned without DB query."""
        # Manually populate cache
        cache_key = service._make_cache_key("auth.token.access_expire_minutes")
        service._cache[cache_key] = SettingValue(
            value=60,
            value_type="int",
            requires_reload=False,
            is_secret=False,
            env_fallback="ACCESS_TOKEN_EXPIRE_MINUTES",
            from_db=True,
            cached_at=time.time(),
        )

        # Should return cached value without DB query
        result = service.get("auth.token.access_expire_minutes")
        assert result == 60

    def test_cache_expiry(self, service):
        """Test that expired cache entries are not used."""
        # Populate cache with expired entry
        cache_key = service._make_cache_key("auth.token.access_expire_minutes")
        service._cache[cache_key] = SettingValue(
            value=60,
            value_type="int",
            requires_reload=False,
            is_secret=False,
            env_fallback="ACCESS_TOKEN_EXPIRE_MINUTES",
            from_db=True,
            cached_at=time.time() - 120,  # 2 minutes ago (expired)
        )

        # Should fall through to env/default since cache is expired
        with patch.dict(os.environ, {"ACCESS_TOKEN_EXPIRE_MINUTES": "45"}):
            result = service.get("auth.token.access_expire_minutes")
            # Will get from env since DB is not available in test
            assert result == 45

    def test_invalidate_all(self, service):
        """Test invalidating entire cache."""
        key1_cache = service._make_cache_key("test.key1")
        key2_cache = service._make_cache_key("test.key2")

        service._cache[key1_cache] = SettingValue(
            value="value1",
            value_type="string",
            requires_reload=False,
            is_secret=False,
            env_fallback=None,
            from_db=True,
            cached_at=time.time(),
        )
        service._cache[key2_cache] = SettingValue(
            value="value2",
            value_type="string",
            requires_reload=False,
            is_secret=False,
            env_fallback=None,
            from_db=True,
            cached_at=time.time(),
        )

        service.invalidate_cache()

        assert len(service._cache) == 0


class TestSettingsServiceEnvFallback:
    """Tests for environment variable fallback."""

    @pytest.fixture
    def service(self):
        """Create a service instance for testing."""
        return SettingsService(
            definitions=SETTINGS_DEFINITIONS,
            get_db_session=lambda: None,
            setting_model=None,
        )

    def test_env_fallback_when_db_unavailable(self, service):
        """Test that env vars are used when DB is unavailable."""
        with patch.dict(os.environ, {"ACCESS_TOKEN_EXPIRE_MINUTES": "120"}):
            result = service.get("auth.token.access_expire_minutes")
            assert result == 120

    def test_default_when_no_env(self, service):
        """Test that defaults are used when no env var is set."""
        # Clear any env var
        with patch.dict(os.environ, {}, clear=True):
            result = service.get("auth.token.access_expire_minutes")
            # Should return definition default (30)
            assert result == 30

    def test_unknown_key_returns_none(self, service):
        """Test that unknown keys return None."""
        result = service.get("unknown.key")
        assert result is None

    def test_unknown_key_returns_provided_default(self, service):
        """Test that unknown keys return provided default."""
        result = service.get("unknown.key", "my_default")
        assert result == "my_default"


class TestSettingsServiceTypedGetters:
    """Tests for typed getter methods."""

    @pytest.fixture
    def service(self):
        """Create a service instance for testing."""
        return SettingsService(
            definitions=SETTINGS_DEFINITIONS,
            get_db_session=lambda: None,
            setting_model=None,
        )

    def test_get_int(self, service):
        """Test get_int method."""
        with patch.dict(os.environ, {"ACCESS_TOKEN_EXPIRE_MINUTES": "60"}):
            result = service.get_int("auth.token.access_expire_minutes", 0)
            assert result == 60
            assert isinstance(result, int)

    def test_get_str(self, service):
        """Test get_str method."""
        with patch.dict(os.environ, {"AUTH_ALGORITHM": "RS256"}):
            result = service.get_str("auth.algorithm", "")
            assert result == "RS256"
            assert isinstance(result, str)


class TestSettingsServiceListMethods:
    """Tests for listing methods."""

    @pytest.fixture
    def service(self):
        """Create a service instance for testing."""
        return SettingsService(
            definitions=SETTINGS_DEFINITIONS,
            get_db_session=lambda: None,
            setting_model=None,
        )

    def test_list_categories(self, service):
        """Test list_categories returns unique categories."""
        categories = service.list_categories()

        assert isinstance(categories, list)
        assert len(categories) > 0
        assert "auth.token" in categories
        assert "auth" in categories
        # Should be sorted
        assert categories == sorted(categories)

    def test_list_all(self, service):
        """Test list_all returns all settings."""
        settings = service.list_all()

        assert isinstance(settings, list)
        assert len(settings) == len(SETTINGS_DEFINITIONS)

        # Check structure of first setting
        first = settings[0]
        assert "key" in first
        assert "value" in first
        assert "value_type" in first
        assert "category" in first
        assert "from_db" in first

    def test_list_all_with_category_filter(self, service):
        """Test list_all with category filter."""
        settings = service.list_all(category="auth.token")

        assert all(s["category"] == "auth.token" for s in settings)
        assert len(settings) > 0


class TestSingleton:
    """Tests for singleton behavior via get_settings_service."""

    @pytest.fixture(autouse=True)
    def reset_singleton(self):
        """Reset singleton before and after each test."""
        import jarvis_auth.app.services.settings_service as ss_module
        ss_module._settings_service = None
        yield
        ss_module._settings_service = None

    def test_singleton_instance(self):
        """Test that get_settings_service returns same instance."""
        # Mock the db imports to avoid actual DB connection
        mock_setting = MagicMock()
        mock_session_local = MagicMock()

        with patch.dict("sys.modules", {
            "jarvis_auth.app.db.models": MagicMock(Setting=mock_setting),
            "jarvis_auth.app.db.session": MagicMock(SessionLocal=mock_session_local),
        }):
            with patch("jarvis_auth.app.db.models.Setting", mock_setting):
                with patch("jarvis_auth.app.db.session.SessionLocal", mock_session_local):
                    service1 = get_settings_service()
                    service2 = get_settings_service()

                    assert service1 is service2


class TestSettingsRoutes:
    """Tests for the settings API routes."""

    @pytest.fixture
    def mock_service(self):
        """Create a mock settings service."""
        service = SettingsService(
            definitions=SETTINGS_DEFINITIONS,
            get_db_session=lambda: None,
            setting_model=None,
        )
        return service

    @pytest.fixture
    def client(self, mock_service):
        """Create test client with mocked dependencies."""
        from jarvis_settings_client import create_settings_router
        from jarvis_auth.app.api.dependencies.app_auth import require_app_client

        app = FastAPI()

        # Create router with mocked auth
        async def mock_auth():
            return None

        router = create_settings_router(
            service=mock_service,
            auth_dependency=mock_auth,
        )
        app.include_router(router, prefix="/settings")

        yield TestClient(app)

    @pytest.fixture
    def unauthenticated_client(self, mock_service):
        """Create test client without auth override."""
        from jarvis_settings_client import create_settings_router
        from jarvis_auth.app.api.dependencies.app_auth import require_app_client

        app = FastAPI()

        # Use the real auth dependency which should fail without proper creds
        router = create_settings_router(
            service=mock_service,
            auth_dependency=require_app_client,
        )
        app.include_router(router, prefix="/settings")

        yield TestClient(app)

    def test_list_all_settings(self, client):
        """Test listing all settings."""
        response = client.get("/settings/")
        assert response.status_code == 200
        data = response.json()
        assert "settings" in data
        assert "total" in data
        assert data["total"] > 0

    def test_list_settings_by_category(self, client):
        """Test filtering settings by category."""
        response = client.get("/settings/?category=auth.token")
        assert response.status_code == 200
        data = response.json()
        assert all(s["category"] == "auth.token" for s in data["settings"])

    def test_list_categories(self, client):
        """Test listing categories."""
        response = client.get("/settings/categories")
        assert response.status_code == 200
        data = response.json()
        assert "categories" in data
        assert "auth.token" in data["categories"]

    def test_get_existing_setting(self, client):
        """Test getting an existing setting."""
        response = client.get("/settings/auth.token.access_expire_minutes")
        assert response.status_code == 200
        data = response.json()
        assert data["key"] == "auth.token.access_expire_minutes"
        assert "value" in data
        assert "value_type" in data

    def test_get_nonexistent_setting(self, client):
        """Test getting a nonexistent setting returns 404."""
        response = client.get("/settings/nonexistent.setting.key")
        assert response.status_code == 404
        assert "not_found" in response.json()["detail"]["error"]["type"]

    def test_update_nonexistent_setting(self, client):
        """Test updating a nonexistent setting returns 404."""
        response = client.put(
            "/settings/nonexistent.setting.key",
            json={"value": "some_value"},
        )
        assert response.status_code == 404

    def test_no_auth_returns_401(self, unauthenticated_client):
        """Test that requests without auth return 401."""
        response = unauthenticated_client.get("/settings/")
        assert response.status_code == 401
