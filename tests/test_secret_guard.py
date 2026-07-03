"""Boot-time guard on placeholder/weak auth secrets.

Policy (P2.3): warn everywhere, but only ABORT startup when JARVIS_ENV=production
— so a dev/self-host box still boots on a not-yet-hardened default, while prod
refuses to run with a forgeable AUTH_SECRET_KEY or a publicly-known admin token.
"""
import logging

import pytest

from jarvis_auth.app.core.settings import Settings, enforce_secret_security

STRONG = "x" * 40
ADMIN_STRONG = "z" * 40


def _settings(**overrides) -> Settings:
    base = {
        "AUTH_SECRET_KEY": STRONG,
        "DATABASE_URL": "sqlite://",
        "JARVIS_AUTH_ADMIN_TOKEN": ADMIN_STRONG,
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)


class TestInsecureSecrets:
    def test_strong_secrets_have_no_problems(self):
        assert _settings().insecure_secrets() == []

    def test_placeholder_auth_secret_flagged(self):
        assert "AUTH_SECRET_KEY" in _settings(AUTH_SECRET_KEY="change-me").insecure_secrets()

    def test_short_admin_token_flagged(self):
        assert "JARVIS_AUTH_ADMIN_TOKEN" in _settings(JARVIS_AUTH_ADMIN_TOKEN="short").insecure_secrets()

    def test_empty_secret_flagged(self):
        assert "AUTH_SECRET_KEY" in _settings(AUTH_SECRET_KEY="").insecure_secrets()


class TestIsProduction:
    @pytest.mark.parametrize("value", ["production", "PROD", " Prod "])
    def test_production_values(self, value):
        assert _settings(JARVIS_ENV=value).is_production is True

    @pytest.mark.parametrize("value", ["development", "dev", "staging", ""])
    def test_non_production_values(self, value):
        assert _settings(JARVIS_ENV=value).is_production is False


class TestEnforce:
    def test_prod_with_weak_secret_raises(self):
        cfg = _settings(AUTH_SECRET_KEY="change-me", JARVIS_ENV="production")
        with pytest.raises(RuntimeError, match="Refusing to start in production"):
            enforce_secret_security(cfg, logging.getLogger("test"))

    def test_dev_with_weak_secret_warns_not_raises(self, caplog):
        cfg = _settings(AUTH_SECRET_KEY="change-me", JARVIS_ENV="development")
        with caplog.at_level(logging.WARNING):
            enforce_secret_security(cfg, logging.getLogger("test"))  # must not raise
        assert any("Insecure auth config" in r.message for r in caplog.records)

    def test_prod_with_strong_secrets_is_silent(self):
        cfg = _settings(JARVIS_ENV="production")
        enforce_secret_security(cfg, logging.getLogger("test"))  # no raise
