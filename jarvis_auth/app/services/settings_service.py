"""Settings service for jarvis-auth.

Provides runtime configuration that can be modified without restarting.
Settings are stored in the database with fallback to environment variables.
Uses the shared jarvis-settings-client library.
"""

import logging

from jarvis_settings_client import SettingDefinition, SettingsService

logger = logging.getLogger(__name__)


# Auth settings definitions
SETTINGS_DEFINITIONS: list[SettingDefinition] = [
    SettingDefinition(
        key="auth.token.access_expire_minutes",
        category="auth.token",
        value_type="int",
        default=30,
        description="Access token expiration time in minutes",
        env_fallback="ACCESS_TOKEN_EXPIRE_MINUTES",
    ),
    SettingDefinition(
        key="auth.token.refresh_expire_days",
        category="auth.token",
        value_type="int",
        default=14,
        description="Refresh token expiration time in days",
        env_fallback="REFRESH_TOKEN_EXPIRE_DAYS",
    ),
    SettingDefinition(
        key="auth.algorithm",
        category="auth",
        value_type="string",
        default="HS256",
        description="JWT signing algorithm",
        env_fallback="AUTH_ALGORITHM",
    ),
]


# Global singleton
_settings_service: SettingsService | None = None


def get_settings_service() -> SettingsService:
    """Get the global SettingsService instance."""
    global _settings_service
    if _settings_service is None:
        from jarvis_auth.app.db.models import Setting
        from jarvis_auth.app.db.session import SessionLocal

        _settings_service = SettingsService(
            definitions=SETTINGS_DEFINITIONS,
            get_db_session=SessionLocal,
            setting_model=Setting,
        )
    return _settings_service
