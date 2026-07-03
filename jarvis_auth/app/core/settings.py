from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore")

    auth_secret_key: str = Field(..., alias="AUTH_SECRET_KEY")
    auth_algorithm: str = Field("HS256", alias="AUTH_ALGORITHM")
    access_token_expire_minutes: int = Field(30, alias="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(14, alias="REFRESH_TOKEN_EXPIRE_DAYS")
    refresh_token_grace_seconds: int = Field(10, alias="REFRESH_TOKEN_GRACE_SECONDS")
    # When a rotated (ancestor) refresh token is replayed and we cannot serve a
    # cached successor, revoke the WHOLE family (strict theft-detection) only if
    # this is on. Default off: a benign replay (two client refresh paths, a lost
    # response over a flaky link, or an auth restart that wiped the in-process
    # grace cache) must NOT sign out the live session. See api/auth.py:/auth/refresh.
    refresh_token_revoke_family_on_reuse: bool = Field(
        False, alias="REFRESH_TOKEN_REVOKE_FAMILY_ON_REUSE"
    )
    temp_password_expire_hours: int = Field(24, alias="TEMP_PASSWORD_EXPIRE_HOURS")
    database_url: str = Field(..., alias="DATABASE_URL")
    admin_token: str = Field(..., alias="JARVIS_AUTH_ADMIN_TOKEN")

    # Brute-force protection for /auth/{login,register,refresh} (in-memory; auth
    # is single-worker). Two layers: a global per-IP sliding window, and a
    # per-(email, IP) failed-login lockout keyed on the pair — never email alone —
    # so an attacker can't lock the real user out from a different IP.
    auth_rate_limit_enabled: bool = Field(True, alias="AUTH_RATE_LIMIT_ENABLED")
    auth_rate_limit_ip_per_minute: int = Field(30, alias="AUTH_RATE_LIMIT_IP_PER_MINUTE")
    auth_login_max_failures: int = Field(8, alias="AUTH_LOGIN_MAX_FAILURES")
    auth_login_lockout_seconds: int = Field(900, alias="AUTH_LOGIN_LOCKOUT_SECONDS")
    # Only trust X-Forwarded-For (right-most hop) when auth sits behind a proxy
    # that sets it; default off so a direct-to-auth client can't spoof its IP.
    auth_rate_limit_trust_forwarded_for: bool = Field(
        False, alias="AUTH_RATE_LIMIT_TRUST_FORWARDED_FOR"
    )
    auth_rate_limit_max_keys: int = Field(50_000, alias="AUTH_RATE_LIMIT_MAX_KEYS")

    # Service discovery for outbound best-effort purge calls on account deletion.
    # Prefer config-service discovery; these env overrides take precedence when set.
    config_url: str | None = Field(None, alias="JARVIS_CONFIG_URL")
    command_center_url: str | None = Field(None, alias="JARVIS_COMMAND_CENTER_URL")
    notifications_url: str | None = Field(None, alias="JARVIS_NOTIFICATIONS_URL")


@lru_cache()
def get_settings() -> Settings:
    return Settings()


def reload_settings() -> Settings:
    get_settings.cache_clear()
    return get_settings()


settings = get_settings()

