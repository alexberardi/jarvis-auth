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

    # Deployment environment. When "production"/"prod", a weak/placeholder secret
    # is fatal at boot; otherwise it's a loud warning (so dev/self-host boxes on a
    # not-yet-hardened default still start). Set JARVIS_ENV=production in prod.
    jarvis_env: str = Field("development", alias="JARVIS_ENV")

    # Service discovery for outbound best-effort purge calls on account deletion.
    # Prefer config-service discovery; these env overrides take precedence when set.
    config_url: str | None = Field(None, alias="JARVIS_CONFIG_URL")
    command_center_url: str | None = Field(None, alias="JARVIS_COMMAND_CENTER_URL")
    notifications_url: str | None = Field(None, alias="JARVIS_NOTIFICATIONS_URL")

    @property
    def is_production(self) -> bool:
        return self.jarvis_env.strip().lower() in {"production", "prod"}

    def insecure_secrets(self) -> list[str]:
        """Names of security-critical secrets that are empty, a known placeholder,
        or too short/low-entropy to be safe. Empty list = all good.

        ``auth_secret_key`` signs/validates every JWT in the fleet and
        ``admin_token`` gates all ``/admin/*`` endpoints — a placeholder here means
        anyone can forge tokens or drive admin ops against a publicly-known value.
        """
        placeholders = {
            "", "change-me", "changeme", "change_me", "__set_me__",
            "changethis", "secret", "your-secret-key",
        }

        def _insecure(value: str | None) -> bool:
            v = (value or "").strip()
            return v.lower() in placeholders or len(v) < 16

        problems: list[str] = []
        if _insecure(self.auth_secret_key):
            problems.append("AUTH_SECRET_KEY")
        if _insecure(self.admin_token):
            problems.append("JARVIS_AUTH_ADMIN_TOKEN")
        return problems


def enforce_secret_security(cfg: "Settings", log) -> None:
    """Warn on insecure secrets everywhere; abort startup only in production."""
    problems = cfg.insecure_secrets()
    if not problems:
        return
    detail = (
        ", ".join(problems)
        + " is empty, a known placeholder, or shorter than 16 chars. Set a strong "
        "random value (e.g. `openssl rand -hex 32`)."
    )
    if cfg.is_production:
        raise RuntimeError(f"Refusing to start in production — insecure auth config: {detail}")
    # Single pre-formatted arg: the app logger (JarvisLogger) doesn't take
    # %-style args like the stdlib logger.
    log.warning(
        "⚠️  Insecure auth config: " + detail
        + "  (set JARVIS_ENV=production to make this fatal)"
    )


@lru_cache()
def get_settings() -> Settings:
    return Settings()


def reload_settings() -> Settings:
    get_settings.cache_clear()
    return get_settings()


settings = get_settings()

