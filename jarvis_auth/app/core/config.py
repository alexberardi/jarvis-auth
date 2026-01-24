from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,  # allow STANDARD_UPPERCASE env vars
        extra="ignore",  # ignore unrelated env keys
    )

    secret_key: str = "changeme"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    algorithm: str = "HS256"
    database_url: str = "sqlite:///./test.db"
    postgres_user: str = "postgres"
    postgres_password: str = "postgres"
    postgres_db: str = "jarvis_auth_db"


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

