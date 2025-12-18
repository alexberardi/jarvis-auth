from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore")

    auth_secret_key: str = Field(..., alias="AUTH_SECRET_KEY")
    auth_algorithm: str = Field("HS256", alias="AUTH_ALGORITHM")
    access_token_expire_minutes: int = Field(30, alias="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(14, alias="REFRESH_TOKEN_EXPIRE_DAYS")
    database_url: str = Field(..., alias="DATABASE_URL")
    admin_token: str = Field(..., alias="JARVIS_AUTH_ADMIN_TOKEN")


@lru_cache()
def get_settings() -> Settings:
    return Settings()


def reload_settings() -> Settings:
    get_settings.cache_clear()
    return get_settings()


settings = get_settings()

