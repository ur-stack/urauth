"""Application settings — single source of truth for configuration."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="APP_")

    APP_NAME: str = "urauth Example - Task Manager"
    DATABASE_URL: str = "sqlite+aiosqlite:///./app.db"
    DEBUG: bool = False

    # Auth
    SECRET_KEY: str = "example-secret-do-not-use-in-production"
    ACCESS_TOKEN_TTL: int = 1800
    REFRESH_TOKEN_TTL: int = 86400


settings = Settings()
