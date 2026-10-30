import os
from functools import lru_cache
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables or .env file."""

    model_config = SettingsConfigDict(
        env_file=(".env", "backend/.env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database
    DATABASE_URL: str = "sqlite:///./crossborder_safeguard.db"

    # Aliyun DashScope LLM
    DASHSCOPE_API_KEY: str = ""

    # Security & Auth (Zero hardcoded secrets: load from env or generate secure random per instance)
    SECRET_KEY: str = ""
    AES_SECRET_KEY: str = ""
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440

    # Rate Limiting & Fail-Closed
    RATE_LIMIT_PER_MINUTE: int = 60
    FAIL_CLOSED_ENABLED: bool = True

    # Offline / Replay Mode
    OFFLINE_MODE: bool = False

    # Debug flag
    DEBUG: bool = False

    def model_post_init(self, __context: object) -> None:
        import secrets
        if not self.SECRET_KEY:
            self.SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
        if not self.AES_SECRET_KEY:
            self.AES_SECRET_KEY = os.environ.get("AES_SECRET_KEY") or secrets.token_hex(32)


@lru_cache()
def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()
