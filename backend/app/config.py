import os
from functools import lru_cache
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables or .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database
    DATABASE_URL: str = "sqlite:///./crossborder_safeguard.db"

    # Aliyun DashScope LLM
    DASHSCOPE_API_KEY: str = ""

    # Security & Auth
    SECRET_KEY: str = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
    AES_SECRET_KEY: str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440

    # Rate Limiting & Fail-Closed
    RATE_LIMIT_PER_MINUTE: int = 10
    FAIL_CLOSED_ENABLED: bool = True

    # Offline / Replay Mode
    OFFLINE_MODE: bool = False

    # Debug flag
    DEBUG: bool = False


@lru_cache()
def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()
