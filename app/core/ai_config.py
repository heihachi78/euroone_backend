"""Gemini API settings, loaded once at import time."""

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class AiConfig(BaseSettings):
    """Gemini API settings from the AI_* environment variables or the .env file.

    Raises:
        pydantic.ValidationError: On creation, if a setting is missing or invalid.
    """

    model_config = SettingsConfigDict(
        env_prefix="AI_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    api_key: SecretStr = Field(
        min_length=20,
        description="Google Gemini API key",
    )
    model: str = Field(
        min_length=1,
        description="Gemini model name, e.g. gemini-2.5-flash",
    )
    timeout_seconds: float = Field(
        default=30,
        gt=0,
        le=120,
        description="Timeout in seconds for Gemini requests",
    )


ai_config = AiConfig()  # pyright: ignore[reportCallIssue]
