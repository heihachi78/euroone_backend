"""General application settings, loaded once at import time."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppConfig(BaseSettings):
    """Application settings from the APP_* environment variables or the .env file.

    Raises:
        pydantic.ValidationError: On creation, if a setting is missing or invalid.
    """

    model_config = SettingsConfigDict(
        env_prefix="APP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    title: str = Field(
        min_length=3,
        description="Application title for FastAPI",
    )


app_config = AppConfig()  # pyright: ignore[reportCallIssue]
