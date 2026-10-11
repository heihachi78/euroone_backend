"""Database settings, loaded once at import time."""

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class DbConfig(BaseSettings):
    """Database settings from the DB_* environment variables or the .env file.

    Raises:
        pydantic.ValidationError: On creation, if a setting is missing or invalid.
    """

    model_config = SettingsConfigDict(
        env_prefix="DB_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    user: str = Field(
        min_length=3,
        description="Database user",
    )
    password: SecretStr = Field(
        min_length=3,
        description="Database password",
    )
    name: str = Field(
        min_length=3,
        description="Database name",
    )

    @property
    def db_url(self):
        """SQLAlchemy URL of the SQLite file `name` in the working directory."""
        return f"sqlite+aiosqlite:///./{self.name}"


db_config = DbConfig()  # pyright: ignore[reportCallIssue]
