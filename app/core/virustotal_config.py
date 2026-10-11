"""VirusTotal API settings, loaded once at import time."""

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class VirusTotalConfig(BaseSettings):
    """VirusTotal API settings from the VIRUS_TOTAL_* env variables or the .env file.

    Raises:
        pydantic.ValidationError: On creation, if a setting is missing or invalid.
    """

    model_config = SettingsConfigDict(
        env_prefix="VIRUS_TOTAL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    api_key: SecretStr = Field(
        min_length=64,
        max_length=64,
        description="VirusTotal API v3 key",
    )
    base_url: str = Field(
        min_length=16,
        description="VirusTotal API base URL",
    )
    ip_address_report_endpoint: str = Field(
        min_length=1,
        description="VirusTotal API endpoint for ip checking",
    )
    timeout_seconds: float = Field(
        default=10,
        gt=0,
        le=60,
        description="Timeout in seconds for VirusTotal requests",
    )


virus_total_config = VirusTotalConfig()  # pyright: ignore[reportCallIssue]
