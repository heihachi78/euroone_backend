"""Tests for the VirusTotal API settings."""

from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from app.core.virustotal_config import VirusTotalConfig, virus_total_config

API_KEY = "k" * 64

VALID_ENV = {
    "VIRUS_TOTAL_API_KEY": API_KEY,
    "VIRUS_TOTAL_BASE_URL": "https://vt.config.test/api/v3",
    "VIRUS_TOTAL_IP_ADDRESS_REPORT_ENDPOINT": "ip_addresses",
    "VIRUS_TOTAL_TIMEOUT_SECONDS": "7.5",
}


@pytest.fixture(autouse=True)
def clean_vt_env(monkeypatch: pytest.MonkeyPatch):
    """Unset the VIRUS_TOTAL_* env vars: real .env / shell values must not affect tests."""
    for key in VALID_ENV:
        monkeypatch.delenv(key, raising=False)


@pytest.fixture
def valid_env(monkeypatch: pytest.MonkeyPatch):
    """Set every env var of VALID_ENV."""
    for key, value in VALID_ENV.items():
        monkeypatch.setenv(key, value)


def load() -> VirusTotalConfig:
    """Load the settings from the env vars only, ignoring any .env file."""
    return VirusTotalConfig(_env_file=None)  # pyright: ignore[reportCallIssue]


def field_of(key: str) -> str:
    """Map a VIRUS_TOTAL_* env var name to the name of its settings field."""
    return key.removeprefix("VIRUS_TOTAL_").lower()


def test_module_level_instance_is_created():
    """Importing the module creates the shared virus_total_config instance."""
    assert isinstance(virus_total_config, VirusTotalConfig)


@pytest.mark.usefixtures("valid_env")
def test_values_are_read_from_prefixed_env_vars():
    """Every setting is read from its VIRUS_TOTAL_* env var."""
    config = load()

    assert config.api_key.get_secret_value() == API_KEY
    assert config.base_url == "https://vt.config.test/api/v3"
    assert config.ip_address_report_endpoint == "ip_addresses"
    assert config.timeout_seconds == 7.5


@pytest.mark.usefixtures("valid_env")
def test_api_key_is_secret_and_not_leaked():
    """The API key is a SecretStr and does not show up in repr, str or JSON dumps."""
    config = load()

    assert isinstance(config.api_key, SecretStr)
    assert API_KEY not in repr(config)
    assert API_KEY not in str(config)
    assert API_KEY not in config.model_dump_json()


@pytest.mark.usefixtures("valid_env")
def test_timeout_defaults_to_10_seconds(monkeypatch: pytest.MonkeyPatch):
    """Without VIRUS_TOTAL_TIMEOUT_SECONDS the timeout is 10 seconds."""
    monkeypatch.delenv("VIRUS_TOTAL_TIMEOUT_SECONDS")

    assert load().timeout_seconds == 10


@pytest.mark.parametrize(
    "missing",
    [
        "VIRUS_TOTAL_API_KEY",
        "VIRUS_TOTAL_BASE_URL",
        "VIRUS_TOTAL_IP_ADDRESS_REPORT_ENDPOINT",
    ],
)
@pytest.mark.usefixtures("valid_env")
def test_missing_required_value_is_rejected(
    monkeypatch: pytest.MonkeyPatch, missing: str
):
    """Loading fails if the API key, the base URL or the report endpoint is not set."""
    monkeypatch.delenv(missing)

    with pytest.raises(ValidationError) as exc_info:
        load()

    assert [(e["loc"], e["type"]) for e in exc_info.value.errors()] == [
        ((field_of(missing),), "missing")
    ]


@pytest.mark.parametrize(
    ("key", "value", "error_type"),
    [
        ("VIRUS_TOTAL_API_KEY", "k" * 63, "too_short"),
        ("VIRUS_TOTAL_API_KEY", "k" * 65, "too_long"),
        ("VIRUS_TOTAL_BASE_URL", "https://a.b/c", "string_too_short"),
        ("VIRUS_TOTAL_IP_ADDRESS_REPORT_ENDPOINT", "", "string_too_short"),
        ("VIRUS_TOTAL_TIMEOUT_SECONDS", "0", "greater_than"),
        ("VIRUS_TOTAL_TIMEOUT_SECONDS", "-1", "greater_than"),
        ("VIRUS_TOTAL_TIMEOUT_SECONDS", "60.1", "less_than_equal"),
        ("VIRUS_TOTAL_TIMEOUT_SECONDS", "soon", "float_parsing"),
    ],
)
@pytest.mark.usefixtures("valid_env")
def test_invalid_value_is_rejected(
    monkeypatch: pytest.MonkeyPatch, key: str, value: str, error_type: str
):
    """An invalid value is rejected with the error of its field.

    E.g. an API key that is not 64 characters or an out of range timeout.
    """
    monkeypatch.setenv(key, value)

    with pytest.raises(ValidationError) as exc_info:
        load()

    assert [(e["loc"], e["type"]) for e in exc_info.value.errors()] == [
        ((field_of(key),), error_type)
    ]


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("VIRUS_TOTAL_BASE_URL", "https://a.b/cdef"),  # exactly 16 chars
        ("VIRUS_TOTAL_IP_ADDRESS_REPORT_ENDPOINT", "i"),
        ("VIRUS_TOTAL_TIMEOUT_SECONDS", "0.001"),
        ("VIRUS_TOTAL_TIMEOUT_SECONDS", "60"),
    ],
)
@pytest.mark.usefixtures("valid_env")
def test_boundary_value_is_accepted(
    monkeypatch: pytest.MonkeyPatch, key: str, value: str
):
    """Values right at the limits of their field are accepted."""
    monkeypatch.setenv(key, value)

    load()


def test_unprefixed_env_vars_are_not_used(monkeypatch: pytest.MonkeyPatch):
    """Env vars without the VIRUS_TOTAL_ prefix are not read."""
    monkeypatch.setenv("API_KEY", API_KEY)
    monkeypatch.setenv("BASE_URL", "https://vt.config.test/api/v3")
    monkeypatch.setenv("IP_ADDRESS_REPORT_ENDPOINT", "ip_addresses")

    with pytest.raises(ValidationError):
        load()


def test_values_are_read_from_env_file(tmp_path: Path):
    """Every setting can come from a .env file."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        f"VIRUS_TOTAL_API_KEY={API_KEY}\n"
        "VIRUS_TOTAL_BASE_URL=https://vt.file.test/api/v3\n"
        "VIRUS_TOTAL_IP_ADDRESS_REPORT_ENDPOINT=ip_addresses\n"
        "VIRUS_TOTAL_TIMEOUT_SECONDS=3\n",
        encoding="utf-8",
    )

    config = VirusTotalConfig(_env_file=env_file)  # pyright: ignore[reportCallIssue]

    assert config.api_key.get_secret_value() == API_KEY
    assert config.base_url == "https://vt.file.test/api/v3"
    assert config.ip_address_report_endpoint == "ip_addresses"
    assert config.timeout_seconds == 3


def test_env_var_overrides_env_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """An env var takes precedence over the same key in the .env file."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        f"VIRUS_TOTAL_API_KEY={API_KEY}\n"
        "VIRUS_TOTAL_BASE_URL=https://vt.file.test/api/v3\n"
        "VIRUS_TOTAL_IP_ADDRESS_REPORT_ENDPOINT=ip_addresses\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("VIRUS_TOTAL_BASE_URL", "https://vt.env.test/api/v3")

    config = VirusTotalConfig(_env_file=env_file)  # pyright: ignore[reportCallIssue]

    assert config.base_url == "https://vt.env.test/api/v3"
    assert config.ip_address_report_endpoint == "ip_addresses"


def test_unknown_keys_in_env_file_are_ignored(tmp_path: Path):
    """Unknown keys in the .env file are ignored, even with the VIRUS_TOTAL_ prefix."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        f"VIRUS_TOTAL_API_KEY={API_KEY}\n"
        "VIRUS_TOTAL_BASE_URL=https://vt.file.test/api/v3\n"
        "VIRUS_TOTAL_IP_ADDRESS_REPORT_ENDPOINT=ip_addresses\n"
        "VIRUS_TOTAL_RETRIES=3\n"
        "AI_MODEL=other\n",
        encoding="utf-8",
    )

    config = VirusTotalConfig(_env_file=env_file)  # pyright: ignore[reportCallIssue]

    assert set(config.model_dump()) == {
        "api_key",
        "base_url",
        "ip_address_report_endpoint",
        "timeout_seconds",
    }
