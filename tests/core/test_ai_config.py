"""Tests for the Gemini API settings."""

from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from app.core.ai_config import AiConfig, ai_config

API_KEY = "g" * 39

VALID_ENV = {
    "AI_API_KEY": API_KEY,
    "AI_MODEL": "gemini-2.5-flash",
    "AI_TIMEOUT_SECONDS": "12.5",
}


@pytest.fixture(autouse=True)
def clean_ai_env(monkeypatch: pytest.MonkeyPatch):
    """Unset the AI_* env vars: real .env / shell values must not affect these tests."""
    for key in VALID_ENV:
        monkeypatch.delenv(key, raising=False)


@pytest.fixture
def valid_env(monkeypatch: pytest.MonkeyPatch):
    """Set every env var of VALID_ENV."""
    for key, value in VALID_ENV.items():
        monkeypatch.setenv(key, value)


def load() -> AiConfig:
    """Load the settings from the env vars only, ignoring any .env file."""
    return AiConfig(_env_file=None)  # pyright: ignore[reportCallIssue]


def test_module_level_instance_is_created():
    """Importing the module creates the shared ai_config instance."""
    assert isinstance(ai_config, AiConfig)


@pytest.mark.usefixtures("valid_env")
def test_values_are_read_from_prefixed_env_vars():
    """Every setting is read from its AI_* env var."""
    config = load()

    assert config.api_key.get_secret_value() == API_KEY
    assert config.model == "gemini-2.5-flash"
    assert config.timeout_seconds == 12.5


@pytest.mark.usefixtures("valid_env")
def test_api_key_is_secret_and_not_leaked():
    """The API key is a SecretStr and does not show up in repr, str or JSON dumps."""
    config = load()

    assert isinstance(config.api_key, SecretStr)
    assert API_KEY not in repr(config)
    assert API_KEY not in str(config)
    assert API_KEY not in config.model_dump_json()


@pytest.mark.usefixtures("valid_env")
def test_timeout_defaults_to_30_seconds(monkeypatch: pytest.MonkeyPatch):
    """Without AI_TIMEOUT_SECONDS the timeout is 30 seconds."""
    monkeypatch.delenv("AI_TIMEOUT_SECONDS")

    assert load().timeout_seconds == 30


@pytest.mark.parametrize("missing", ["AI_API_KEY", "AI_MODEL"])
@pytest.mark.usefixtures("valid_env")
def test_missing_required_value_is_rejected(
    monkeypatch: pytest.MonkeyPatch, missing: str
):
    """Loading fails if the API key or the model is not set."""
    monkeypatch.delenv(missing)

    with pytest.raises(ValidationError) as exc_info:
        load()

    field = missing.removeprefix("AI_").lower()
    assert [(e["loc"], e["type"]) for e in exc_info.value.errors()] == [
        ((field,), "missing")
    ]


@pytest.mark.parametrize(
    ("key", "value", "error_type"),
    [
        ("AI_API_KEY", "g" * 19, "too_short"),
        ("AI_MODEL", "", "string_too_short"),
        ("AI_TIMEOUT_SECONDS", "0", "greater_than"),
        ("AI_TIMEOUT_SECONDS", "-1", "greater_than"),
        ("AI_TIMEOUT_SECONDS", "120.1", "less_than_equal"),
        ("AI_TIMEOUT_SECONDS", "soon", "float_parsing"),
    ],
)
@pytest.mark.usefixtures("valid_env")
def test_invalid_value_is_rejected(
    monkeypatch: pytest.MonkeyPatch, key: str, value: str, error_type: str
):
    """An invalid value is rejected with the error of its field.

    E.g. a too short API key or an out of range timeout.
    """
    monkeypatch.setenv(key, value)

    with pytest.raises(ValidationError) as exc_info:
        load()

    field = key.removeprefix("AI_").lower()
    assert [(e["loc"], e["type"]) for e in exc_info.value.errors()] == [
        ((field,), error_type)
    ]


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("AI_API_KEY", "g" * 20),
        ("AI_MODEL", "m"),
        ("AI_TIMEOUT_SECONDS", "0.001"),
        ("AI_TIMEOUT_SECONDS", "120"),
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
    """Env vars without the AI_ prefix are not read."""
    monkeypatch.setenv("API_KEY", API_KEY)
    monkeypatch.setenv("MODEL", "gemini-2.5-flash")

    with pytest.raises(ValidationError):
        load()


def test_values_are_read_from_env_file(tmp_path: Path):
    """Every setting can come from a .env file."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        f"AI_API_KEY={API_KEY}\nAI_MODEL=file-model\nAI_TIMEOUT_SECONDS=9\n",
        encoding="utf-8",
    )

    config = AiConfig(_env_file=env_file)  # pyright: ignore[reportCallIssue]

    assert config.api_key.get_secret_value() == API_KEY
    assert config.model == "file-model"
    assert config.timeout_seconds == 9


def test_env_var_overrides_env_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """An env var takes precedence over the same key in the .env file."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        f"AI_API_KEY={API_KEY}\nAI_MODEL=file-model\n", encoding="utf-8"
    )
    monkeypatch.setenv("AI_MODEL", "env-model")

    config = AiConfig(_env_file=env_file)  # pyright: ignore[reportCallIssue]

    assert config.model == "env-model"
    assert config.api_key.get_secret_value() == API_KEY


def test_unknown_keys_in_env_file_are_ignored(tmp_path: Path):
    """Unknown keys in the .env file are ignored, even with the AI_ prefix."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        f"AI_API_KEY={API_KEY}\nAI_MODEL=file-model\nAI_TEMPERATURE=0.2\nDB_NAME=other\n",
        encoding="utf-8",
    )

    config = AiConfig(_env_file=env_file)  # pyright: ignore[reportCallIssue]

    assert set(config.model_dump()) == {"api_key", "model", "timeout_seconds"}
