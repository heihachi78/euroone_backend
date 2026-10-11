"""Tests for the database settings."""

from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from app.core.db_config import DbConfig, db_config

VALID_ENV = {
    "DB_USER": "euroone",
    "DB_PASSWORD": "s3cr3t-pass",
    "DB_NAME": "euroone_db",
}


@pytest.fixture(autouse=True)
def clean_db_env(monkeypatch: pytest.MonkeyPatch):
    """Unset the DB_* env vars: real .env / shell values must not affect these tests."""
    for key in VALID_ENV:
        monkeypatch.delenv(key, raising=False)


@pytest.fixture
def valid_env(monkeypatch: pytest.MonkeyPatch):
    """Set every env var of VALID_ENV."""
    for key, value in VALID_ENV.items():
        monkeypatch.setenv(key, value)


def load() -> DbConfig:
    """Load the settings from the env vars only, ignoring any .env file."""
    return DbConfig(_env_file=None)  # pyright: ignore[reportCallIssue]


def test_module_level_instance_is_created():
    """Importing the module creates the shared db_config instance."""
    assert isinstance(db_config, DbConfig)


@pytest.mark.usefixtures("valid_env")
def test_values_are_read_from_prefixed_env_vars():
    """Every setting is read from its DB_* env var."""
    config = load()

    assert config.user == "euroone"
    assert config.password.get_secret_value() == "s3cr3t-pass"
    assert config.name == "euroone_db"


@pytest.mark.usefixtures("valid_env")
def test_password_is_secret_and_not_leaked():
    """The password is a SecretStr and does not show up in repr, str or JSON dumps."""
    config = load()

    assert isinstance(config.password, SecretStr)
    assert "s3cr3t-pass" not in repr(config)
    assert "s3cr3t-pass" not in str(config)
    assert "s3cr3t-pass" not in config.model_dump_json()


@pytest.mark.parametrize("missing", list(VALID_ENV))
def test_missing_value_is_rejected(monkeypatch: pytest.MonkeyPatch, missing: str):
    """Loading fails if any of the DB_* settings is not set."""
    for key, value in VALID_ENV.items():
        if key != missing:
            monkeypatch.setenv(key, value)

    with pytest.raises(ValidationError) as exc_info:
        load()

    field = missing.removeprefix("DB_").lower()
    assert [(e["loc"], e["type"]) for e in exc_info.value.errors()] == [
        ((field,), "missing")
    ]


@pytest.mark.parametrize("key", list(VALID_ENV))
@pytest.mark.usefixtures("valid_env")
def test_value_shorter_than_three_chars_is_rejected(
    monkeypatch: pytest.MonkeyPatch, key: str
):
    """A value shorter than three characters is rejected for every setting."""
    monkeypatch.setenv(key, "ab")

    with pytest.raises(ValidationError) as exc_info:
        load()

    field = key.removeprefix("DB_").lower()
    errors = exc_info.value.errors()
    assert [e["loc"] for e in errors] == [(field,)]
    # SecretStr reports "too_short"/"items" instead of "string_too_short"/"characters".
    assert "at least 3" in errors[0]["msg"]


@pytest.mark.parametrize("key", list(VALID_ENV))
@pytest.mark.usefixtures("valid_env")
def test_value_of_exactly_three_chars_is_accepted(
    monkeypatch: pytest.MonkeyPatch, key: str
):
    """Three characters, the minimum length, are accepted for every setting."""
    monkeypatch.setenv(key, "abc")

    load()


def test_unprefixed_env_vars_are_not_used(monkeypatch: pytest.MonkeyPatch):
    """Env vars without the DB_ prefix are not read."""
    monkeypatch.setenv("USER", "shelluser")
    monkeypatch.setenv("PASSWORD", "shellpass")
    monkeypatch.setenv("NAME", "shellname")

    with pytest.raises(ValidationError):
        load()


def test_values_are_read_from_env_file(tmp_path: Path):
    """Every setting can come from a .env file."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "DB_USER=fileuser\nDB_PASSWORD=filepass\nDB_NAME=filedb\n", encoding="utf-8"
    )

    config = DbConfig(_env_file=env_file)  # pyright: ignore[reportCallIssue]

    assert config.user == "fileuser"
    assert config.password.get_secret_value() == "filepass"
    assert config.name == "filedb"


def test_env_var_overrides_env_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """An env var takes precedence over the same key in the .env file."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "DB_USER=fileuser\nDB_PASSWORD=filepass\nDB_NAME=filedb\n", encoding="utf-8"
    )
    monkeypatch.setenv("DB_USER", "envuser")

    config = DbConfig(_env_file=env_file)  # pyright: ignore[reportCallIssue]

    assert config.user == "envuser"
    assert config.name == "filedb"


def test_unknown_keys_in_env_file_are_ignored(tmp_path: Path):
    """Unknown keys in the .env file are ignored, even with the DB_ prefix."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "DB_USER=fileuser\nDB_PASSWORD=filepass\nDB_NAME=filedb\nDB_HOST=localhost\nAPP_TITLE=Other\n",
        encoding="utf-8",
    )

    config = DbConfig(_env_file=env_file)  # pyright: ignore[reportCallIssue]

    assert not hasattr(config, "host")
    assert set(config.model_dump()) == {"user", "password", "name"}


@pytest.mark.usefixtures("valid_env")
def test_db_url_points_to_sqlite_file_named_after_db_name():
    """db_url points to the aiosqlite file named DB_NAME in the working directory."""
    assert load().db_url == "sqlite+aiosqlite:///./euroone_db"


@pytest.mark.usefixtures("valid_env")
def test_db_url_follows_db_name(monkeypatch: pytest.MonkeyPatch):
    """Changing DB_NAME changes the file in db_url."""
    monkeypatch.setenv("DB_NAME", "other.sqlite3")

    assert load().db_url == "sqlite+aiosqlite:///./other.sqlite3"


@pytest.mark.usefixtures("valid_env")
def test_db_url_does_not_contain_credentials():
    """db_url has no user:password part, so the password cannot leak through it."""
    db_url = load().db_url
    assert "@" not in db_url
    assert "s3cr3t-pass" not in db_url
