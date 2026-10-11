"""Tests for the general application settings."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.app_config import AppConfig, app_config


@pytest.fixture(autouse=True)
def clean_app_env(monkeypatch: pytest.MonkeyPatch):
    """Unset APP_TITLE: real .env / shell values must not affect these tests."""
    monkeypatch.delenv("APP_TITLE", raising=False)


def load() -> AppConfig:
    """Load the settings from the env vars only, ignoring any .env file."""
    return AppConfig(_env_file=None)  # pyright: ignore[reportCallIssue]


def test_module_level_instance_is_created():
    """Importing the module creates the shared app_config instance."""
    assert isinstance(app_config, AppConfig)


def test_title_is_read_from_prefixed_env_var(monkeypatch: pytest.MonkeyPatch):
    """The title is read from APP_TITLE."""
    monkeypatch.setenv("APP_TITLE", "EuroOne API")

    assert load().title == "EuroOne API"


def test_missing_title_is_rejected():
    """Loading fails if APP_TITLE is not set."""
    with pytest.raises(ValidationError) as exc_info:
        load()

    assert [(e["loc"], e["type"]) for e in exc_info.value.errors()] == [
        (("title",), "missing")
    ]


@pytest.mark.parametrize("title", ["", "ab"])
def test_title_shorter_than_three_chars_is_rejected(
    monkeypatch: pytest.MonkeyPatch, title: str
):
    """An empty or two-character title is rejected."""
    monkeypatch.setenv("APP_TITLE", title)

    with pytest.raises(ValidationError) as exc_info:
        load()

    assert [(e["loc"], e["type"]) for e in exc_info.value.errors()] == [
        (("title",), "string_too_short")
    ]


def test_title_of_exactly_three_chars_is_accepted(monkeypatch: pytest.MonkeyPatch):
    """A title of exactly three characters, the minimum, is accepted."""
    monkeypatch.setenv("APP_TITLE", "abc")

    assert load().title == "abc"


def test_unprefixed_env_var_is_not_used(monkeypatch: pytest.MonkeyPatch):
    """A TITLE env var without the APP_ prefix is not read."""
    monkeypatch.setenv("TITLE", "Shell title")

    with pytest.raises(ValidationError):
        load()


def test_title_is_read_from_env_file(tmp_path: Path):
    """The title can come from a .env file."""
    env_file = tmp_path / ".env"
    env_file.write_text("APP_TITLE=File title\n", encoding="utf-8")

    assert AppConfig(_env_file=env_file).title == "File title"  # pyright: ignore[reportCallIssue]


def test_env_var_overrides_env_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """APP_TITLE in the environment takes precedence over the .env file."""
    env_file = tmp_path / ".env"
    env_file.write_text("APP_TITLE=File title\n", encoding="utf-8")
    monkeypatch.setenv("APP_TITLE", "Env title")

    assert AppConfig(_env_file=env_file).title == "Env title"  # pyright: ignore[reportCallIssue]


def test_unknown_keys_in_env_file_are_ignored(tmp_path: Path):
    """Unknown keys in the .env file are ignored, even with the APP_ prefix."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "APP_TITLE=File title\nAPP_DEBUG=1\nDB_NAME=other\n", encoding="utf-8"
    )

    config = AppConfig(_env_file=env_file)  # pyright: ignore[reportCallIssue]

    assert set(config.model_dump()) == {"title"}
