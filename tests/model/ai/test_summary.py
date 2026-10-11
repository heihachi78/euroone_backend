"""Tests for the Gemini summary model."""

from typing import Any

import pytest
from pydantic import ValidationError

from app.models.ai.summary import Summary


def test_valid_summary_is_accepted():
    """A summary with a status code and a text is accepted."""
    summary = Summary(status_code=200, text="The IP is harmless.")

    assert summary.status_code == 200
    assert summary.text == "The IP is harmless."


def test_numeric_string_status_code_is_coerced_to_int():
    """A numeric string status code is converted to int."""
    assert (
        Summary.model_validate({"status_code": "200", "text": "ok"}).status_code == 200
    )


@pytest.mark.parametrize("missing", ["status_code", "text"])
def test_missing_field_is_rejected(missing: str):
    """Both the status code and the text are required."""
    payload: dict[str, Any] = {"status_code": 200, "text": "The IP is harmless."}
    del payload[missing]

    with pytest.raises(ValidationError) as exc_info:
        Summary.model_validate(payload)

    assert [(e["loc"], e["type"]) for e in exc_info.value.errors()] == [
        ((missing,), "missing")
    ]


@pytest.mark.parametrize("status_code", ["ok", 200.5, None])
def test_non_integer_status_code_is_rejected(status_code: Any):
    """A status code that is not an integer is rejected."""
    with pytest.raises(ValidationError) as exc_info:
        Summary.model_validate({"status_code": status_code, "text": "ok"})

    assert [e["loc"] for e in exc_info.value.errors()] == [("status_code",)]


@pytest.mark.parametrize("text", [None, 42, ["The IP is harmless."]])
def test_non_string_text_is_rejected(text: Any):
    """A text that is not a string is rejected."""
    with pytest.raises(ValidationError) as exc_info:
        Summary.model_validate({"status_code": 200, "text": text})

    assert [(e["loc"], e["type"]) for e in exc_info.value.errors()] == [
        (("text",), "string_type")
    ]
