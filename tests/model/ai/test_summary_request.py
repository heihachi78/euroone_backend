"""Tests for the Gemini summary request model."""

from typing import Any

import pytest
from pydantic import ValidationError

from app.models.ai.summary_request import SummaryRequest

VALID: dict[str, Any] = {
    "system_prompt": "You are a security analyst.",
    "user_prompt": "Summarize:",
    "payload": '{"data": {"id": "8.8.8.8"}}',
}


def test_valid_request_is_accepted():
    """A request with all three string fields is accepted as is."""
    request = SummaryRequest(**VALID)

    assert request.system_prompt == "You are a security analyst."
    assert request.user_prompt == "Summarize:"
    assert request.payload == '{"data": {"id": "8.8.8.8"}}'


def test_payload_is_kept_verbatim():
    """The payload is kept verbatim: it is not parsed or reformatted as JSON."""
    payload = '{"b": 1,  "a": [true, null]}\n'

    assert (
        SummaryRequest.model_validate({**VALID, "payload": payload}).payload == payload
    )


@pytest.mark.parametrize("missing", list(VALID))
def test_missing_field_is_rejected(missing: str):
    """Every field is required."""
    payload = {key: value for key, value in VALID.items() if key != missing}

    with pytest.raises(ValidationError) as exc_info:
        SummaryRequest.model_validate(payload)

    assert [(e["loc"], e["type"]) for e in exc_info.value.errors()] == [
        ((missing,), "missing")
    ]


@pytest.mark.parametrize("field", list(VALID))
@pytest.mark.parametrize("value", [None, 42, {"data": {}}])
def test_non_string_field_is_rejected(field: str, value: Any):
    """Every field rejects non-string values, including None and dicts."""
    with pytest.raises(ValidationError) as exc_info:
        SummaryRequest.model_validate({**VALID, field: value})

    assert [(e["loc"], e["type"]) for e in exc_info.value.errors()] == [
        ((field,), "string_type")
    ]
