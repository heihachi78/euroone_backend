"""Tests for the stored VirusTotal IP address report model."""

from ipaddress import IPv4Address
from typing import Any

import pytest
from pydantic import ValidationError

from app.models.virustotal.stored_ip_report import StoredIpReport

VT_DATA: dict[str, Any] = {
    "data": {
        "id": "8.8.8.8",
        "type": "ip_address",
        "attributes": {
            "as_owner": "GOOGLE",
            "tags": ["dns"],
            "reputation": 0,
            "whois": None,
        },
    }
}

VALID: dict[str, Any] = {"id": 1, "ip": "8.8.8.8", "status_code": 200, "data": VT_DATA}


def test_valid_report_is_accepted():
    """A stored report with id, IP, status code and data is accepted."""
    stored = StoredIpReport(
        id=1, ip=IPv4Address("8.8.8.8"), status_code=200, data=VT_DATA
    )

    assert stored.id == 1
    assert stored.ip == IPv4Address("8.8.8.8")
    assert stored.status_code == 200
    assert stored.data == VT_DATA


def test_nested_data_is_kept_unchanged():
    """Validating and dumping to JSON gives back the input unchanged."""
    assert StoredIpReport.model_validate(VALID).model_dump(mode="json") == VALID


@pytest.mark.parametrize("missing", list(VALID))
def test_missing_field_is_rejected(missing: str):
    """Every field is required."""
    payload = {key: value for key, value in VALID.items() if key != missing}

    with pytest.raises(ValidationError) as exc_info:
        StoredIpReport.model_validate(payload)

    assert [(e["loc"], e["type"]) for e in exc_info.value.errors()] == [
        ((missing,), "missing")
    ]


@pytest.mark.parametrize(
    ("field", "value", "error_type"),
    [
        ("id", "one", "int_parsing"),
        ("id", None, "int_type"),
        ("ip", None, "ip_any_address"),
        ("ip", "not-an-ip", "ip_any_address"),
        ("status_code", 200.5, "int_from_float"),
        ("data", [VT_DATA], "dict_type"),
        ("data", None, "dict_type"),
    ],
)
def test_invalid_field_is_rejected(field: str, value: Any, error_type: str):
    """A value of the wrong type is rejected with the error of its field."""
    with pytest.raises(ValidationError) as exc_info:
        StoredIpReport.model_validate({**VALID, field: value})

    assert [(e["loc"], e["type"]) for e in exc_info.value.errors()] == [
        ((field,), error_type)
    ]
