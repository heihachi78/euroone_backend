"""Tests for the VirusTotal IP address report model."""

from typing import Any

import pytest
from pydantic import ValidationError

from app.models.virustotal.ip_report import IpReport

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


def test_valid_report_is_accepted():
    """A report with a status code and a data dict is accepted."""
    report = IpReport(status_code=200, data=VT_DATA)

    assert report.status_code == 200
    assert report.data == VT_DATA


def test_nested_data_is_kept_unchanged():
    """The nested VirusTotal data survives validation and dumping unchanged."""
    report = IpReport.model_validate({"status_code": 200, "data": VT_DATA})

    assert report.model_dump() == {"status_code": 200, "data": VT_DATA}


def test_empty_data_is_accepted():
    """An empty data dict is accepted."""
    assert IpReport(status_code=200, data={}).data == {}


def test_numeric_string_status_code_is_coerced_to_int():
    """A numeric string status code is converted to int."""
    assert (
        IpReport.model_validate({"status_code": "200", "data": {}}).status_code == 200
    )


@pytest.mark.parametrize("missing", ["status_code", "data"])
def test_missing_field_is_rejected(missing: str):
    """Both the status code and the data are required."""
    payload: dict[str, Any] = {"status_code": 200, "data": VT_DATA}
    del payload[missing]

    with pytest.raises(ValidationError) as exc_info:
        IpReport.model_validate(payload)

    assert [(e["loc"], e["type"]) for e in exc_info.value.errors()] == [
        ((missing,), "missing")
    ]


@pytest.mark.parametrize("status_code", ["ok", 200.5, None])
def test_non_integer_status_code_is_rejected(status_code: Any):
    """A status code that is not an integer is rejected."""
    with pytest.raises(ValidationError) as exc_info:
        IpReport.model_validate({"status_code": status_code, "data": {}})

    assert [e["loc"] for e in exc_info.value.errors()] == [("status_code",)]


@pytest.mark.parametrize("data", [[VT_DATA], "not-a-dict", None, 42])
def test_non_dict_data_is_rejected(data: Any):
    """Data that is not a dict, e.g. a list or None, is rejected."""
    with pytest.raises(ValidationError) as exc_info:
        IpReport.model_validate({"status_code": 200, "data": data})

    assert [(e["loc"], e["type"]) for e in exc_info.value.errors()] == [
        (("data",), "dict_type")
    ]
