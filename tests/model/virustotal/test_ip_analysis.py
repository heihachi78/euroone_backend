"""Tests for the IP address analysis response model."""

from ipaddress import IPv4Address, IPv6Address
from typing import Any

import pytest
from pydantic import ValidationError

from app.models.virustotal.ip_analysis import IpAnalysis

IP = IPv4Address("8.8.8.8")

SUMMARY = "8.8.8.8 is Google Public DNS, no engine flags it as malicious."


def test_valid_analysis_is_accepted():
    """An analysis with an IP address and a summary is accepted."""
    analysis = IpAnalysis(ip=IP, summary=SUMMARY)

    assert analysis.ip == IP
    assert analysis.summary == SUMMARY


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("8.8.8.8", IPv4Address("8.8.8.8")),
        ("2001:4860:4860::8888", IPv6Address("2001:4860:4860::8888")),
    ],
)
def test_ip_string_is_parsed_to_address(
    value: str, expected: IPv4Address | IPv6Address
):
    """An IPv4 or IPv6 string is parsed into an address object."""
    assert IpAnalysis.model_validate({"ip": value, "summary": SUMMARY}).ip == expected


def test_serializes_to_ip_and_summary():
    """The JSON dump has just the IP as a string and the summary."""
    assert IpAnalysis(ip=IP, summary=SUMMARY).model_dump(mode="json") == {
        "ip": "8.8.8.8",
        "summary": SUMMARY,
    }


@pytest.mark.parametrize("missing", ["ip", "summary"])
def test_missing_field_is_rejected(missing: str):
    """Both the IP and the summary are required."""
    payload: dict[str, Any] = {"ip": IP, "summary": SUMMARY}
    del payload[missing]

    with pytest.raises(ValidationError) as exc_info:
        IpAnalysis.model_validate(payload)

    assert [(e["loc"], e["type"]) for e in exc_info.value.errors()] == [
        ((missing,), "missing")
    ]


@pytest.mark.parametrize(
    ("field", "value", "error_type"),
    [
        ("ip", "not-an-ip", "ip_any_address"),
        ("ip", None, "ip_any_address"),
        ("ip", [IP], "ip_any_address"),
        ("summary", None, "string_type"),
        ("summary", 42, "string_type"),
        ("summary", [SUMMARY], "string_type"),
    ],
)
def test_invalid_field_is_rejected(field: str, value: Any, error_type: str):
    """An IP that is not an address or a summary that is not a string is rejected."""
    payload: dict[str, Any] = {"ip": IP, "summary": SUMMARY}
    payload[field] = value

    with pytest.raises(ValidationError) as exc_info:
        IpAnalysis.model_validate(payload)

    assert [(e["loc"], e["type"]) for e in exc_info.value.errors()] == [
        ((field,), error_type)
    ]
