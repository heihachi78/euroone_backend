"""Tests for the IP address request model."""

from ipaddress import IPv4Address, IPv6Address

import pytest
from pydantic import ValidationError

from app.models.virustotal.ip import Ip


@pytest.mark.parametrize("value", ["8.8.8.8", "1.1.1.1"])
def test_public_ipv4_is_accepted(value: str):
    """A public IPv4 address is accepted."""
    assert Ip.model_validate({"ip": value}).ip == IPv4Address(value)


def test_public_ipv6_is_accepted():
    """A public IPv6 address is accepted."""
    assert Ip.model_validate({"ip": "2001:4860:4860::8888"}).ip == IPv6Address(
        "2001:4860:4860::8888"
    )


def test_ipv4_mapped_ipv6_is_converted_to_ipv4():
    """An IPv4-mapped IPv6 address is converted to plain IPv4."""
    assert Ip.model_validate({"ip": "::ffff:8.8.8.8"}).ip == IPv4Address("8.8.8.8")


@pytest.mark.parametrize(
    "value",
    [
        "10.0.0.1",  # private
        "192.168.1.1",  # private
        "127.0.0.1",  # loopback
        "169.254.1.1",  # link-local
        "100.64.0.1",  # carrier-grade NAT
        "::1",  # IPv6 loopback
        "fe80::1",  # IPv6 link-local
        "::ffff:10.0.0.1",  # IPv4-mapped private
    ],
)
def test_non_global_ip_is_rejected(value: str):
    """Private, loopback, link-local and other non-public addresses are rejected."""
    with pytest.raises(ValidationError, match="must be a public unicast address"):
        Ip.model_validate({"ip": value})


@pytest.mark.parametrize("value", ["224.0.1.1", "ff0e::101"])
def test_global_multicast_ip_is_rejected(value: str):
    """Multicast addresses are rejected, even globally routable ones."""
    with pytest.raises(ValidationError, match="must be a public unicast address"):
        Ip.model_validate({"ip": value})


def test_ipv6_with_scope_id_is_rejected():
    """An IPv6 address with a scope ID (e.g. %eth0) is rejected."""
    with pytest.raises(ValidationError, match="must not contain a scope ID"):
        Ip.model_validate({"ip": "2001:4860:4860::8888%eth0"})


@pytest.mark.parametrize("value", ["not-an-ip", "999.1.1.1", ""])
def test_malformed_ip_is_rejected(value: str):
    """A string that is not an IP address is rejected."""
    with pytest.raises(ValidationError, match="not a valid IPv4 or IPv6 address"):
        Ip.model_validate({"ip": value})
