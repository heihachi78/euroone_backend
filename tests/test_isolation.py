"""Guards for the test setup in conftest.py: no real credentials, no network access."""

import socket

import httpx
import pytest

from app.core.ai_config import ai_config
from app.core.db_config import db_config
from app.core.virustotal_config import virus_total_config

UNROUTABLE_IP = "192.0.2.1"  # TEST-NET-1 (RFC 5737)


def test_app_configs_use_fake_test_values_not_the_real_env_file():
    """The app settings hold the fake values of conftest.py, not the real .env."""
    assert virus_total_config.api_key.get_secret_value() == "x" * 64
    assert virus_total_config.base_url == "https://vt.example.test/api/v3"
    assert ai_config.api_key.get_secret_value() == "g" * 39
    assert ai_config.model == "gemini-test"
    assert db_config.name == "test_db.db"


def test_dns_lookup_is_blocked(block_network: type[Exception]):
    """Resolving a host name fails instead of reaching a DNS server."""
    with pytest.raises(block_network):
        socket.getaddrinfo("example.com", 443)


def test_socket_connect_is_blocked(block_network: type[Exception]):
    """Both connect and connect_ex fail instead of opening a TCP connection."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(block_network):
            sock.connect((UNROUTABLE_IP, 443))
        with pytest.raises(block_network):
            sock.connect_ex((UNROUTABLE_IP, 443))


@pytest.mark.parametrize("url", ["https://example.com", f"https://{UNROUTABLE_IP}"])
def test_sync_http_request_is_blocked(block_network: type[Exception], url: str):
    """A sync httpx request fails, whether the URL has a host name or an IP."""
    with pytest.raises(block_network):
        httpx.get(url)


@pytest.mark.anyio
async def test_async_http_request_to_host_name_is_blocked(
    block_network: type[Exception],
):
    """An async httpx request to a host name fails at the DNS lookup."""
    async with httpx.AsyncClient() as client:
        with pytest.raises(block_network):
            await client.get("https://example.com")


@pytest.mark.anyio
async def test_async_http_request_to_ip_address_is_blocked(
    block_network: type[Exception],
):
    """An async httpx request to an IP address fails at the connect.

    The error arrives wrapped in an exception group.
    """
    async with httpx.AsyncClient() as client:
        with pytest.RaisesGroup(block_network):
            await client.get(f"https://{UNROUTABLE_IP}")
