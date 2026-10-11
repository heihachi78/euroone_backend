"""Shared test setup: fake settings in the environment and no network access."""

import os
import socket
from collections.abc import Iterator
from typing import Any

import pytest

os.environ["APP_TITLE"] = "EuroOne test"
os.environ["VIRUS_TOTAL_API_KEY"] = "x" * 64
os.environ["VIRUS_TOTAL_BASE_URL"] = "https://vt.example.test/api/v3"
os.environ["VIRUS_TOTAL_IP_ADDRESS_REPORT_ENDPOINT"] = "ip_addresses"
os.environ["VIRUS_TOTAL_TIMEOUT_SECONDS"] = "5"
os.environ["AI_API_KEY"] = "g" * 39
os.environ["AI_MODEL"] = "gemini-test"
os.environ["AI_TIMEOUT_SECONDS"] = "5"
os.environ["DB_USER"] = "test_user"
os.environ["DB_PASSWORD"] = "test_password"
os.environ["DB_NAME"] = "test_db.db"


class NetworkAccessError(Exception):
    """Raised when a test tries to reach the network.

    Deliberately not an OSError, so httpx cannot turn it into a ConnectError that a test
    expecting a network failure would accept.
    """


def _refuse_network_access(*args: Any, **kwargs: Any) -> Any:
    """Stand in for a socket function and fail instead of accessing the network."""
    raise NetworkAccessError(
        f"Tests must not access the network (attempted with {args!r} {kwargs!r})."
    )


@pytest.fixture(scope="session", autouse=True)
def block_network() -> Iterator[type[Exception]]:
    """Block DNS lookups and every socket connect, sync or async, for the whole session.

    Safety net under the per-test fakes: if a fake is missing or bypassed, the test
    fails here instead of sending a request (and an API key) to a real service.
    """
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(socket, "getaddrinfo", _refuse_network_access)
        mp.setattr(socket.socket, "connect", _refuse_network_access)
        mp.setattr(socket.socket, "connect_ex", _refuse_network_access)
        yield NetworkAccessError
