"""Tests for the VirusTotal API client."""

from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from app.clients.errors import UnusableResponseError
from app.clients.virustotal_client import VirusTotalClient
from app.core.virustotal_config import VirusTotalConfig
from app.models.virustotal.ip import Ip
from app.models.virustotal.ip_report import IpReport

pytestmark = pytest.mark.anyio

API_KEY = "k" * 64

VT_IP_REPORT: dict[str, Any] = {
    "data": {
        "id": "8.8.8.8",
        "type": "ip_address",
        "attributes": {
            "as_owner": "GOOGLE",
            "last_analysis_stats": {"harmless": 62, "malicious": 0},
        },
    }
}


class FakeVirusTotal:
    """Stands in for the VirusTotal API: records every request and answers via `handler`."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.handler: Callable[[httpx.Request], httpx.Response] = lambda _: (
            httpx.Response(200, json=VT_IP_REPORT)
        )

    def __call__(self, request: httpx.Request) -> httpx.Response:
        """Record the request and answer it with `handler`."""
        self.requests.append(request)
        return self.handler(request)


@pytest.fixture
def config() -> VirusTotalConfig:
    """VirusTotal settings with a fake key, independent of the environment and .env."""
    return VirusTotalConfig(
        api_key=SecretStr(API_KEY),
        base_url="https://vt.client.test/api/v3",
        ip_address_report_endpoint="ip_addresses",
        timeout_seconds=7,
        _env_file=None,  # pyright: ignore[reportCallIssue]
    )


@pytest.fixture
def fake_vt(monkeypatch: pytest.MonkeyPatch) -> FakeVirusTotal:
    """Send the requests of every new httpx.AsyncClient to a FakeVirusTotal."""
    fake = FakeVirusTotal()
    real_async_client = httpx.AsyncClient

    def async_client_with_mock_transport(
        *args: Any, **kwargs: Any
    ) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(fake)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", async_client_with_mock_transport)
    return fake


@pytest.fixture
async def client(
    config: VirusTotalConfig, fake_vt: FakeVirusTotal
) -> AsyncIterator[VirusTotalClient]:
    """VirusTotalClient under test, closed after the test."""
    vt_client = VirusTotalClient(config)
    yield vt_client
    await vt_client.aclose()


def ip(value: str) -> Ip:
    """Validate an IP address string into an Ip."""
    return Ip.model_validate({"ip": value})


async def test_returns_report_with_status_code_and_json_body(client: VirusTotalClient):
    """The report holds the status code and the JSON body of the answer."""
    report = await client.get_ip_report(ip("8.8.8.8"))

    assert report == IpReport(status_code=200, data=VT_IP_REPORT)


async def test_sends_get_to_ip_report_endpoint(
    client: VirusTotalClient, fake_vt: FakeVirusTotal
):
    """The request is a GET to the IP's report URL under the configured base URL."""
    await client.get_ip_report(ip("8.8.8.8"))

    [request] = fake_vt.requests
    assert request.method == "GET"
    assert str(request.url) == "https://vt.client.test/api/v3/ip_addresses/8.8.8.8"


async def test_sends_api_key_and_accept_headers(
    client: VirusTotalClient, fake_vt: FakeVirusTotal
):
    """The request carries the API key and asks for JSON."""
    await client.get_ip_report(ip("8.8.8.8"))

    [request] = fake_vt.requests
    assert request.headers["x-apikey"] == API_KEY
    assert request.headers["accept"] == "application/json"


async def test_uses_configured_timeout(
    client: VirusTotalClient, fake_vt: FakeVirusTotal
):
    """The request uses the timeout from the settings."""
    await client.get_ip_report(ip("8.8.8.8"))

    [request] = fake_vt.requests
    assert request.extensions["timeout"] == httpx.Timeout(7).as_dict()


@pytest.mark.parametrize(
    ("value", "expected_path_ip"),
    [
        ("2001:4860:4860::8888", "2001:4860:4860::8888"),
        ("::ffff:8.8.8.8", "8.8.8.8"),  # IPv4-mapped IPv6 is sent as plain IPv4
    ],
)
async def test_ip_is_sent_in_normalized_form(
    client: VirusTotalClient, fake_vt: FakeVirusTotal, value: str, expected_path_ip: str
):
    """The IP goes into the URL normalized: IPv4-mapped IPv6 as plain IPv4."""
    await client.get_ip_report(ip(value))

    [request] = fake_vt.requests
    assert request.url.path == f"/api/v3/ip_addresses/{expected_path_ip}"


async def test_each_call_sends_a_new_request(
    client: VirusTotalClient, fake_vt: FakeVirusTotal
):
    """Every call sends its own request; nothing is cached."""
    await client.get_ip_report(ip("8.8.8.8"))
    await client.get_ip_report(ip("1.1.1.1"))

    assert [r.url.path for r in fake_vt.requests] == [
        "/api/v3/ip_addresses/8.8.8.8",
        "/api/v3/ip_addresses/1.1.1.1",
    ]


async def test_non_200_success_status_code_is_kept(
    client: VirusTotalClient, fake_vt: FakeVirusTotal
):
    """A 2xx status other than 200 is kept in the report as is."""
    fake_vt.handler = lambda _: httpx.Response(203, json=VT_IP_REPORT)

    report = await client.get_ip_report(ip("8.8.8.8"))

    assert report.status_code == 203


@pytest.mark.parametrize("status_code", [400, 401, 404, 429, 500, 503])
async def test_error_status_raises_http_status_error(
    client: VirusTotalClient, fake_vt: FakeVirusTotal, status_code: int
):
    """A 4xx or 5xx answer raises HTTPStatusError with that status."""
    fake_vt.handler = lambda _: httpx.Response(
        status_code, json={"error": {"code": "SomeError"}}
    )

    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        await client.get_ip_report(ip("8.8.8.8"))

    assert exc_info.value.response.status_code == status_code


async def test_network_error_is_propagated(
    client: VirusTotalClient, fake_vt: FakeVirusTotal
):
    """A connection error is raised to the caller unchanged."""

    def raise_connect_error(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    fake_vt.handler = raise_connect_error

    with pytest.raises(httpx.ConnectError):
        await client.get_ip_report(ip("8.8.8.8"))


async def test_timeout_is_propagated(client: VirusTotalClient, fake_vt: FakeVirusTotal):
    """A timeout is raised to the caller unchanged."""

    def raise_timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    fake_vt.handler = raise_timeout

    with pytest.raises(httpx.TimeoutException):
        await client.get_ip_report(ip("8.8.8.8"))


async def test_non_json_body_raises(client: VirusTotalClient, fake_vt: FakeVirusTotal):
    """A body that is not JSON raises UnusableResponseError."""
    fake_vt.handler = lambda _: httpx.Response(200, text="<html>not json</html>")

    with pytest.raises(UnusableResponseError, match="not a JSON object"):
        await client.get_ip_report(ip("8.8.8.8"))


async def test_non_object_json_body_raises(
    client: VirusTotalClient, fake_vt: FakeVirusTotal
):
    """A JSON body that is not an object, e.g. a list, raises UnusableResponseError."""
    fake_vt.handler = lambda _: httpx.Response(200, json=[VT_IP_REPORT])

    with pytest.raises(UnusableResponseError, match="not a JSON object"):
        await client.get_ip_report(ip("8.8.8.8"))


async def test_closed_client_cannot_send_requests(
    config: VirusTotalConfig, fake_vt: FakeVirusTotal
):
    """After aclose, get_ip_report raises RuntimeError and sends nothing."""
    vt_client = VirusTotalClient(config)
    await vt_client.aclose()

    with pytest.raises(RuntimeError):
        await vt_client.get_ip_report(ip("8.8.8.8"))

    assert fake_vt.requests == []
