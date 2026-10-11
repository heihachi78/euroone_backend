"""Tests for the VirusTotal service."""

from typing import Any

import httpx
import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.clients.virustotal_client import VirusTotalClient
from app.db.virustotal_repository import VirusTotalRepository
from app.models.virustotal.ip import Ip
from app.models.virustotal.ip_report import IpReport
from app.services.virustotal_service import VirusTotalService

pytestmark = pytest.mark.anyio

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


class FakeVirusTotalClient(VirusTotalClient):
    """Replaces the HTTP client: records the requested IPs and returns `report` (or raises `error`)."""

    def __init__(self) -> None:  # no super().__init__: no httpx client is needed
        self.requested: list[Ip] = []
        self.report = IpReport(status_code=200, data=VT_IP_REPORT)
        self.error: Exception | None = None

    async def get_ip_report(self, ip: Ip) -> IpReport:
        """Record the IP and return `report`, or raise `error` if it is set."""
        self.requested.append(ip)
        if self.error is not None:
            raise self.error
        return self.report


class FakeRepository(VirusTotalRepository):
    """Replaces the database: records the saved reports and numbers them from 1 (or raises `error`)."""

    def __init__(self) -> None:  # no super().__init__: no database is needed
        self.saved: list[tuple[Ip, IpReport]] = []
        self.error: Exception | None = None

    async def save_report(self, ip: Ip, report: IpReport) -> int:
        """Record the report, or raise `error` if it is set."""
        if self.error is not None:
            raise self.error
        self.saved.append((ip, report))
        return len(self.saved)


@pytest.fixture
def fake_client() -> FakeVirusTotalClient:
    """Fake VirusTotal client that returns VT_IP_REPORT."""
    return FakeVirusTotalClient()


@pytest.fixture
def fake_repository() -> FakeRepository:
    """Fake repository with no saved reports."""
    return FakeRepository()


@pytest.fixture
def service(
    fake_client: FakeVirusTotalClient, fake_repository: FakeRepository
) -> VirusTotalService:
    """VirusTotal service under test, on the fakes."""
    return VirusTotalService(fake_client, fake_repository)


def ip(value: str) -> Ip:
    """Validate an IP address string into an Ip."""
    return Ip.model_validate({"ip": value})


async def test_returns_id_of_the_saved_report(service: VirusTotalService):
    """fetch_report returns the id of the report it saved."""
    assert await service.fetch_report(ip("8.8.8.8")) == 1


async def test_passes_ip_to_client(
    service: VirusTotalService, fake_client: FakeVirusTotalClient
):
    """The requested IP is passed to the VirusTotal client."""
    await service.fetch_report(ip("8.8.8.8"))

    assert fake_client.requested == [ip("8.8.8.8")]


async def test_saves_ip_with_the_report_of_the_client(
    service: VirusTotalService,
    fake_client: FakeVirusTotalClient,
    fake_repository: FakeRepository,
):
    """The IP is saved together with the exact report the client returned."""
    fake_client.report = IpReport(status_code=203, data=VT_IP_REPORT)

    await service.fetch_report(ip("8.8.8.8"))

    [(saved_ip, saved_report)] = fake_repository.saved
    assert saved_ip == ip("8.8.8.8")
    assert saved_report is fake_client.report


async def test_each_call_saves_a_new_report(
    service: VirusTotalService, fake_repository: FakeRepository
):
    """Every call saves a new report, even for the same IP."""
    ids = [
        await service.fetch_report(ip("8.8.8.8")),
        await service.fetch_report(ip("8.8.8.8")),
        await service.fetch_report(ip("1.1.1.1")),
    ]

    assert ids == [1, 2, 3]
    assert [saved_ip for saved_ip, _ in fake_repository.saved] == [
        ip("8.8.8.8"),
        ip("8.8.8.8"),
        ip("1.1.1.1"),
    ]


@pytest.mark.parametrize(
    "error",
    [
        httpx.HTTPStatusError(
            "404 Not Found",
            request=httpx.Request("GET", "https://vt.test/ip_addresses/8.8.8.8"),
            response=httpx.Response(404),
        ),
        httpx.ConnectError("connection refused"),
    ],
)
async def test_client_error_is_propagated_and_nothing_is_saved(
    service: VirusTotalService,
    fake_client: FakeVirusTotalClient,
    fake_repository: FakeRepository,
    error: Exception,
):
    """An HTTP or network error from the client is raised and nothing is saved."""
    fake_client.error = error

    with pytest.raises(type(error)):
        await service.fetch_report(ip("8.8.8.8"))

    assert fake_repository.saved == []


async def test_repository_error_is_propagated(
    service: VirusTotalService, fake_repository: FakeRepository
):
    """A database error while saving the report is raised to the caller."""
    fake_repository.error = SQLAlchemyError("database is locked")

    with pytest.raises(SQLAlchemyError, match="database is locked"):
        await service.fetch_report(ip("8.8.8.8"))
