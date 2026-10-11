"""Tests for the summary service."""

import json
from ipaddress import IPv4Address
from typing import Any

import httpx
import pytest
from google.genai import errors
from sqlalchemy.exc import SQLAlchemyError

from app.clients.ai_client import AiClient
from app.clients.errors import UnusableResponseError
from app.db.virustotal_repository import ReportNotFoundError, VirusTotalRepository
from app.models.ai.summary import Summary
from app.models.ai.summary_request import SummaryRequest
from app.models.virustotal.ip import Ip
from app.models.virustotal.ip_analysis import IpAnalysis
from app.models.virustotal.stored_ip_report import StoredIpReport
from app.services.summary_service import (
    SUMMARY_SYSTEM_PROMPT,
    SUMMARY_USER_PROMPT,
    SummaryService,
)

pytestmark = pytest.mark.anyio

REPORT_ID = 7

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

SUMMARY_TEXT = "8.8.8.8 is Google Public DNS, no engine flags it as malicious."


class FakeAiClient(AiClient):
    """Replaces the Gemini client: records the summary requests and returns `summary` (or raises `error`)."""

    def __init__(self) -> None:  # no super().__init__: no Gemini client is needed
        self.requests: list[SummaryRequest] = []
        self.summary = Summary(status_code=200, text=SUMMARY_TEXT)
        self.error: Exception | None = None

    async def summarize(self, request: SummaryRequest) -> Summary:
        """Record the request and return `summary`, or raise `error` if it is set."""
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return self.summary


class FakeRepository(VirusTotalRepository):
    """Replaces the database: holds one stored report and records the saved summaries.

    `find_latest_summary` returns `latest_summary` and records the looked-up IPs.

    `get_error` / `save_error` make the matching method raise instead.
    """

    def __init__(self) -> None:  # no super().__init__: no database is needed
        self.stored = StoredIpReport(
            id=REPORT_ID, ip=IPv4Address("8.8.8.8"), status_code=200, data=VT_IP_REPORT
        )
        self.requested_ids: list[int] = []
        self.saved: list[tuple[int, Summary]] = []
        self.latest_summary: str | None = None
        self.looked_up_ips: list[Ip] = []
        self.get_error: Exception | None = None
        self.save_error: Exception | None = None

    async def get_report(self, report_id: int) -> StoredIpReport:
        """Record the id and return `stored`, or raise `get_error` if it is set."""
        self.requested_ids.append(report_id)
        if self.get_error is not None:
            raise self.get_error
        return self.stored

    async def save_summary(self, report_id: int, summary: Summary) -> None:
        """Record the summary, or raise `save_error` if it is set."""
        if self.save_error is not None:
            raise self.save_error
        self.saved.append((report_id, summary))

    async def find_latest_summary(self, ip: Ip) -> str | None:
        """Record the IP and return `latest_summary`."""
        self.looked_up_ips.append(ip)
        return self.latest_summary


@pytest.fixture
def fake_ai() -> FakeAiClient:
    """Fake Gemini client that returns SUMMARY_TEXT."""
    return FakeAiClient()


@pytest.fixture
def fake_repository() -> FakeRepository:
    """Fake repository that holds the report with REPORT_ID."""
    return FakeRepository()


@pytest.fixture
def service(fake_ai: FakeAiClient, fake_repository: FakeRepository) -> SummaryService:
    """Summary service under test, on the fakes."""
    return SummaryService(fake_ai, fake_repository)


async def test_returns_stored_ip_with_ai_summary(service: SummaryService):
    """summarize returns the stored IP together with the AI summary."""
    assert await service.summarize(REPORT_ID) == IpAnalysis(
        ip=IPv4Address("8.8.8.8"), summary=SUMMARY_TEXT
    )


async def test_reads_the_given_report(
    service: SummaryService, fake_repository: FakeRepository
):
    """summarize loads exactly the report with the given id."""
    await service.summarize(REPORT_ID)

    assert fake_repository.requested_ids == [REPORT_ID]


async def test_asks_ai_to_summarize_the_report(
    service: SummaryService, fake_ai: FakeAiClient
):
    """The AI gets the summary prompts and the stored report as JSON payload."""
    await service.summarize(REPORT_ID)

    [request] = fake_ai.requests
    assert request.system_prompt == SUMMARY_SYSTEM_PROMPT
    assert request.user_prompt == SUMMARY_USER_PROMPT
    assert json.loads(request.payload) == VT_IP_REPORT


async def test_ai_gets_the_report_and_response_the_ip_read_from_the_repository(
    service: SummaryService, fake_ai: FakeAiClient, fake_repository: FakeRepository
):
    """Both the AI payload and the returned IP come from the stored report."""
    other_report: dict[str, Any] = {
        "data": {"id": "1.1.1.1", "attributes": {"as_owner": "CLOUDFLARENET"}}
    }
    fake_repository.stored = StoredIpReport(
        id=REPORT_ID, ip=IPv4Address("1.1.1.1"), status_code=200, data=other_report
    )

    result = await service.summarize(REPORT_ID)

    [request] = fake_ai.requests
    assert json.loads(request.payload) == other_report
    assert result.ip == IPv4Address("1.1.1.1")


async def test_saves_the_ai_summary_to_the_given_report(
    service: SummaryService, fake_ai: FakeAiClient, fake_repository: FakeRepository
):
    """The summary from the AI is saved to the given report and returned."""
    fake_ai.summary = Summary(status_code=201, text="Other summary.")

    result = await service.summarize(REPORT_ID)

    [(saved_id, saved_summary)] = fake_repository.saved
    assert saved_id == REPORT_ID
    assert saved_summary is fake_ai.summary
    assert result.summary == "Other summary."


async def test_unknown_report_is_propagated_without_asking_ai(
    service: SummaryService, fake_ai: FakeAiClient, fake_repository: FakeRepository
):
    """ReportNotFoundError is raised before the AI is asked or anything is saved."""
    fake_repository.get_error = ReportNotFoundError(REPORT_ID)

    with pytest.raises(ReportNotFoundError):
        await service.summarize(REPORT_ID)

    assert fake_ai.requests == []
    assert fake_repository.saved == []


@pytest.mark.parametrize(
    "error",
    [
        errors.ClientError(
            429,
            {
                "error": {
                    "code": 429,
                    "message": "quota",
                    "status": "RESOURCE_EXHAUSTED",
                }
            },
        ),
        errors.ServerError(
            503,
            {"error": {"code": 503, "message": "overloaded", "status": "UNAVAILABLE"}},
        ),
        UnusableResponseError("Gemini response contains no generated text"),
        httpx.ReadTimeout("timed out"),
    ],
)
async def test_ai_error_is_propagated_and_nothing_is_saved(
    service: SummaryService,
    fake_ai: FakeAiClient,
    fake_repository: FakeRepository,
    error: Exception,
):
    """Any error from the AI client is raised and no summary is saved."""
    fake_ai.error = error

    with pytest.raises(type(error)):
        await service.summarize(REPORT_ID)

    assert fake_repository.saved == []


async def test_repository_save_error_is_propagated(
    service: SummaryService, fake_repository: FakeRepository
):
    """A database error while saving the summary is raised to the caller."""
    fake_repository.save_error = SQLAlchemyError("database is locked")

    with pytest.raises(SQLAlchemyError, match="database is locked"):
        await service.summarize(REPORT_ID)


async def test_find_summary_returns_the_ip_with_its_saved_summary(
    service: SummaryService, fake_ai: FakeAiClient, fake_repository: FakeRepository
):
    """find_summary returns the given IP with its saved summary, without asking the AI."""
    fake_repository.latest_summary = SUMMARY_TEXT
    ip = Ip.model_validate({"ip": "1.1.1.1"})

    assert await service.find_summary(ip) == IpAnalysis(
        ip=IPv4Address("1.1.1.1"), summary=SUMMARY_TEXT
    )
    assert fake_repository.looked_up_ips == [ip]
    assert fake_ai.requests == []


async def test_find_summary_without_saved_summary_returns_none(
    service: SummaryService,
):
    """find_summary returns None if the IP has no saved summary."""
    assert await service.find_summary(Ip.model_validate({"ip": "1.1.1.1"})) is None
