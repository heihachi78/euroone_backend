"""Tests for the IP address report endpoint, with fake APIs and a throwaway database."""

import json
import logging
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import NullPool, create_engine, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session

from app.api.v1 import virustotal_router
from app.app import app
from app.clients.ai_client import AiClient
from app.clients.virustotal_client import VirusTotalClient
from app.core.ai_config import ai_config
from app.core.virustotal_config import virus_total_config
from app.db import database
from app.db.virustotal_repository import VirusTotal
from app.services.summary_service import (
    SUMMARY_SYSTEM_PROMPT,
    SUMMARY_USER_PROMPT,
    SummaryService,
)
from app.services.virustotal_service import VirusTotalService

ENDPOINT_URL = "/api/v1/ip_address_report"

VT_IP_REPORT: dict[str, Any] = {
    "data": {
        "id": "8.8.8.8",
        "type": "ip_address",
        "attributes": {
            "as_owner": "GOOGLE",
            "country": "US",
            "last_analysis_stats": {
                "harmless": 62,
                "malicious": 0,
                "suspicious": 0,
                "undetected": 28,
            },
        },
    }
}

SUMMARY_TEXT = "8.8.8.8 is Google Public DNS, no engine flags it as malicious."

GEMINI_RESPONSE: dict[str, Any] = {
    "candidates": [
        {
            "content": {"role": "model", "parts": [{"text": SUMMARY_TEXT}]},
            "finishReason": "STOP",
        }
    ],
}

REAL_ASYNC_CLIENT = httpx.AsyncClient


def expected_vt_url(ip: str) -> str:
    """Build the VirusTotal report URL the app should request, from the test settings."""
    base_url = virus_total_config.base_url.rstrip("/")
    endpoint = virus_total_config.ip_address_report_endpoint.strip("/")
    return f"{base_url}/{endpoint}/{ip}"


class FakeApi:
    """Stands in for a remote API: records every request and answers via `handler`."""

    def __init__(self, response: dict[str, Any]) -> None:
        """Start with no requests and a `handler` that answers 200 with `response`."""
        self.requests: list[httpx.Request] = []
        self.handler: Callable[[httpx.Request], httpx.Response] = lambda _: (
            httpx.Response(200, json=response)
        )

    def __call__(self, request: httpx.Request) -> httpx.Response:
        """Record the request and answer it with `handler`."""
        self.requests.append(request)
        return self.handler(request)


@pytest.fixture
def fake_vt(monkeypatch: pytest.MonkeyPatch) -> FakeApi:
    """Fake VirusTotal API that answers with VT_IP_REPORT."""
    fake = FakeApi(VT_IP_REPORT)

    def async_client_with_mock_transport(
        *args: Any, **kwargs: Any
    ) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(fake)
        return REAL_ASYNC_CLIENT(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", async_client_with_mock_transport)
    return fake


@pytest.fixture
def fake_gemini(monkeypatch: pytest.MonkeyPatch) -> FakeApi:
    """Fake Gemini API that answers with GEMINI_RESPONSE."""
    fake = FakeApi(GEMINI_RESPONSE)

    def async_client_with_mock_transport(**kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(fake)
        return REAL_ASYNC_CLIENT(**kwargs)

    monkeypatch.setattr(
        "google.genai._api_client.AsyncHttpxClient", async_client_with_mock_transport
    )
    monkeypatch.setattr("google.genai._api_client.has_aiohttp", False)
    return fake


@pytest.fixture
def db_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the app's engine and the router's sessions at a throwaway SQLite file."""
    path = tmp_path / "router_test.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{path}", poolclass=NullPool)
    monkeypatch.setattr(database, "engine", engine)
    monkeypatch.setattr(
        virustotal_router,
        "SessionLocal",
        async_sessionmaker(bind=engine, expire_on_commit=False),
    )
    return path


@pytest.fixture
def client(
    fake_vt: FakeApi, fake_gemini: FakeApi, db_path: Path
) -> Iterator[TestClient]:
    """Test client of the started app, using the fake APIs and the test database."""
    with TestClient(app) as test_client:
        # Startup creates the database but calls no API.
        assert db_path.exists()
        assert fake_vt.requests == fake_gemini.requests == []
        yield test_client


def saved_rows(db_path: Path) -> list[VirusTotal]:
    """Read every row of the test database, ordered by id."""
    engine = create_engine(f"sqlite:///{db_path}")
    with Session(engine) as session:
        rows = list(session.scalars(select(VirusTotal).order_by(VirusTotal.id)).all())
    engine.dispose()
    return rows


def test_returns_ip_with_ai_summary(
    client: TestClient, fake_vt: FakeApi, fake_gemini: FakeApi
):
    """A valid request returns the IP with Gemini's summary, calling each API once."""
    response = client.post(ENDPOINT_URL, json={"ip": "8.8.8.8"})

    assert response.status_code == 200
    assert response.json() == {"ip": "8.8.8.8", "summary": SUMMARY_TEXT}
    assert len(fake_vt.requests) == 1
    assert len(fake_gemini.requests) == 1


def test_calls_virustotal_with_correct_request(client: TestClient, fake_vt: FakeApi):
    """VirusTotal gets a GET to the IP's report URL.

    The request carries the API key and asks for JSON.
    """
    client.post(ENDPOINT_URL, json={"ip": "8.8.8.8"})

    [vt_request] = fake_vt.requests
    assert vt_request.method == "GET"
    assert str(vt_request.url) == expected_vt_url("8.8.8.8")
    assert (
        vt_request.headers["x-apikey"] == virus_total_config.api_key.get_secret_value()
    )
    assert vt_request.headers["accept"] == "application/json"


def test_asks_gemini_to_summarize_the_virustotal_report(
    client: TestClient, fake_gemini: FakeApi
):
    """Gemini gets the summary prompts and the VirusTotal report as payload.

    It is sent to the configured model's generateContent endpoint, with the API key.
    """
    client.post(ENDPOINT_URL, json={"ip": "8.8.8.8"})

    [ai_request] = fake_gemini.requests
    assert ai_request.method == "POST"
    assert ai_request.url.path.endswith(f"/models/{ai_config.model}:generateContent")
    assert ai_request.headers["x-goog-api-key"] == ai_config.api_key.get_secret_value()
    body = json.loads(ai_request.content)
    assert body["systemInstruction"]["parts"] == [{"text": SUMMARY_SYSTEM_PROMPT}]
    [content] = body["contents"]
    [user_prompt, payload] = content["parts"]
    assert user_prompt == {"text": SUMMARY_USER_PROMPT}
    assert json.loads(payload["text"]) == VT_IP_REPORT


def test_logs_each_step_of_the_request(
    client: TestClient, caplog: pytest.LogCaptureFixture
):
    """Every step of a successful request is logged at INFO level, in order."""
    caplog.set_level(logging.INFO, logger="app")

    client.post(ENDPOINT_URL, json={"ip": "8.8.8.8"})

    assert [
        record.getMessage()
        for record in caplog.records
        if record.name.startswith("app.")
    ] == [
        "Received report request for ip=8.8.8.8",
        "VirusTotal responded 200 for ip=8.8.8.8",
        "Saved report id=1 for ip=8.8.8.8",
        "Received report id=1 for ip=8.8.8.8",
        "Loaded report id=1",
        f"Gemini responded for model={ai_config.model}",
        "Saved summary for report id=1",
        "Returning report id=1 for ip=8.8.8.8",
    ]


def test_saves_report_and_summary_to_db(client: TestClient, db_path: Path):
    """The VirusTotal report and the Gemini summary end up in one database row."""
    client.post(ENDPOINT_URL, json={"ip": "8.8.8.8"})

    [row] = saved_rows(db_path)
    assert row.ip == "8.8.8.8"
    assert row.vt_response == VT_IP_REPORT
    assert row.vt_status_code == 200
    assert row.ai_response == SUMMARY_TEXT
    assert row.ai_status_code == 200


@pytest.mark.parametrize("repeated_ip", ["8.8.8.8", "::ffff:8.8.8.8"])
def test_saved_summary_is_returned_without_calling_any_api(
    client: TestClient,
    fake_vt: FakeApi,
    fake_gemini: FakeApi,
    db_path: Path,
    repeated_ip: str,
):
    """A repeated request for an IP is answered with its saved summary.

    Neither API is called again and nothing new is saved, even if the IP is written in
    another form.
    """
    client.post(ENDPOINT_URL, json={"ip": "8.8.8.8"})

    response = client.post(ENDPOINT_URL, json={"ip": repeated_ip})

    assert response.status_code == 200
    assert response.json() == {"ip": "8.8.8.8", "summary": SUMMARY_TEXT}
    assert len(fake_vt.requests) == 1
    assert len(fake_gemini.requests) == 1
    assert len(saved_rows(db_path)) == 1


def test_logs_that_the_saved_summary_is_returned(
    client: TestClient, caplog: pytest.LogCaptureFixture
):
    """A request answered from the database logs that the saved summary is returned."""
    caplog.set_level(logging.INFO, logger="app")
    client.post(ENDPOINT_URL, json={"ip": "8.8.8.8"})
    caplog.clear()

    client.post(ENDPOINT_URL, json={"ip": "8.8.8.8"})

    assert [
        record.getMessage()
        for record in caplog.records
        if record.name.startswith("app.")
    ] == [
        "Received report request for ip=8.8.8.8",
        "Returning saved summary for ip=8.8.8.8",
    ]


def test_ip_without_saved_summary_is_looked_up_and_summarized_again(
    client: TestClient, fake_vt: FakeApi, fake_gemini: FakeApi, db_path: Path
):
    """If summarizing an IP failed earlier, a repeated request calls both APIs again."""
    fake_gemini.handler = lambda _: httpx.Response(
        200, json={"promptFeedback": {"blockReason": "SAFETY"}}
    )
    client.post(ENDPOINT_URL, json={"ip": "8.8.8.8"})
    fake_gemini.handler = lambda _: httpx.Response(200, json=GEMINI_RESPONSE)

    response = client.post(ENDPOINT_URL, json={"ip": "8.8.8.8"})

    assert response.status_code == 200
    assert response.json() == {"ip": "8.8.8.8", "summary": SUMMARY_TEXT}
    assert len(fake_vt.requests) == 2
    assert len(fake_gemini.requests) == 2
    assert [row.ai_response for row in saved_rows(db_path)] == [None, SUMMARY_TEXT]


@pytest.mark.parametrize(
    ("ip", "expected_vt_ip"),
    [
        ("2001:4860:4860::8888", "2001:4860:4860::8888"),
        ("::ffff:8.8.8.8", "8.8.8.8"),
    ],
)
def test_ip_is_normalized_before_calling_virustotal(
    client: TestClient, fake_vt: FakeApi, ip: str, expected_vt_ip: str
):
    """The IP is normalized both for the VirusTotal call and in the response.

    An IPv4-mapped IPv6 address becomes plain IPv4.
    """
    response = client.post(ENDPOINT_URL, json={"ip": ip})

    assert response.status_code == 200
    [vt_request] = fake_vt.requests
    assert str(vt_request.url) == expected_vt_url(expected_vt_ip)
    assert response.json()["ip"] == expected_vt_ip


@pytest.mark.parametrize(
    "payload",
    [
        {"ip": "10.0.0.1"},  # private
        {"ip": "127.0.0.1"},  # loopback
        {"ip": "224.0.1.1"},  # multicast
        {"ip": "not-an-ip"},
        {"ip": ""},
        {"ip": None},
        {},
        {"address": "8.8.8.8"},
    ],
)
def test_invalid_payload_is_rejected_without_calling_any_api(
    client: TestClient,
    fake_vt: FakeApi,
    fake_gemini: FakeApi,
    db_path: Path,
    payload: dict[str, Any],
):
    """A malformed body or a non-public IP is rejected with 422.

    Neither API is called and nothing is saved.
    """
    response = client.post(ENDPOINT_URL, json=payload)

    assert response.status_code == 422
    assert fake_vt.requests == []
    assert fake_gemini.requests == []
    assert saved_rows(db_path) == []


def test_get_method_is_not_allowed(
    client: TestClient, fake_vt: FakeApi, fake_gemini: FakeApi
):
    """The endpoint only accepts POST: a GET gets 405 and calls no API."""
    response = client.get(ENDPOINT_URL, params={"ip": "8.8.8.8"})

    assert response.status_code == 405
    assert fake_vt.requests == []
    assert fake_gemini.requests == []


UPSTREAM_ERROR = "An external service returned an error"
UPSTREAM_RATE_LIMITED = "An external service is rate limited, try again later"
UPSTREAM_TIMED_OUT = "An external service timed out"
UPSTREAM_UNREACHABLE = "An external service could not be reached"
UPSTREAM_UNUSABLE = "An external service returned an unusable response"
DATABASE_ERROR = "A database error occurred"
INTERNAL_ERROR = "Internal server error"


@pytest.mark.parametrize(
    ("vt_status", "expected_status", "expected_detail"),
    [
        (401, 502, UPSTREAM_ERROR),
        (404, 502, UPSTREAM_ERROR),
        (500, 502, UPSTREAM_ERROR),
        (429, 503, UPSTREAM_RATE_LIMITED),
    ],
)
def test_virustotal_error_is_answered_without_summarizing_or_saving(
    client: TestClient,
    fake_vt: FakeApi,
    fake_gemini: FakeApi,
    db_path: Path,
    vt_status: int,
    expected_status: int,
    expected_detail: str,
):
    """A VirusTotal error status is answered with 502, or 503 when rate limited.

    The VirusTotal error body is not passed on, Gemini is not called and nothing is
    saved.
    """
    fake_vt.handler = lambda _: httpx.Response(
        vt_status, json={"error": {"code": "SomeError", "message": "vt details"}}
    )

    response = client.post(ENDPOINT_URL, json={"ip": "8.8.8.8"})

    assert response.status_code == expected_status
    assert response.json() == {"detail": expected_detail}
    assert fake_gemini.requests == []
    assert saved_rows(db_path) == []


@pytest.mark.parametrize(
    ("gemini_status", "gemini_error_status", "expected_status", "expected_detail"),
    [
        (400, "INVALID_ARGUMENT", 502, UPSTREAM_ERROR),
        (500, "INTERNAL", 502, UPSTREAM_ERROR),
        (429, "RESOURCE_EXHAUSTED", 503, UPSTREAM_RATE_LIMITED),
    ],
)
def test_gemini_error_is_answered_and_keeps_report_without_summary(
    client: TestClient,
    fake_gemini: FakeApi,
    db_path: Path,
    gemini_status: int,
    gemini_error_status: str,
    expected_status: int,
    expected_detail: str,
):
    """A Gemini error status is answered with 502, or 503 when rate limited.

    The Gemini error body is not passed on. The saved row keeps the VirusTotal report,
    with no summary.
    """
    fake_gemini.handler = lambda _: httpx.Response(
        gemini_status,
        json={
            "error": {
                "code": gemini_status,
                "message": "gemini details",
                "status": gemini_error_status,
            }
        },
    )

    response = client.post(ENDPOINT_URL, json={"ip": "8.8.8.8"})

    assert response.status_code == expected_status
    assert response.json() == {"detail": expected_detail}
    [row] = saved_rows(db_path)
    assert row.vt_response == VT_IP_REPORT
    assert row.ai_response is None
    assert row.ai_status_code is None


@pytest.mark.parametrize(
    "vt_response",
    [
        httpx.Response(200, text="<html>not json</html>"),
        httpx.Response(200, json=[VT_IP_REPORT]),
    ],
)
def test_unusable_virustotal_response_is_answered_without_summarizing_or_saving(
    client: TestClient,
    fake_vt: FakeApi,
    fake_gemini: FakeApi,
    db_path: Path,
    vt_response: httpx.Response,
):
    """A VirusTotal body that is not a JSON object is answered with 502.

    Gemini is not called and nothing is saved.
    """
    fake_vt.handler = lambda _: vt_response

    response = client.post(ENDPOINT_URL, json={"ip": "8.8.8.8"})

    assert response.status_code == 502
    assert response.json() == {"detail": UPSTREAM_UNUSABLE}
    assert fake_gemini.requests == []
    assert saved_rows(db_path) == []


def test_gemini_response_without_text_is_answered_and_keeps_report_without_summary(
    client: TestClient, fake_gemini: FakeApi, db_path: Path
):
    """A Gemini answer without generated text, e.g. a blocked prompt, gets 502.

    The saved row keeps the VirusTotal report, with no summary.
    """
    fake_gemini.handler = lambda _: httpx.Response(
        200, json={"promptFeedback": {"blockReason": "SAFETY"}}
    )

    response = client.post(ENDPOINT_URL, json={"ip": "8.8.8.8"})

    assert response.status_code == 502
    assert response.json() == {"detail": UPSTREAM_UNUSABLE}
    [row] = saved_rows(db_path)
    assert row.vt_response == VT_IP_REPORT
    assert row.ai_response is None
    assert row.ai_status_code is None


def raise_timeout(request: httpx.Request) -> httpx.Response:
    """Fail the request as if the remote API did not answer in time."""
    raise httpx.ReadTimeout("timed out", request=request)


def raise_connect_error(request: httpx.Request) -> httpx.Response:
    """Fail the request as if the remote API could not be connected to."""
    raise httpx.ConnectError("connection refused", request=request)


@pytest.mark.parametrize("fake_api", ["fake_vt", "fake_gemini"])
@pytest.mark.parametrize(
    ("failure", "expected_status", "expected_detail"),
    [
        (raise_timeout, 504, UPSTREAM_TIMED_OUT),
        (raise_connect_error, 502, UPSTREAM_UNREACHABLE),
    ],
)
def test_unreachable_api_is_answered_with_gateway_error(
    client: TestClient,
    request: pytest.FixtureRequest,
    fake_api: str,
    failure: Callable[[httpx.Request], httpx.Response],
    expected_status: int,
    expected_detail: str,
):
    """A timeout of either API is answered with 504, a connection error with 502."""
    fake: FakeApi = request.getfixturevalue(fake_api)
    fake.handler = failure

    response = client.post(ENDPOINT_URL, json={"ip": "8.8.8.8"})

    assert response.status_code == expected_status
    assert response.json() == {"detail": expected_detail}


def test_api_error_is_logged_as_warning_with_the_exception(
    client: TestClient, fake_vt: FakeApi, caplog: pytest.LogCaptureFixture
):
    """An answered API error is logged at WARNING level with its exception attached."""
    fake_vt.handler = lambda _: httpx.Response(500)

    client.post(ENDPOINT_URL, json={"ip": "8.8.8.8"})

    [record] = [
        record
        for record in caplog.records
        if record.name.startswith("app.") and record.levelno >= logging.WARNING
    ]
    assert record.levelno == logging.WARNING
    assert record.getMessage() == f"{UPSTREAM_ERROR}, answering 502"
    assert record.exc_info is not None
    assert record.exc_info[0] is httpx.HTTPStatusError


def drop_reports_table(db_path: Path) -> None:
    """Drop the reports table, so every later database operation of the app fails."""
    engine = create_engine(f"sqlite:///{db_path}")
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE virustotal"))
    engine.dispose()


def test_database_error_is_answered_with_500_without_calling_any_api(
    client: TestClient, fake_vt: FakeApi, fake_gemini: FakeApi, db_path: Path
):
    """A failed database operation is answered with 500 and a JSON detail.

    The saved summaries cannot be looked up, so neither API is called.
    """
    drop_reports_table(db_path)

    response = client.post(ENDPOINT_URL, json={"ip": "8.8.8.8"})

    assert response.status_code == 500
    assert response.json() == {"detail": DATABASE_ERROR}
    assert fake_vt.requests == []
    assert fake_gemini.requests == []


def test_database_error_is_logged_as_error_with_the_exception(
    client: TestClient, db_path: Path, caplog: pytest.LogCaptureFixture
):
    """A failed database operation is logged at ERROR level with its exception."""
    drop_reports_table(db_path)

    client.post(ENDPOINT_URL, json={"ip": "8.8.8.8"})

    [record] = [
        record
        for record in caplog.records
        if record.name.startswith("app.") and record.levelno >= logging.WARNING
    ]
    assert record.levelno == logging.ERROR
    assert record.getMessage() == f"{DATABASE_ERROR}, answering 500"
    assert record.exc_info is not None
    assert record.exc_info[0] is not None
    assert issubclass(record.exc_info[0], SQLAlchemyError)


def raise_unexpected_error(request: httpx.Request) -> httpx.Response:
    """Fail the request with an exception that no handler expects, as a bug would."""
    raise RuntimeError("unexpected")


@pytest.mark.usefixtures("fake_gemini", "db_path")
def test_unexpected_error_is_answered_with_500_and_a_json_detail(fake_vt: FakeApi):
    """An exception without a handler of its own is answered with 500 and a JSON detail.

    The exception still reaches the server, which logs it, so the test client is told
    not to raise it here.
    """
    fake_vt.handler = raise_unexpected_error

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post(ENDPOINT_URL, json={"ip": "8.8.8.8"})

    assert response.status_code == 500
    assert response.json() == {"detail": INTERNAL_ERROR}


@pytest.mark.usefixtures("fake_vt", "fake_gemini", "db_path")
def test_lifespan_creates_services_and_closes_clients_on_shutdown(
    monkeypatch: pytest.MonkeyPatch,
):
    """Startup puts both services on the app state.

    Shutdown closes the VirusTotal client, then the Gemini client.
    """
    closed: list[str] = []
    real_vt_aclose = VirusTotalClient.aclose
    real_ai_aclose = AiClient.aclose

    async def recording_vt_aclose(self: VirusTotalClient) -> None:
        closed.append("virustotal")
        await real_vt_aclose(self)

    async def recording_ai_aclose(self: AiClient) -> None:
        closed.append("ai")
        await real_ai_aclose(self)

    monkeypatch.setattr(VirusTotalClient, "aclose", recording_vt_aclose)
    monkeypatch.setattr(AiClient, "aclose", recording_ai_aclose)

    with TestClient(app):
        assert isinstance(app.state.virustotal_service, VirusTotalService)
        assert isinstance(app.state.summary_service, SummaryService)
        assert closed == []

    assert closed == ["virustotal", "ai"]
