"""Tests for the Gemini API client."""

import json
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import pytest
from google.genai import errors
from pydantic import SecretStr

from app.clients.ai_client import AiClient
from app.clients.errors import UnusableResponseError
from app.core.ai_config import AiConfig
from app.models.ai.summary import Summary
from app.models.ai.summary_request import SummaryRequest

pytestmark = pytest.mark.anyio

API_KEY = "g" * 39

GEMINI_RESPONSE: dict[str, Any] = {
    "candidates": [
        {
            "content": {
                "role": "model",
                "parts": [{"text": "The IP is "}, {"text": "harmless."}],
            },
            "finishReason": "STOP",
        }
    ],
    "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 4},
}

REQUEST = SummaryRequest(
    system_prompt="You are a security analyst.",
    user_prompt="Summarize:",
    payload='{"ip": "8.8.8.8"}',
)


class FakeGemini:
    """Stands in for the Gemini API: records every request and answers via `handler`."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.handler: Callable[[httpx.Request], httpx.Response] = lambda _: (
            httpx.Response(200, json=GEMINI_RESPONSE)
        )

    def __call__(self, request: httpx.Request) -> httpx.Response:
        """Record the request and answer it with `handler`."""
        self.requests.append(request)
        return self.handler(request)


@pytest.fixture
def config() -> AiConfig:
    """Gemini settings with a fake key, independent of the environment and .env."""
    return AiConfig(
        api_key=SecretStr(API_KEY),
        model="gemini-test",
        timeout_seconds=7,
        _env_file=None,  # pyright: ignore[reportCallIssue]
    )


@pytest.fixture
def fake_gemini(monkeypatch: pytest.MonkeyPatch) -> FakeGemini:
    """Send the requests of the Gemini SDK to a FakeGemini."""
    fake = FakeGemini()

    def async_client_with_mock_transport(**kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(fake)
        return httpx.AsyncClient(**kwargs)

    monkeypatch.setattr(
        "google.genai._api_client.AsyncHttpxClient", async_client_with_mock_transport
    )
    monkeypatch.setattr("google.genai._api_client.has_aiohttp", False)
    return fake


@pytest.fixture
async def client(config: AiConfig, fake_gemini: FakeGemini) -> AsyncIterator[AiClient]:
    """AiClient under test, closed after the test."""
    ai_client = AiClient(config)
    yield ai_client
    await ai_client.aclose()


def gemini_error(status_code: int) -> httpx.Response:
    """Build a Gemini API error response."""
    return httpx.Response(
        status_code,
        json={"error": {"code": status_code, "message": "boom", "status": "ERROR"}},
    )


async def test_returns_summary_with_ok_status_and_joined_text(client: AiClient):
    """The summary holds the 200 status and the text parts of the answer, joined."""
    summary = await client.summarize(REQUEST)

    assert summary == Summary(status_code=200, text="The IP is harmless.")


async def test_sends_post_to_generate_content_endpoint_of_configured_model(
    client: AiClient, fake_gemini: FakeGemini
):
    """The request is a POST to the generateContent endpoint of the configured model."""
    await client.summarize(REQUEST)

    [request] = fake_gemini.requests
    assert request.method == "POST"
    assert (
        str(request.url)
        == "https://generativelanguage.googleapis.com/v1beta/models/gemini-test:generateContent"
    )


async def test_sends_api_key_in_header_not_in_url(
    client: AiClient, fake_gemini: FakeGemini
):
    """The API key is sent in the x-goog-api-key header and never in the URL."""
    await client.summarize(REQUEST)

    [request] = fake_gemini.requests
    assert request.headers["x-goog-api-key"] == API_KEY
    assert API_KEY not in str(request.url)


async def test_sends_system_prompt_user_prompt_and_payload(
    client: AiClient, fake_gemini: FakeGemini
):
    """The system prompt goes into the system instruction.

    The user prompt and the payload are sent as two parts of one user message.
    """
    await client.summarize(REQUEST)

    [request] = fake_gemini.requests
    body = json.loads(request.content)
    assert body["systemInstruction"]["parts"] == [
        {"text": "You are a security analyst."}
    ]
    assert body["contents"] == [
        {
            "role": "user",
            "parts": [{"text": "Summarize:"}, {"text": '{"ip": "8.8.8.8"}'}],
        }
    ]


async def test_uses_configured_timeout(client: AiClient, fake_gemini: FakeGemini):
    """The request uses the timeout from the settings."""
    await client.summarize(REQUEST)

    [request] = fake_gemini.requests
    assert request.extensions["timeout"] == httpx.Timeout(7).as_dict()


async def test_parts_without_text_are_skipped(
    client: AiClient, fake_gemini: FakeGemini
):
    """Non-text parts of the answer, e.g. a function call, are left out."""
    response: dict[str, Any] = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {"text": "a"},
                        {"functionCall": {"name": "f"}},
                        {"text": "b"},
                    ]
                }
            }
        ]
    }
    fake_gemini.handler = lambda _: httpx.Response(200, json=response)

    summary = await client.summarize(REQUEST)

    assert summary.text == "ab"


@pytest.mark.parametrize(
    "response",
    [
        {"promptFeedback": {"blockReason": "SAFETY"}},
        {"candidates": []},
        {"candidates": [{"finishReason": "SAFETY"}]},
        {"candidates": [{"content": {"role": "model"}}]},
        {"candidates": [{"content": {"parts": [{"text": ""}]}}]},
    ],
)
async def test_response_without_generated_text_raises(
    client: AiClient, fake_gemini: FakeGemini, response: dict[str, Any]
):
    """An answer without any generated text raises UnusableResponseError.

    E.g. a blocked prompt, no candidates, or only empty text.
    """
    fake_gemini.handler = lambda _: httpx.Response(200, json=response)

    with pytest.raises(UnusableResponseError, match="no generated text"):
        await client.summarize(REQUEST)


@pytest.mark.parametrize(
    ("status_code", "error_type"),
    [
        (400, errors.ClientError),
        (401, errors.ClientError),
        (403, errors.ClientError),
        (404, errors.ClientError),
        (429, errors.ClientError),
        (500, errors.ServerError),
        (503, errors.ServerError),
    ],
)
async def test_error_status_raises_api_error(
    client: AiClient,
    fake_gemini: FakeGemini,
    status_code: int,
    error_type: type[errors.APIError],
):
    """An error status raises the matching SDK error with the status code.

    4xx gives ClientError, 5xx gives ServerError.
    """
    fake_gemini.handler = lambda _: gemini_error(status_code)

    with pytest.raises(error_type) as exc_info:
        await client.summarize(REQUEST)

    assert exc_info.value.code == status_code


@pytest.mark.parametrize("status_code", [429, 503])
async def test_failed_request_is_not_retried(
    client: AiClient, fake_gemini: FakeGemini, status_code: int
):
    """A rate limited or unavailable answer is not retried: one request is sent."""
    fake_gemini.handler = lambda _: gemini_error(status_code)

    with pytest.raises(errors.APIError):
        await client.summarize(REQUEST)

    assert len(fake_gemini.requests) == 1


async def test_network_error_is_propagated(client: AiClient, fake_gemini: FakeGemini):
    """A connection error is raised to the caller unchanged."""

    def raise_connect_error(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    fake_gemini.handler = raise_connect_error

    with pytest.raises(httpx.ConnectError):
        await client.summarize(REQUEST)


async def test_timeout_is_propagated(client: AiClient, fake_gemini: FakeGemini):
    """A timeout is raised to the caller unchanged."""

    def raise_timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    fake_gemini.handler = raise_timeout

    with pytest.raises(httpx.TimeoutException):
        await client.summarize(REQUEST)


async def test_closed_client_cannot_send_requests(
    config: AiConfig, fake_gemini: FakeGemini
):
    """After aclose, summarize raises RuntimeError and sends nothing."""
    ai_client = AiClient(config)
    await ai_client.aclose()

    with pytest.raises(RuntimeError):
        await ai_client.summarize(REQUEST)

    assert fake_gemini.requests == []
