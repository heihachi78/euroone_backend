"""Async client for the Google Gemini API."""

import logging
from http import HTTPStatus

from google import genai
from google.genai import types

from app.clients.errors import UnusableResponseError
from app.core.ai_config import AiConfig
from app.models.ai.summary import Summary
from app.models.ai.summary_request import SummaryRequest

logger = logging.getLogger(__name__)


class AiClient:
    """Generates summaries with Gemini."""

    def __init__(self, config: AiConfig) -> None:
        """Create the underlying Gemini client.

        Args:
            config: Gemini API key, model name and request timeout.
        """
        self._model = config.model
        self._client = genai.Client(
            api_key=config.api_key.get_secret_value(),
            http_options=types.HttpOptionsDict(
                timeout=int(config.timeout_seconds * 1000)
            ),
        ).aio

    async def summarize(self, request: SummaryRequest) -> Summary:
        """Send a summary request to Gemini. Failed requests are not retried.

        Args:
            request: The prompts and the payload to summarize.

        Returns:
            The generated text with HTTP status 200.

        Raises:
            google.genai.errors.APIError: If Gemini returns an error status.
            httpx.RequestError: If the request cannot be sent or times out.
            UnusableResponseError: If the response contains no generated text.
            RuntimeError: If the client has already been closed.
        """
        response = await self._client.models.generate_content(  # pyright: ignore[reportUnknownMemberType]
            model=self._model,
            contents=[request.user_prompt, request.payload],
            config=types.GenerateContentConfigDict(
                system_instruction=request.system_prompt
            ),
        )
        logger.info("Gemini responded for model=%s", self._model)
        if not response.text:
            raise UnusableResponseError(
                f"Gemini response contains no generated text: {response}"
            )
        return Summary(status_code=HTTPStatus.OK, text=response.text)

    async def aclose(self) -> None:
        """Close the underlying connections; the client cannot be used afterwards."""
        await self._client.aclose()
