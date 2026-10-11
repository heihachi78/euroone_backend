"""Exception handlers that answer every error with a JSON body of a generic `detail`.

Failed VirusTotal and Gemini calls are answered with gateway errors, failed database
operations and every other exception with 500.
"""

import logging
from collections.abc import Callable, Coroutine
from http import HTTPStatus
from typing import Any

import httpx
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from google.genai import errors
from sqlalchemy.exc import SQLAlchemyError

from app.clients.errors import UnusableResponseError

logger = logging.getLogger(__name__)


def _error_response(
    status: HTTPStatus, detail: str, exc: Exception, level: int = logging.WARNING
) -> JSONResponse:
    """Log the exception and answer with a generic message that hides its details.

    Args:
        status: Status code of the answer.
        detail: Message for the caller.
        exc: The exception being answered.
        level: Logging level of the exception.

    Returns:
        The answer with `detail` as its JSON body.
    """
    logger.log(level, "%s, answering %d", detail, status, exc_info=exc)
    return JSONResponse(status_code=status, content={"detail": detail})


def _error_status_response(api_status: int, exc: Exception) -> JSONResponse:
    """Answer an error status of an API with 503 if it is rate limiting, otherwise 502.

    Args:
        api_status: The status code the API answered with.
        exc: The exception being answered.

    Returns:
        The answer with a generic message.
    """
    if api_status == HTTPStatus.TOO_MANY_REQUESTS:
        return _error_response(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "An external service is rate limited, try again later",
            exc,
        )
    return _error_response(
        HTTPStatus.BAD_GATEWAY, "An external service returned an error", exc
    )


async def _virustotal_error(
    request: Request, exc: httpx.HTTPStatusError
) -> JSONResponse:
    """Answer an error status of VirusTotal."""
    return _error_status_response(exc.response.status_code, exc)


async def _gemini_error(request: Request, exc: errors.APIError) -> JSONResponse:
    """Answer an error status of Gemini."""
    return _error_status_response(exc.code, exc)


async def _timeout(request: Request, exc: httpx.TimeoutException) -> JSONResponse:
    """Answer a request to either API that timed out with 504."""
    return _error_response(
        HTTPStatus.GATEWAY_TIMEOUT, "An external service timed out", exc
    )


async def _unreachable(request: Request, exc: httpx.RequestError) -> JSONResponse:
    """Answer a request to either API that could not be sent with 502."""
    return _error_response(
        HTTPStatus.BAD_GATEWAY, "An external service could not be reached", exc
    )


async def _unusable_response(
    request: Request, exc: UnusableResponseError
) -> JSONResponse:
    """Answer a response of either API that has no usable body with 502."""
    return _error_response(
        HTTPStatus.BAD_GATEWAY, "An external service returned an unusable response", exc
    )


async def _database_error(request: Request, exc: SQLAlchemyError) -> JSONResponse:
    """Answer a failed database operation with 500, logged as an error."""
    return _error_response(
        HTTPStatus.INTERNAL_SERVER_ERROR,
        "A database error occurred",
        exc,
        level=logging.ERROR,
    )


async def _internal_error(request: Request, exc: Exception) -> JSONResponse:
    """Answer any other exception with 500.

    Not logged here: the exception still reaches the server, which logs it.
    """
    return JSONResponse(
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


EXCEPTION_HANDLERS: dict[
    int | type[Exception], Callable[[Request, Any], Coroutine[Any, Any, Response]]
] = {
    httpx.HTTPStatusError: _virustotal_error,
    errors.APIError: _gemini_error,
    httpx.TimeoutException: _timeout,
    httpx.RequestError: _unreachable,
    UnusableResponseError: _unusable_response,
    SQLAlchemyError: _database_error,
    Exception: _internal_error,
}
