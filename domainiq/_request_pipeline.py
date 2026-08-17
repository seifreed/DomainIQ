"""Shared request execution pipeline for sync and async clients."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Any, Literal

from .exceptions import DomainIQAPIError
from .request_policy import (
    RequestPolicy,
    classify_http_response,
    on_os_error,
    on_timeout_error,
    parse_response_body,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from .http import AsyncTransport, SyncTransport
    from .http._responses import AsyncResponse, SyncResponse

    SyncSleeper = Callable[[float], None]
    AsyncSleeper = Callable[[float], Awaitable[None]]

logger = logging.getLogger(__name__)


def _sync_sleep(delay: float) -> None:
    """Sleep between synchronous retries (injectable via ``execute_sync_request``)."""
    time.sleep(delay)


async def _async_sleep(delay: float) -> None:
    """Sleep between async retries (injectable via ``execute_async_request``)."""
    await asyncio.sleep(delay)


def _handle_request_error(
    exc: TimeoutError | OSError,
    attempt: int,
    policy: RequestPolicy,
) -> float:
    """Map a network exception to its retry delay."""
    if isinstance(exc, TimeoutError):
        return on_timeout_error(exc, attempt, policy)
    return on_os_error(exc, attempt, policy)


def _transport_closed_delay(
    exc: RuntimeError,
    attempt: int,
    policy: RequestPolicy,
) -> float:
    """Map a transport-closed RuntimeError to its retry delay; re-raise others."""
    if not any(k in str(exc).lower() for k in ("closed", "shut", "terminated")):
        raise exc
    logger.warning("Transport closed on attempt %s: %s", attempt, exc)
    os_error = OSError(f"Transport closed: {exc}")
    os_error.__cause__ = exc
    return _handle_request_error(os_error, attempt, policy)


_RequestResult = dict[str, Any] | list[Any] | str


def _process_response(
    response: SyncResponse | AsyncResponse,
    attempt: int,
    policy: RequestPolicy,
    output_format: str,
) -> tuple[Literal["retry"], float] | tuple[Literal["success"], _RequestResult]:
    """Classify an HTTP response and return either a retry delay or parsed body."""
    logger.debug("API response status: %s", response.status_code)
    retry_delay = classify_http_response(
        response.status_code,
        response.text,
        dict(response.headers),
        attempt,
        policy,
    )
    if retry_delay is not None:
        return ("retry", retry_delay)
    return ("success", parse_response_body(response, output_format))


def execute_sync_request(
    transport: SyncTransport,
    request_params: dict[str, str],
    output_format: str,
    policy: RequestPolicy,
    sleeper: SyncSleeper = _sync_sleep,
) -> dict[str, Any] | list[Any] | str:
    """Execute a synchronous request using the shared retry policy.

    The policy handlers raise once the retry budget is exhausted, so every
    iteration either returns, raises, or retries with a bumped attempt count.
    """
    attempt = 0
    while True:
        try:
            response = transport.get(
                policy.base_url,
                request_params,
                policy.timeout,
            )
        except (TimeoutError, OSError) as exc:
            sleeper(_handle_request_error(exc, attempt, policy))
            attempt += 1
            continue
        except UnicodeDecodeError as exc:
            msg = f"Response decoding failed: {exc}"
            raise DomainIQAPIError(msg, status_code=None) from exc
        except RuntimeError as exc:
            sleeper(_transport_closed_delay(exc, attempt, policy))
            attempt += 1
            continue

        decision = _process_response(response, attempt, policy, output_format)
        if decision[0] == "retry":
            sleeper(decision[1])
            attempt += 1
            continue
        return decision[1]


async def execute_async_request(
    transport: AsyncTransport,
    request_params: dict[str, str],
    output_format: str,
    policy: RequestPolicy,
    sleeper: AsyncSleeper = _async_sleep,
) -> dict[str, Any] | list[Any] | str:
    """Execute an asynchronous request using the shared retry policy.

    The policy handlers raise once the retry budget is exhausted, so every
    iteration either returns, raises, or retries with a bumped attempt count.
    """
    attempt = 0
    while True:
        try:
            response = await transport.get(
                policy.base_url,
                request_params,
                policy.timeout,
            )
        except (TimeoutError, OSError) as exc:
            await sleeper(_handle_request_error(exc, attempt, policy))
            attempt += 1
            continue
        except UnicodeDecodeError as exc:
            msg = f"Response decoding failed: {exc}"
            raise DomainIQAPIError(msg, status_code=None) from exc
        except RuntimeError as exc:
            await sleeper(_transport_closed_delay(exc, attempt, policy))
            attempt += 1
            continue

        decision = _process_response(response, attempt, policy, output_format)
        if decision[0] == "retry":
            await sleeper(decision[1])
            attempt += 1
            continue
        return decision[1]


__all__ = [
    "RequestPolicy",
    "classify_http_response",
    "execute_async_request",
    "execute_sync_request",
    "parse_response_body",
]
