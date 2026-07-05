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
    from .http import AsyncTransport, SyncTransport

logger = logging.getLogger(__name__)


def _sync_sleep(delay: float) -> None:
    """Indirection point so tests can stub retries without patching stdlib time."""
    time.sleep(delay)


async def _async_sleep(delay: float) -> None:
    """Indirection point so tests can stub retries without patching asyncio globally."""
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


_RequestResult = dict[str, Any] | list[Any] | str


def _process_response(
    response: Any,  # noqa: ANN401
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
) -> dict[str, Any] | list[Any] | str:
    """Execute a synchronous request using the shared retry policy."""
    for attempt in range(policy.max_retries + 1):
        try:
            response = transport.get(
                policy.base_url,
                request_params,
                policy.timeout,
            )
        except (TimeoutError, OSError) as exc:
            _sync_sleep(_handle_request_error(exc, attempt, policy))
            continue
        except UnicodeDecodeError as exc:
            msg = f"Response decoding failed: {exc}"
            raise DomainIQAPIError(msg, status_code=None) from exc
        except RuntimeError as exc:
            _msg = str(exc).lower()
            if any(k in _msg for k in ("closed", "shut", "terminated")):
                logger.warning("Transport closed on attempt %s: %s", attempt, exc)
                _os_error = OSError(f"Transport closed: {exc}")
                _os_error.__cause__ = exc
                _sync_sleep(_handle_request_error(_os_error, attempt, policy))
                continue
            raise

        decision = _process_response(response, attempt, policy, output_format)
        if decision[0] == "retry":
            _sync_sleep(decision[1])
            continue
        return decision[1]

    _unreachable = "unreachable"
    raise RuntimeError(_unreachable)  # pragma: no cover


async def execute_async_request(
    transport: AsyncTransport,
    request_params: dict[str, str],
    output_format: str,
    policy: RequestPolicy,
) -> dict[str, Any] | list[Any] | str:
    """Execute an asynchronous request using the shared retry policy."""
    for attempt in range(policy.max_retries + 1):
        try:
            response = await transport.get(
                policy.base_url,
                request_params,
                policy.timeout,
            )
        except (TimeoutError, OSError) as exc:
            await _async_sleep(_handle_request_error(exc, attempt, policy))
            continue
        except UnicodeDecodeError as exc:
            msg = f"Response decoding failed: {exc}"
            raise DomainIQAPIError(msg, status_code=None) from exc
        except RuntimeError as exc:
            _msg = str(exc).lower()
            if any(k in _msg for k in ("closed", "shut", "terminated")):
                logger.warning("Transport closed on attempt %s: %s", attempt, exc)
                _os_error = OSError(f"Transport closed: {exc}")
                _os_error.__cause__ = exc
                await _async_sleep(_handle_request_error(_os_error, attempt, policy))
                continue
            raise

        decision = _process_response(response, attempt, policy, output_format)
        if decision[0] == "retry":
            await _async_sleep(decision[1])
            continue
        return decision[1]

    _unreachable = "unreachable"
    raise RuntimeError(_unreachable)  # pragma: no cover


__all__ = [
    "RequestPolicy",
    "classify_http_response",
    "execute_async_request",
    "execute_sync_request",
    "parse_response_body",
]
