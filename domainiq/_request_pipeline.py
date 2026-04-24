"""Shared request execution pipeline for sync and async clients."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Any

from .constants import RETRY_EXHAUSTED_MSG
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
        except TimeoutError as exc:
            _sync_sleep(on_timeout_error(exc, attempt, policy))
            continue
        except OSError as exc:
            _sync_sleep(on_os_error(exc, attempt, policy))
            continue

        logger.debug("API response status: %s", response.status_code)

        retry_delay = classify_http_response(
            response.status_code,
            response.text,
            dict(response.headers),
            attempt,
            policy,
        )
        if retry_delay is not None:
            _sync_sleep(retry_delay)
            continue

        return parse_response_body(response, output_format)

    raise DomainIQAPIError(RETRY_EXHAUSTED_MSG)


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
        except TimeoutError as exc:
            await _async_sleep(on_timeout_error(exc, attempt, policy))
            continue
        except OSError as exc:
            await _async_sleep(on_os_error(exc, attempt, policy))
            continue

        logger.debug("API response status: %s", response.status_code)

        retry_delay = classify_http_response(
            response.status_code,
            response.text,
            dict(response.headers),
            attempt,
            policy,
        )
        if retry_delay is not None:
            await _async_sleep(retry_delay)
            continue

        return parse_response_body(response, output_format)

    raise DomainIQAPIError(RETRY_EXHAUSTED_MSG)


__all__ = [
    "RequestPolicy",
    "classify_http_response",
    "execute_async_request",
    "execute_sync_request",
    "parse_response_body",
]
