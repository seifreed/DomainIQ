"""HTTP response classification and retry policy helpers."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ._http_constants import HTTP_BAD_REQUEST, HTTP_TOO_MANY_REQUESTS, HTTP_UNAUTHORIZED
from .constants import API_FORMAT_JSON
from .exceptions import (
    DomainIQAPIError,
    DomainIQAuthenticationError,
    DomainIQRateLimitError,
    DomainIQTimeoutError,
)
from .utils import compute_backoff, parse_retry_after

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .http import AsyncResponse, SyncResponse

logger = logging.getLogger(__name__)

_RETRYABLE_STATUSES: frozenset[int] = frozenset({500, 502, 503, 504})


@dataclass(frozen=True)
class RequestPolicy:
    """Runtime request policy shared by sync and async clients."""

    base_url: str
    timeout: float
    max_retries: int
    retry_delay: int


def _compute_retry_delay(
    status_code: int,
    retry_after_secs: int | None,
    attempt: int,
    policy: RequestPolicy,
) -> float | None:
    if status_code in _RETRYABLE_STATUSES:
        if attempt < policy.max_retries:
            return compute_backoff(policy.retry_delay, attempt)
        return None

    if status_code == HTTP_TOO_MANY_REQUESTS and attempt < policy.max_retries:
        if retry_after_secs is not None:
            return float(max(retry_after_secs, 1))
        return compute_backoff(policy.retry_delay, attempt)

    return None


def _handle_retryable_status(
    status_code: int,
    response_text: str,
    attempt: int,
    policy: RequestPolicy,
) -> float | None:
    delay = _compute_retry_delay(status_code, None, attempt, policy)
    if delay is not None:
        logger.warning(
            "Server error %s, retrying in %ss (attempt %s/%s)",
            status_code,
            delay,
            attempt + 1,
            policy.max_retries + 1,
        )
        return delay
    msg = f"API request failed with status {status_code}: {response_text[:500]}"
    raise DomainIQAPIError(msg, status_code=status_code)


def _handle_rate_limit(
    response_headers: Mapping[str, str],
    attempt: int,
    policy: RequestPolicy,
) -> float | None:
    retry_after_secs = parse_retry_after(response_headers)
    delay = _compute_retry_delay(
        HTTP_TOO_MANY_REQUESTS,
        retry_after_secs,
        attempt,
        policy,
    )
    if delay is not None:
        logger.warning(
            "Rate limited, retrying in %ss (attempt %s/%s)",
            delay,
            attempt + 1,
            policy.max_retries + 1,
        )
        return delay
    msg = "Rate limit exceeded"
    raise DomainIQRateLimitError(msg, retry_after=retry_after_secs)


def classify_http_response(
    status_code: int,
    response_text: str,
    response_headers: Mapping[str, str],
    attempt: int,
    policy: RequestPolicy,
) -> float | None:
    """Return a retry delay, None for success, or raise a fatal error."""
    if status_code in _RETRYABLE_STATUSES:
        return _handle_retryable_status(status_code, response_text, attempt, policy)
    if status_code == HTTP_UNAUTHORIZED:
        msg = "Invalid API key or authentication failed"
        raise DomainIQAuthenticationError(msg)
    if status_code == HTTP_TOO_MANY_REQUESTS:
        return _handle_rate_limit(response_headers, attempt, policy)
    if status_code >= HTTP_BAD_REQUEST:
        msg = f"API request failed with status {status_code}: {response_text[:500]}"
        raise DomainIQAPIError(msg, status_code=status_code)
    return None


def parse_response_body(
    response: SyncResponse | AsyncResponse,
    output_format: str,
) -> dict[str, Any] | list[Any] | str:
    """Parse a successful HTTP response into the expected Python type."""
    if output_format == API_FORMAT_JSON:
        try:
            return response.json()
        except ValueError as exc:
            msg = f"Failed to parse JSON response: {exc}"
            raise DomainIQAPIError(msg) from exc
    return response.text


def on_timeout_error(
    exc: TimeoutError,
    attempt: int,
    policy: RequestPolicy,
) -> float:
    if attempt < policy.max_retries:
        delay = compute_backoff(policy.retry_delay, attempt)
        logger.warning(
            "Request timed out, retrying in %ss (attempt %s/%s)",
            delay,
            attempt + 1,
            policy.max_retries + 1,
        )
        return delay
    msg = f"Request timed out after {policy.timeout}s"
    raise DomainIQTimeoutError(msg) from exc


def on_os_error(
    exc: OSError,
    attempt: int,
    policy: RequestPolicy,
) -> float:
    if attempt < policy.max_retries:
        delay = compute_backoff(policy.retry_delay, attempt)
        logger.warning(
            "Request failed: %s, retrying in %ss (attempt %s/%s)",
            exc,
            delay,
            attempt + 1,
            policy.max_retries + 1,
        )
        return delay
    msg = f"Request failed: {exc}"
    raise DomainIQAPIError(msg) from exc


__all__ = [
    "RequestPolicy",
    "classify_http_response",
    "on_os_error",
    "on_timeout_error",
    "parse_response_body",
]
