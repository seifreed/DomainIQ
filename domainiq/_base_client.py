"""Internal base class shared by DomainIQClient and AsyncDomainIQClient.

Not part of the public API — do not import from outside this package.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Unpack

if TYPE_CHECKING:
    from collections.abc import Awaitable

from .config import Config, ConfigKwargs
from .constants import API_FORMAT_CSV, API_FORMAT_JSON
from ._http_constants import HTTP_BAD_REQUEST, HTTP_TOO_MANY_REQUESTS, HTTP_UNAUTHORIZED
from .exceptions import (
    DomainIQAPIError,
    DomainIQAuthenticationError,
    DomainIQRateLimitError,
    DomainIQTimeoutError,
)
from .formatters import format_api_params, sanitize_params_for_log
from .utils import assert_json_dict, compute_backoff, parse_retry_after

logger = logging.getLogger(__name__)

_RETRYABLE_STATUSES: frozenset[int] = frozenset({500, 502, 503, 504})


def _compute_retry_delay(
    status_code: int,
    retry_after_secs: int | None,
    attempt: int,
    max_retries: int,
    retry_delay: int,
) -> float | None:
    """Pure decision: return backoff delay for retryable statuses, None otherwise.

    Does not log or raise — callers handle those concerns.
    retry_after_secs is pre-computed by the caller (only meaningful for 429).
    """
    if status_code in _RETRYABLE_STATUSES:
        if attempt < max_retries:
            return compute_backoff(retry_delay, attempt)
        return None  # exhausted — caller will raise

    if status_code == HTTP_TOO_MANY_REQUESTS and attempt < max_retries:
        return (
            max(retry_after_secs, 1)
            if retry_after_secs is not None
            else compute_backoff(retry_delay, attempt)
        )

    return None  # 2xx, 401, 4xx, or exhausted retries


def classify_http_response(
    status_code: int,
    response_text: str,
    response_headers: Mapping[str, str],
    attempt: int,
    max_retries: int,
    retry_delay: int,
) -> float | None:
    """Classify HTTP response status and decide action.

    Returns float delay for retry, None for success (2xx), raises for fatal errors.
    """
    if status_code in _RETRYABLE_STATUSES:
        delay = _compute_retry_delay(
            status_code, None, attempt, max_retries, retry_delay
        )
        if delay is not None:
            logger.warning(
                "Server error %s, retrying in %ss (attempt %s/%s)",
                status_code, delay, attempt + 1, max_retries + 1,
            )
            return delay
        msg = f"API request failed with status {status_code}: {response_text}"
        raise DomainIQAPIError(msg, status_code=status_code)

    if status_code == HTTP_UNAUTHORIZED:
        raise DomainIQAuthenticationError("Invalid API key or authentication failed")

    if status_code == HTTP_TOO_MANY_REQUESTS:
        retry_after_secs = parse_retry_after(response_headers)
        delay = _compute_retry_delay(
            status_code, retry_after_secs, attempt, max_retries, retry_delay
        )
        if delay is not None:
            logger.warning(
                "Rate limited, retrying in %ss (attempt %s/%s)",
                delay, attempt + 1, max_retries + 1,
            )
            return delay
        raise DomainIQRateLimitError("Rate limit exceeded", retry_after=retry_after_secs)

    if status_code >= HTTP_BAD_REQUEST:
        msg = f"API request failed with status {status_code}: {response_text}"
        raise DomainIQAPIError(msg, status_code=status_code)

    return None  # 2xx success


def _on_timeout_error(
    exc: TimeoutError,
    attempt: int,
    max_retries: int,
    retry_delay: int,
    timeout: float,
) -> float:
    """Return backoff delay if retries remain, else raise DomainIQTimeoutError."""
    if attempt < max_retries:
        delay = compute_backoff(retry_delay, attempt)
        logger.warning(
            "Request timed out, retrying in %ss (attempt %s/%s)",
            delay, attempt + 1, max_retries + 1,
        )
        return delay
    msg = f"Request timed out after {timeout}s"
    raise DomainIQTimeoutError(msg) from exc


def _on_os_error(
    exc: OSError,
    attempt: int,
    max_retries: int,
    retry_delay: int,
) -> float:
    """Return backoff delay if retries remain, else raise DomainIQAPIError."""
    if attempt < max_retries:
        delay = compute_backoff(retry_delay, attempt)
        logger.warning(
            "Request failed: %s, retrying in %ss (attempt %s/%s)",
            exc, delay, attempt + 1, max_retries + 1,
        )
        return delay
    msg = f"Request failed: {exc}"
    raise DomainIQAPIError(msg) from exc


class _BaseDomainIQClient:
    """Common state and helpers for sync and async DomainIQ clients.

    Subclasses own _handle_error_status, _parse_response, _make_request,
    and all public API methods — those cannot be shared across async/sync.

    _make_request canonical algorithm (duplicated in subclasses due to sync/async divergence):
        for attempt in range(max_retries + 1):
            try: response = [await] transport.get(url, params, timeout)
            except TimeoutError → [await] sleep(_on_timeout(e, attempt)); continue
            except OSError     → [await] sleep(_on_oserror(e, attempt)); continue
            delay = [await] _handle_error_status(response, attempt)
            if delay: [await] sleep(delay); continue
            return [await] _parse_response(response, format)
        raise DomainIQAPIError(RETRY_EXHAUSTED_MSG)
    """

    _RETRYABLE_STATUSES: frozenset[int] = _RETRYABLE_STATUSES

    # ── Construction ──────────────────────────────────────────────────────────
    def __init__(
        self,
        config: Config | None = None,
        **kwargs: Unpack[ConfigKwargs],
    ) -> None:
        """Initialize base client state.

        Side effects:
            Calls config.validate(), which may write the API key to disk if it
            was obtained interactively during Config construction (persisted to
            config_file, default ~/.domainiq, with mode 0o600).
        """
        if config is None:
            config = Config(**kwargs)
        config.validate()  # may persist API key to disk; see docstring
        self.config = config

    # ── Error-handling adapters (thin wrappers over module-level pure fns) ───
    def _on_timeout(self, exc: TimeoutError, attempt: int) -> float:
        """Return backoff delay for a timeout, or raise DomainIQTimeoutError."""
        return _on_timeout_error(
            exc, attempt, self.config.max_retries, self.config.retry_delay, self.config.timeout
        )

    def _on_oserror(self, exc: OSError, attempt: int) -> float:
        """Return backoff delay for a network error, or raise DomainIQAPIError."""
        return _on_os_error(exc, attempt, self.config.max_retries, self.config.retry_delay)

    def _classify_response(
        self,
        status_code: int,
        response_text: str,
        response_headers: Mapping[str, str],
        attempt: int,
    ) -> float | None:
        """Classify HTTP response status; return retry delay, None for success, or raise."""
        return classify_http_response(
            status_code, response_text, response_headers,
            attempt, self.config.max_retries, self.config.retry_delay,
        )

    # ── Request building ──────────────────────────────────────────────────────
    def _build_request_params(
        self,
        params: dict[str, Any],
        output_format: str,
    ) -> dict[str, str]:
        """Build and log the final query-parameter dict for an API call."""
        request_params: dict[str, str] = {
            **format_api_params(params),
            "key": self.config.api_key,
        }
        if output_format == API_FORMAT_JSON:
            request_params["output_mode"] = API_FORMAT_JSON
        elif output_format == API_FORMAT_CSV:
            request_params["output_mode"] = API_FORMAT_CSV
        logger.debug(
            "Making API request with params: %s",
            sanitize_params_for_log(request_params),
        )
        return request_params


_assert_json_dict = assert_json_dict


def _assert_json_dict_or_list(
    raw: dict[str, Any] | list[Any] | str,
) -> dict[str, Any] | list[Any]:
    """Validate that a raw API response is a JSON dict or list."""
    if isinstance(raw, (dict, list)):
        return raw
    msg = f"Expected JSON dict or list but got {type(raw).__name__}: {raw!r}"
    raise DomainIQAPIError(msg)


def _assert_csv_str(raw: dict[str, Any] | list[Any] | str) -> str:
    """Validate that a raw API response is a CSV string."""
    if isinstance(raw, str):
        return raw
    msg = "Expected CSV response but got JSON"
    raise DomainIQAPIError(msg)


class _SyncRequestable(ABC):
    """Abstract base declaring infrastructure methods required by sync mixins.

    Any class that inherits a sync mixin must implement these three methods.
    Python raises TypeError at class creation time if they are missing.
    """

    @abstractmethod
    def _make_json_request(self, params: dict[str, Any]) -> dict[str, Any]: ...

    @abstractmethod
    def _make_json_request_maybe_list(
        self, params: dict[str, Any]
    ) -> dict[str, Any] | list[Any]: ...

    @abstractmethod
    def _make_csv_request(self, params: dict[str, Any]) -> str: ...


class _AsyncRequestable(ABC):
    """Abstract base declaring infrastructure methods required by async mixins.

    Any class that inherits an async mixin must implement these three coroutines.
    Python raises TypeError at class creation time if they are missing.
    """

    @abstractmethod
    async def _make_json_request(self, params: dict[str, Any]) -> dict[str, Any]: ...

    @abstractmethod
    async def _make_json_request_maybe_list(
        self, params: dict[str, Any]
    ) -> dict[str, Any] | list[Any]: ...

    @abstractmethod
    async def _make_csv_request(self, params: dict[str, Any]) -> str: ...
