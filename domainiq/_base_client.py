"""Internal base class shared by DomainIQClient and AsyncDomainIQClient.

Not part of the public API — do not import from outside this package.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Unpack

from .config import Config, ConfigKwargs
from .constants import API_FORMAT_CSV, API_FORMAT_JSON
from .exceptions import DomainIQAPIError
from .formatters import format_api_params, sanitize_params_for_log
from ._request_pipeline import RequestPolicy
from .utils import assert_json_dict, truncate_repr

logger = logging.getLogger(__name__)


class _BaseDomainIQClient:
    """Common state and helpers for sync and async DomainIQ clients.
    """

    # ── Construction ──────────────────────────────────────────────────────────
    def __init__(
        self,
        config: Config | None = None,
        **kwargs: Unpack[ConfigKwargs],
    ) -> None:
        """Initialize base client state."""
        if config is None:
            config = Config(**kwargs)
        config.validate()
        self.config = config

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

    def _request_policy(self) -> RequestPolicy:
        """Build the request policy for the current client configuration."""
        return RequestPolicy(
            base_url=self.config.base_url,
            timeout=self.config.timeout,
            max_retries=self.config.max_retries,
            retry_delay=self.config.retry_delay,
        )


_assert_json_dict = assert_json_dict


def _assert_json_dict_or_list(
    raw: dict[str, Any] | list[Any] | str,
) -> dict[str, Any] | list[Any]:
    """Validate that a raw API response is a JSON dict or list."""
    if isinstance(raw, (dict, list)):
        return raw
    msg = f"Expected JSON dict or list but got {type(raw).__name__}: {truncate_repr(raw)}"
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
