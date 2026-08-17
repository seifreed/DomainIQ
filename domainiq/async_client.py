"""Asynchronous client for the DomainIQ API."""

import asyncio
import functools
import logging
import warnings
from typing import TYPE_CHECKING, Any, Self, TypeVar, Unpack

from ._async_concurrency import _LookupFailure, _run_with_critical_cancel
from ._base_client import (
    _assert_csv_str,
    _assert_json_dict_or_list,
    _BaseDomainIQClient,
    _warn_if_unclosed,
)
from ._mixins import (
    _AsyncBulkMixin,
    _AsyncDNSMixin,
    _AsyncDomainAnalysisMixin,
    _AsyncLimitsMixin,
    _AsyncMonitorMixin,
    _AsyncQueueMixin,
    _AsyncReportMixin,
    _AsyncSearchMixin,
    _AsyncWhoisMixin,
)
from ._models import DNSRecordType, DNSResult, WhoisResult
from ._request_pipeline import _async_sleep, execute_async_request
from .constants import API_FORMAT_CSV, API_FORMAT_JSON
from .exceptions import (
    DomainIQAPIError,
    DomainIQAuthenticationError,
    DomainIQConfigurationError,
    DomainIQError,
    DomainIQRateLimitError,
    DomainIQTimeoutError,
    DomainIQValidationError,
)
from .http import AiohttpTransport, AsyncTransport
from .utils import assert_json_dict
from .validators import ensure_positive_int, is_ip_address

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine
    from types import TracebackType

    from ._request_pipeline import AsyncSleeper
    from .config import Config, ConfigKwargs

logger = logging.getLogger(__name__)

_HTTP_SERVER_ERROR_MIN = 500
_LT = TypeVar("_LT")


def _try_sync_close(transport: AsyncTransport) -> None:
    """Invoke the transport's best-effort synchronous teardown, if it has one."""
    sync_close = getattr(transport, "try_sync_close", None)
    if sync_close is not None:
        sync_close()


def _make_default_async_transport(
    config: Config,
    transport_factory: Callable[..., AsyncTransport] = AiohttpTransport,
) -> AsyncTransport:
    """Create default AiohttpTransport from config. ImportError → DomainIQError."""
    try:
        return transport_factory(
            connector_limit=config.connector_limit,
            connector_limit_per_host=config.connector_limit_per_host,
        )
    except ImportError as e:
        raise DomainIQError(str(e)) from e


class AsyncDomainIQClient(
    _AsyncWhoisMixin,
    _AsyncDNSMixin,
    _AsyncDomainAnalysisMixin,
    _AsyncReportMixin,
    _AsyncSearchMixin,
    _AsyncBulkMixin,
    _AsyncMonitorMixin,
    _AsyncQueueMixin,
    _AsyncLimitsMixin,
    _BaseDomainIQClient,
):
    """Asynchronous client for the DomainIQ API.

    This client provides async/await methods to interact with all
    DomainIQ API endpoints with better performance for concurrent
    operations.

    Requires aiohttp to be installed:
        pip install aiohttp

    Type annotation guidance
    ------------------------
    Annotate function arguments with the narrowest Protocol that covers
    the capabilities required, not with the concrete client class::

        Full surface:     domainiq.protocols.AsyncDomainIQClientProtocol
        WHOIS only:       domainiq.protocols.AsyncWhoisProtocol
        DNS only:         domainiq.protocols.AsyncDNSProtocol
        Reports:          domainiq.protocols.AsyncReportProtocol
        Search:           domainiq.protocols.AsyncSearchProtocol
        Bulk ops:         domainiq.protocols.AsyncBulkProtocol
        Monitoring:       domainiq.protocols.AsyncMonitorProtocol
        Domain analysis:  domainiq.protocols.AsyncDomainAnalysisProtocol
        Queued requests:  domainiq.protocols.AsyncQueueProtocol
        Account limits:   domainiq.protocols.AsyncLimitsProtocol

    This decouples callers from the concrete class and enables lightweight
    test fakes that implement only the required protocol.
    """

    def __init__(
        self,
        config: Config | None = None,
        transport: AsyncTransport | None = None,
        *,
        sleeper: AsyncSleeper = _async_sleep,
        **kwargs: Unpack[ConfigKwargs],
    ) -> None:
        """Initialize the async DomainIQ client.

        Args:
            config: Configuration object. If None, will create default config.
            transport: Async HTTP transport. Defaults to AiohttpTransport.
            sleeper: Coroutine called to pause between retries. Defaults to
                ``asyncio.sleep``; inject a no-op to make retries instant in tests.
            **kwargs: Additional arguments passed to Config

        Raises:
            DomainIQError: If aiohttp is not available and no transport is given
        """
        super().__init__(config=config, **kwargs)
        self._transport: AsyncTransport = (
            transport
            if transport is not None
            else _make_default_async_transport(self.config)
        )
        self._sleeper: AsyncSleeper = sleeper

        logger.debug(
            "Initialized async DomainIQ client with config: %s",
            self.config,
        )

    async def _make_request(
        self,
        params: dict[str, Any],
        output_format: str = API_FORMAT_JSON,
    ) -> dict[str, Any] | list[Any] | str:
        """Make an async API request using the shared request pipeline."""
        request_params = self._build_request_params(params, output_format)
        return await execute_async_request(
            self._transport,
            request_params,
            output_format,
            self._request_policy(),
            self._sleeper,
        )

    async def _make_json_request(self, params: dict[str, Any]) -> dict[str, Any]:
        """Make async API request expecting JSON response."""
        return assert_json_dict(
            await self._make_request(params, output_format=API_FORMAT_JSON)
        )

    async def _make_json_request_maybe_list(
        self, params: dict[str, Any]
    ) -> dict[str, Any] | list[Any]:
        """Make async API request expecting JSON (dict or list)."""
        return _assert_json_dict_or_list(
            await self._make_request(params, output_format=API_FORMAT_JSON)
        )

    async def _make_csv_request(self, params: dict[str, Any]) -> str:
        """Make async API request expecting CSV response."""
        return _assert_csv_str(
            await self._make_request(params, output_format=API_FORMAT_CSV)
        )

    async def _concurrent_lookup(
        self,
        inner_fn: Callable[[str], Coroutine[Any, Any, _LT]],
        targets: list[str],
        max_concurrent: int,
        label: str,
        result_type: type[_LT],
    ) -> list[_LT | None]:
        """Generic concurrent lookup with semaphore and critical-error cancellation."""
        max_concurrent = ensure_positive_int("max_concurrent", max_concurrent)
        semaphore = asyncio.Semaphore(max_concurrent)

        async def _bounded(target: str) -> _LT | _LookupFailure:
            async with semaphore:
                try:
                    return await inner_fn(target)
                except (
                    DomainIQAuthenticationError,
                    DomainIQConfigurationError,
                    DomainIQRateLimitError,
                ):
                    raise
                except DomainIQAPIError as e:
                    if (
                        e.status_code is not None
                        and e.status_code >= _HTTP_SERVER_ERROR_MIN
                    ):
                        raise
                    logger.warning("%s lookup failed for %s: %s", label, target, e)
                    return _LookupFailure(target, e)
                except (
                    DomainIQTimeoutError,
                    DomainIQValidationError,
                    TimeoutError,
                    OSError,
                ) as e:
                    logger.warning("%s lookup failed for %s: %s", label, target, e)
                    return _LookupFailure(target, e)

        return await _run_with_critical_cancel(
            [_bounded(t) for t in targets],
            result_type,
        )

    async def concurrent_whois_lookup(
        self,
        targets: list[str],
        max_concurrent: int = 10,
    ) -> list[WhoisResult | None]:
        """Perform multiple WHOIS lookups concurrently.

        On a critical error (auth, config, rate-limit) in any lookup,
        in-flight tasks are cancelled and a ``DomainIQPartialResultsError``
        is raised (with the triggering exception as its ``__cause__``). Its
        ``partial_results`` attribute holds the results (or ``None``) already
        completed before the failure, aligned by task submission order.
        """

        async def _do(target: str) -> WhoisResult:
            if is_ip_address(target):
                return await self.whois_lookup(ip=target)
            return await self.whois_lookup(domain=target)

        return await self._concurrent_lookup(
            _do, targets, max_concurrent, "WHOIS", WhoisResult
        )

    async def concurrent_dns_lookup(
        self,
        domains: list[str],
        record_types: list[str | DNSRecordType] | None = None,
        max_concurrent: int = 10,
    ) -> list[DNSResult | None]:
        """Perform multiple DNS lookups concurrently.

        See ``concurrent_whois_lookup`` for the critical-error cancellation
        and ``partial_results`` behavior.
        """

        async def _do(domain: str) -> DNSResult:
            return await self.dns_lookup(domain, record_types)

        return await self._concurrent_lookup(
            _do, domains, max_concurrent, "DNS", DNSResult
        )

    async def close(self) -> None:
        """Close the HTTP transport."""
        await self._transport.close()

    async def __aenter__(self) -> Self:
        """Async context manager entry."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Async context manager exit."""
        await self.close()

    def __del__(self) -> None:
        """Warn if transport was not properly closed."""
        transport: AsyncTransport | None = getattr(self, "_transport", None)
        if transport is None:
            return
        _warn_if_unclosed(
            transport,
            functools.partial(_try_sync_close, transport),
            f"Unclosed {self.__class__.__name__}. "
            "Use 'async with' or call 'await client.close()' explicitly.",
            getattr(warnings, "warn", None),
        )
