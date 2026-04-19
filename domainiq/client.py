"""Main client for the DomainIQ API."""

import logging
import time
from types import TracebackType
from typing import Any, Self, Unpack

from ._base_client import (
    _BaseDomainIQClient,
    _assert_csv_str,
    _assert_json_dict,
    _assert_json_dict_or_list,
)
from .constants import API_FORMAT_CSV, API_FORMAT_JSON, RETRY_EXHAUSTED_MSG
from ._mixins import (
    _BulkMixin,
    _DNSMixin,
    _DomainAnalysisMixin,
    _MonitorMixin,
    _ReportMixin,
    _SearchMixin,
    _WhoisMixin,
)
from .config import Config, ConfigKwargs
from .exceptions import DomainIQAPIError
from .http_transport import RequestsTransport, SyncResponse, SyncTransport

logger = logging.getLogger(__name__)


class DomainIQClient(
    _WhoisMixin, _DNSMixin, _DomainAnalysisMixin,
    _ReportMixin, _SearchMixin, _BulkMixin, _MonitorMixin,
    _BaseDomainIQClient,
):
    """Synchronous client for the DomainIQ API.

    This client provides methods to interact with all DomainIQ API
    endpoints including WHOIS lookups, DNS queries, domain reports,
    monitoring, and more.

    Type annotation guidance
    ------------------------
    Annotate function arguments with the narrowest Protocol that covers
    the capabilities required, not with the concrete client class::

        Full surface:     domainiq.protocols.DomainIQClientProtocol
        WHOIS only:       domainiq.protocols.WhoisProtocol
        DNS only:         domainiq.protocols.DNSProtocol
        Reports:          domainiq.protocols.ReportProtocol
        Search:           domainiq.protocols.SearchProtocol
        Bulk ops:         domainiq.protocols.BulkProtocol
        Monitoring:       domainiq.protocols.MonitorProtocol
        Domain analysis:  domainiq.protocols.DomainAnalysisProtocol

    This decouples callers from the concrete class and enables lightweight
    test fakes that implement only the required protocol.
    """

    def __init__(
        self,
        config: Config | None = None,
        transport: SyncTransport | None = None,
        **kwargs: Unpack[ConfigKwargs],
    ) -> None:
        """Initialize the DomainIQ client.

        Args:
            config: Configuration object. If None, will create default config.
            transport: HTTP transport to use. Defaults to RequestsTransport.
            **kwargs: Additional arguments passed to Config if config is None
        """
        super().__init__(config=config, **kwargs)
        self._transport: SyncTransport = transport if transport is not None else RequestsTransport()

        logger.debug("Initialized DomainIQ client with config: %s", self.config)

    def _handle_error_status(
        self, response: SyncResponse, attempt: int
    ) -> float | None:
        """Delegate to shared error classifier. Returns retry delay or None for success."""
        return self._classify_response(
            response.status_code, response.text, response.headers, attempt
        )

    def _parse_response(
        self, response: SyncResponse, output_format: str
    ) -> dict[str, Any] | list[Any] | str:
        """Parse a successful HTTP response into the expected Python type."""
        if output_format == API_FORMAT_JSON:
            try:
                json_response: dict[str, Any] | list[Any] = response.json()
            except ValueError as e:
                msg = f"Failed to parse JSON response: {e}"
                raise DomainIQAPIError(msg) from e
            logger.debug("API JSON response: %s", json_response)
            return json_response
        return response.text

    def _make_request(
        self, params: dict[str, Any], output_format: str = API_FORMAT_JSON
    ) -> dict[str, Any] | list[Any] | str:
        """Make an API request to DomainIQ.

        Args:
            params: Request parameters
            output_format: Output format ('json' or 'csv')

        Returns:
            Response data as dict (JSON) or string (CSV)

        Raises:
            DomainIQAPIError: If the API returns an error
            DomainIQAuthenticationError: If authentication fails
            DomainIQRateLimitError: If rate limit is exceeded
            DomainIQTimeoutError: If request times out
        """
        request_params = self._build_request_params(params, output_format)

        for attempt in range(self.config.max_retries + 1):
            try:
                response = self._transport.get(
                    self.config.base_url,
                    params=request_params,
                    timeout=self.config.timeout,
                )
            except TimeoutError as e:
                time.sleep(self._on_timeout(e, attempt))
                continue
            except OSError as e:
                time.sleep(self._on_oserror(e, attempt))
                continue

            logger.debug("API response status: %s", response.status_code)

            retry_delay = self._handle_error_status(response, attempt)
            if retry_delay is not None:
                time.sleep(retry_delay)
                continue

            return self._parse_response(response, output_format)

        raise DomainIQAPIError(RETRY_EXHAUSTED_MSG)

    def _make_json_request(self, params: dict[str, Any]) -> dict[str, Any]:
        """Make an API request expecting a JSON dict response."""
        return _assert_json_dict(self._make_request(params, output_format=API_FORMAT_JSON))

    def _make_json_request_maybe_list(
        self, params: dict[str, Any]
    ) -> dict[str, Any] | list[Any]:
        """Make API request expecting JSON (may be dict or list)."""
        return _assert_json_dict_or_list(self._make_request(params, output_format=API_FORMAT_JSON))

    def _make_csv_request(self, params: dict[str, Any]) -> str:
        """Make an API request expecting CSV response."""
        return _assert_csv_str(self._make_request(params, output_format=API_FORMAT_CSV))

    def close(self) -> None:
        """Close the HTTP session."""
        self._transport.close()

    def __enter__(self) -> Self:
        """Context manager entry."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Context manager exit."""
        self.close()
