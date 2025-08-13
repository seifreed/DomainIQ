"""Main client for the DomainIQ API."""

import logging
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import Config
from .exceptions import (
    DomainIQAPIError,
    DomainIQAuthenticationError,
    DomainIQRateLimitError,
    DomainIQTimeoutError,
)
from .models import (
    BulkWhoisType,
    DNSRecordType,
    DNSResult,
    DomainCategory,
    DomainReport,
    DomainSnapshot,
    MatchType,
    MonitorReport,
    ReverseSearchType,
    WhoisResult,
)
from .utils import csv_to_dict_list, format_api_params

logger = logging.getLogger(__name__)

# HTTP status code constants
HTTP_UNAUTHORIZED = 401
HTTP_TOO_MANY_REQUESTS = 429
HTTP_BAD_REQUEST = 400


class DomainIQClient:
    """Synchronous client for the DomainIQ API.

    This client provides methods to interact with all DomainIQ API endpoints
    including WHOIS lookups, DNS queries, domain reports, monitoring, and more.
    """

    def __init__(self, config: Config | None = None, **kwargs: Any) -> None:
        """Initialize the DomainIQ client.

        Args:
            config: Configuration object. If None, will create default config.
            **kwargs: Additional arguments passed to Config if config is None
        """
        if config is None:
            config = Config(**kwargs)

        config.validate()
        self.config = config

        # Setup session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=config.max_retries,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
            backoff_factor=config.retry_delay
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        logger.debug("Initialized DomainIQ client with config: %s", config)

    def _make_request(
        self,
        params: dict[str, Any],
        output_format: str = "json"
    ) -> dict[str, Any] | str:
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
        # Add API key and format parameters
        request_params = {
            "key": self.config.api_key,
            **format_api_params(params)
        }

        if output_format == "json":
            request_params["output_mode"] = "json"

        logger.debug("Making API request with params: %s", self._sanitize_params_for_log(request_params))

        try:
            response = self.session.get(
                self.config.base_url,
                params=request_params,
                timeout=self.config.timeout
            )

            logger.debug("API response status: %s", response.status_code)

            # Handle different status codes
            if response.status_code == HTTP_UNAUTHORIZED:
                msg = "Invalid API key or authentication failed"
                raise DomainIQAuthenticationError(msg)
            if response.status_code == HTTP_TOO_MANY_REQUESTS:
                retry_after = response.headers.get("Retry-After")
                msg = "Rate limit exceeded"
                raise DomainIQRateLimitError(
                    msg,
                    retry_after=int(retry_after) if retry_after else None
                )
            if response.status_code >= HTTP_BAD_REQUEST:
                msg = f"API request failed with status {response.status_code}: {response.text}"
                raise DomainIQAPIError(
                    msg,
                    status_code=response.status_code
                )

            response.raise_for_status()

            # Return appropriate format
            if output_format == "json":
                json_response = response.json()
                logger.debug("API JSON response: %s", json_response)
                return json_response
            return response.text

        except requests.exceptions.Timeout as e:
            msg = f"Request timed out after {self.config.timeout}s"
            raise DomainIQTimeoutError(msg) from e
        except requests.exceptions.RequestException as e:
            msg = f"Request failed: {e}"
            raise DomainIQAPIError(msg) from e
        except ValueError as e:
            msg = f"Failed to parse JSON response: {e}"
            raise DomainIQAPIError(msg) from e

    def _sanitize_params_for_log(self, params: dict[str, str]) -> dict[str, str]:
        """Sanitize parameters for logging (hide API key)."""
        sanitized = params.copy()
        if "key" in sanitized:
            sanitized["key"] = "*" * 8
        return sanitized

    # WHOIS Methods

    def whois_lookup(
        self,
        domain: str | None = None,
        ip: str | None = None,
        full: bool = False,
        current_only: bool = False
    ) -> WhoisResult | None:
        """Perform WHOIS lookup for a domain or IP address.

        Args:
            domain: Domain name to lookup
            ip: IP address to lookup
            full: Retrieve full WHOIS record
            current_only: Use only current WHOIS record

        Returns:
            WhoisResult object or None if no data
        """
        if not domain and not ip:
            msg = "Either domain or ip must be provided"
            raise ValueError(msg)

        params = {"service": "whois"}
        if domain:
            params["domain"] = domain
        if ip:
            params["ip"] = ip
        if full:
            params["full"] = 1
        if current_only:
            params["current_only"] = 1

        response = self._make_request(params)
        return WhoisResult.from_dict(response) if response else None

    # DNS Methods

    def dns_lookup(
        self,
        query: str,
        record_types: list[str | DNSRecordType] | None = None
    ) -> DNSResult | None:
        """Perform DNS lookup for a domain or hostname.

        Args:
            query: Domain or hostname to query
            record_types: List of DNS record types to retrieve

        Returns:
            DNSResult object or None if no data
        """
        params = {"service": "dns", "q": query}

        if record_types:
            types_str = ",".join(
                t.value if isinstance(t, DNSRecordType) else str(t)
                for t in record_types
            )
            params["types"] = types_str

        response = self._make_request(params)
        return DNSResult.from_dict(response) if response else None

    # Domain Analysis Methods

    def domain_categorize(self, domains: list[str]) -> list[DomainCategory]:
        """Categorize domain names.

        Args:
            domains: List of domain names to categorize

        Returns:
            List of DomainCategory objects
        """
        params = {"service": "categorize", "domains": domains}
        response = self._make_request(params)

        if not response:
            return []

        # Handle both single domain and multiple domains responses
        if isinstance(response, dict) and "domain" in response:
            return [DomainCategory.from_dict(response)]
        if isinstance(response, list):
            return [DomainCategory.from_dict(item) for item in response]
        return []

    def domain_snapshot(
        self,
        domain: str,
        full: bool = False,
        no_cache: bool = False,
        raw: bool = False,
        width: int = 250,
        height: int = 125
    ) -> DomainSnapshot | None:
        """Get a snapshot of a domain.

        Args:
            domain: Domain to snapshot
            full: Retrieve full-size image
            no_cache: Don't use cached snapshot
            raw: Return raw image data
            width: Snapshot width
            height: Snapshot height

        Returns:
            DomainSnapshot object or None if no data
        """
        params = {
            "service": "snapshot",
            "domain": domain,
            "width": width,
            "height": height
        }
        if full:
            params["full"] = 1
        if no_cache:
            params["no_cache"] = 1
        if raw:
            params["raw"] = 1

        response = self._make_request(params)
        return DomainSnapshot.from_dict(response) if response else None

    def domain_snapshot_history(
        self,
        domain: str,
        width: int = 250,
        height: int = 125,
        limit: int = 10
    ) -> list[DomainSnapshot]:
        """Get snapshot history for a domain.

        Args:
            domain: Domain to get history for
            width: Snapshot width
            height: Snapshot height
            limit: Maximum number of snapshots to return

        Returns:
            List of DomainSnapshot objects
        """
        params = {
            "service": "snapshot_history",
            "domain": domain,
            "width": width,
            "height": height,
            "limit": limit
        }

        response = self._make_request(params)
        if not response:
            return []

        if isinstance(response, list):
            return [DomainSnapshot.from_dict(item) for item in response]
        return [DomainSnapshot.from_dict(response)]

    # Report Methods

    def domain_report(self, domain: str) -> DomainReport | None:
        """Get comprehensive domain report.

        Args:
            domain: Domain to get report for

        Returns:
            DomainReport object or None if no data
        """
        params = {"service": "domain_report", "domain": domain}
        response = self._make_request(params)
        return DomainReport.from_dict(response) if response else None

    def name_report(self, name: str) -> dict[str, Any] | None:
        """Get registrant name report.

        Args:
            name: Registrant name to search for

        Returns:
            Report data as dictionary or None if no data
        """
        params = {"service": "name_report", "name": name}
        return self._make_request(params)

    def organization_report(self, organization: str) -> dict[str, Any] | None:
        """Get registrant organization report.

        Args:
            organization: Organization name to search for

        Returns:
            Report data as dictionary or None if no data
        """
        params = {"service": "organization_report", "organization": organization}
        return self._make_request(params)

    def email_report(self, email: str) -> dict[str, Any] | None:
        """Get registrant email report.

        Args:
            email: Email address to search for

        Returns:
            Report data as dictionary or None if no data
        """
        params = {"service": "email_report", "email": email}
        return self._make_request(params)

    def ip_report(self, ip: str) -> dict[str, Any] | None:
        """Get IP address summary report.

        Args:
            ip: IP address to get report for

        Returns:
            Report data as dictionary or None if no data
        """
        params = {"service": "ip_report", "ip": ip}
        return self._make_request(params)

    # Search Methods

    def domain_search(
        self,
        keywords: list[str],
        conditions: list[str] | None = None,
        match: MatchType = MatchType.ANY,
        **kwargs: Any
    ) -> dict[str, Any] | None:
        """Search for domains matching keywords.

        Args:
            keywords: List of keywords to search for
            conditions: List of conditions for each keyword
            match: Match type (any/all)
            **kwargs: Additional search parameters

        Returns:
            Search results as dictionary or None if no data
        """
        params = {
            "service": "domain_search",
            "match": match.value if isinstance(match, MatchType) else match
        }

        # Add keywords
        for idx, keyword in enumerate(keywords):
            params[f"keyword[{idx}]"] = keyword

        # Add conditions if provided
        if conditions:
            for idx, condition in enumerate(conditions):
                params[f"condition[{idx}]"] = condition

        # Add additional parameters
        params.update(kwargs)

        return self._make_request(params)

    def reverse_search(
        self,
        search_type: str | ReverseSearchType,
        search_term: str,
        match: MatchType = MatchType.CONTAINS
    ) -> dict[str, Any] | None:
        """Perform reverse search by email, name, or organization.

        Args:
            search_type: Type of search (email, name, org)
            search_term: Term to search for
            match: Match type (contains, begins, ends)

        Returns:
            Search results as dictionary or None if no data
        """
        params = {
            "service": "reverse_search",
            "type": search_type.value if isinstance(search_type, ReverseSearchType) else search_type,
            "search": search_term,
            "match": match.value if isinstance(match, MatchType) else match
        }

        return self._make_request(params)

    def reverse_dns(self, domain: str) -> dict[str, Any] | None:
        """Perform reverse DNS search.

        Args:
            domain: Domain to search for

        Returns:
            Search results as dictionary or None if no data
        """
        params = {"service": "reverse_dns", "domain": domain}
        return self._make_request(params)

    def reverse_ip(self, search_type: str, data: str) -> dict[str, Any] | None:
        """Perform reverse IP search.

        Args:
            search_type: Type of IP search (ip, subnet, block, range, domain)
            data: IP data to search for

        Returns:
            Search results as dictionary or None if no data
        """
        params = {"service": "reverse_ip", "type": search_type, "data": data}
        return self._make_request(params)

    def reverse_mx(
        self,
        search_type: str,
        data: str,
        recursive: bool = False
    ) -> dict[str, Any] | None:
        """Perform reverse MX search.

        Args:
            search_type: Type of MX search (hostname, ip, subnet, block, range)
            data: MX data to search for
            recursive: Recursively check MX hostnames

        Returns:
            Search results as dictionary or None if no data
        """
        params = {"service": "reverse_mx", "type": search_type, "data": data}
        if recursive:
            params["recursive"] = "1"

        return self._make_request(params)

    # Bulk Operations

    def bulk_dns(self, domains: list[str]) -> list[dict[str, Any]]:
        """Perform bulk DNS lookups.

        Args:
            domains: List of domains to lookup

        Returns:
            List of DNS results as dictionaries
        """
        params = {"service": "bulk_dns", "domains": domains}
        csv_response = self._make_request(params, output_format="csv")

        if not csv_response:
            return []

        return csv_to_dict_list(csv_response)

    def bulk_whois(
        self,
        items: list[str],
        lookup_type: BulkWhoisType = BulkWhoisType.LIVE
    ) -> list[dict[str, Any]]:
        """Perform bulk WHOIS lookups.

        Args:
            items: List of domains or IPs to lookup
            lookup_type: Type of WHOIS lookup (live, registry, cached)

        Returns:
            List of WHOIS results as dictionaries
        """
        params = {
            "service": "bulk_whois",
            "type": lookup_type.value if isinstance(lookup_type, BulkWhoisType) else lookup_type,
            "domains": items
        }

        csv_response = self._make_request(params, output_format="csv")

        if not csv_response:
            return []

        return csv_to_dict_list(csv_response)

    def bulk_whois_ip(self, domains: list[str]) -> list[dict[str, Any]]:
        """Perform bulk domain IP WHOIS lookups.

        Args:
            domains: List of domains to lookup

        Returns:
            List of IP WHOIS results as dictionaries
        """
        params = {"service": "bulk_whois_ip", "domains": domains}
        csv_response = self._make_request(params, output_format="csv")

        if not csv_response:
            return []

        return csv_to_dict_list(csv_response)

    # Monitoring Methods

    def monitor_list(self) -> list[MonitorReport]:
        """Get list of active monitors.

        Returns:
            List of MonitorReport objects
        """
        params = {"service": "monitor", "action": "list"}
        response = self._make_request(params)

        if not response:
            return []

        if isinstance(response, list):
            return [MonitorReport.from_dict(item) for item in response]
        return [MonitorReport.from_dict(response)]

    def monitor_report_items(self, report_id: int) -> dict[str, Any] | None:
        """Get items in a monitor report.

        Args:
            report_id: Monitor report ID

        Returns:
            Report items data or None if no data
        """
        params = {"service": "monitor", "action": "report_items", "report": report_id}
        return self._make_request(params)

    def monitor_report_summary(
        self,
        report_id: int,
        item_id: int | None = None,
        days_range: int | None = None
    ) -> dict[str, Any] | None:
        """Get monitor report summary.

        Args:
            report_id: Monitor report ID
            item_id: Specific item ID (optional)
            days_range: Range of days for summary (optional)

        Returns:
            Report summary data or None if no data
        """
        params = {"service": "monitor", "action": "report_summary", "report": report_id}
        if item_id is not None:
            params["item"] = item_id
        if days_range is not None:
            params["range"] = days_range

        return self._make_request(params)

    def monitor_report_changes(self, report_id: int, change_id: int) -> dict[str, Any] | None:
        """Get monitor report changes.

        Args:
            report_id: Monitor report ID
            change_id: Change ID

        Returns:
            Report changes data or None if no data
        """
        params = {
            "service": "monitor",
            "action": "report_changes",
            "report": report_id,
            "change": change_id
        }
        return self._make_request(params)

    def create_monitor_report(
        self,
        report_type: str,
        name: str,
        email_alert: bool = True
    ) -> dict[str, Any] | None:
        """Create a new monitor report.

        Args:
            report_type: Type of monitor report
            name: Name of the monitor report
            email_alert: Enable email alerts

        Returns:
            Created report data or None if failed
        """
        params = {
            "service": "monitor",
            "action": "report_create",
            "type": report_type,
            "name": name,
            "email_alert": "1" if email_alert else "0"
        }
        return self._make_request(params)

    def add_monitor_item(
        self,
        report_id: int,
        item_type: str,
        items: list[str],
        **kwargs: Any
    ) -> dict[str, Any] | None:
        """Add items to a monitor report.

        Args:
            report_id: Monitor report ID
            item_type: Type of items to add
            items: List of items to add
            **kwargs: Additional parameters

        Returns:
            Response data or None if failed
        """
        params = {
            "service": "monitor",
            "action": "report_item_add",
            "report_id": report_id,
            "type": item_type,
            "items": items
        }
        params.update(kwargs)
        return self._make_request(params)

    def enable_typos(self, report_id: int, item_id: int, strength: int = 41) -> dict[str, Any] | None:
        """Enable typo monitoring for a keyword monitor item.

        Args:
            report_id: Monitor report ID
            item_id: Monitor item ID
            strength: Typo monitoring strength (5-41)

        Returns:
            Response data or None if failed
        """
        params = {
            "service": "monitor",
            "action": "enable_typos",
            "report_id": report_id,
            "item_id": item_id,
            "strength": strength
        }
        return self._make_request(params)

    def disable_typos(self, report_id: int, item_id: int) -> dict[str, Any] | None:
        """Disable typo monitoring for a keyword monitor item.

        Args:
            report_id: Monitor report ID
            item_id: Monitor item ID

        Returns:
            Response data or None if failed
        """
        params = {
            "service": "monitor",
            "action": "disable_typos",
            "report_id": report_id,
            "item_id": item_id
        }
        return self._make_request(params)

    def modify_typo_strength(self, report_id: int, item_id: int, strength: int) -> dict[str, Any] | None:
        """Modify typo monitoring strength for a keyword monitor item.

        Args:
            report_id: Monitor report ID
            item_id: Monitor item ID
            strength: New typo monitoring strength (5-41)

        Returns:
            Response data or None if failed
        """
        params = {
            "service": "monitor",
            "action": "modify_typo_strength",
            "report_id": report_id,
            "item_id": item_id,
            "strength": strength
        }
        return self._make_request(params)

    def delete_monitor_item(self, item_id: int) -> dict[str, Any] | None:
        """Delete a monitor item.

        Args:
            item_id: Monitor item ID to delete

        Returns:
            Response data or None if failed
        """
        params = {
            "service": "monitor",
            "action": "report_item_delete",
            "item_id": item_id
        }
        return self._make_request(params)

    def delete_monitor_report(self, report_id: int) -> dict[str, Any] | None:
        """Delete a monitor report.

        Args:
            report_id: Monitor report ID to delete

        Returns:
            Response data or None if failed
        """
        params = {
            "service": "monitor",
            "action": "report_delete",
            "report_id": report_id
        }
        return self._make_request(params)

    def close(self) -> None:
        """Close the HTTP session."""
        if self.session:
            self.session.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
