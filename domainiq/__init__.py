"""DomainIQ Python Library - A modern Python client for the DomainIQ API.

This library provides both synchronous and asynchronous clients for interacting
with the DomainIQ API, enabling domain intelligence gathering, WHOIS lookups,
DNS queries, and monitoring capabilities.
"""

from .async_client import AsyncDomainIQClient
from .client import DomainIQClient
from .config import ConfigKwargs
from .deserializers import (
    parse_dns_result,
    parse_domain_category,
    parse_domain_report,
    parse_domain_snapshot,
    parse_monitor_report,
    parse_whois_result,
)
from .exceptions import (
    DomainIQAPIError,
    DomainIQAuthenticationError,
    DomainIQConfigurationError,
    DomainIQError,
    DomainIQPartialResultsError,
    DomainIQRateLimitError,
    DomainIQTimeoutError,
    DomainIQValidationError,
)
from .models import (
    DNSResult,
    DomainReport,
    DomainSearchFilters,
    EmailReportResult,
    IpReportResult,
    KeywordMatchType,
    MatchType,
    MonitorActionResult,
    MonitorReport,
    NameReportResult,
    OrganizationReportResult,
    ReverseMatchType,
    ReverseSearchResult,
    SearchResult,
    SnapshotOptions,
    WhoisResult,
)
from .protocols import (
    AsyncBulkProtocol,
    AsyncDNSProtocol,
    AsyncDomainAnalysisProtocol,
    AsyncDomainIQClientProtocol,
    AsyncMonitorProtocol,
    AsyncReportProtocol,
    AsyncSearchProtocol,
    AsyncWhoisProtocol,
    BulkProtocol,
    DNSProtocol,
    DomainAnalysisProtocol,
    DomainIQClientProtocol,
    MonitorProtocol,
    ReportProtocol,
    SearchProtocol,
    WhoisProtocol,
)

__version__ = "2.0.0"
__author__ = "seifreed"
__email__ = "mriverolopez@gmail.com"
__license__ = "MIT"

__all__ = [
    "AsyncBulkProtocol",
    "AsyncDNSProtocol",
    "AsyncDomainAnalysisProtocol",
    "AsyncDomainIQClient",
    "AsyncDomainIQClientProtocol",
    "AsyncMonitorProtocol",
    "AsyncReportProtocol",
    "AsyncSearchProtocol",
    "AsyncWhoisProtocol",
    "BulkProtocol",
    "ConfigKwargs",
    "DNSProtocol",
    "DNSResult",
    "DomainAnalysisProtocol",
    "DomainIQAPIError",
    "DomainIQAuthenticationError",
    "DomainIQClient",
    "DomainIQClientProtocol",
    "DomainIQConfigurationError",
    "DomainIQError",
    "DomainIQPartialResultsError",
    "DomainIQRateLimitError",
    "DomainIQTimeoutError",
    "DomainIQValidationError",
    "DomainReport",
    "DomainSearchFilters",
    "EmailReportResult",
    "IpReportResult",
    "KeywordMatchType",
    "MatchType",
    "MonitorActionResult",
    "MonitorProtocol",
    "MonitorReport",
    "NameReportResult",
    "OrganizationReportResult",
    "ReportProtocol",
    "ReverseMatchType",
    "ReverseSearchResult",
    "SearchProtocol",
    "SearchResult",
    "SnapshotOptions",
    "WhoisProtocol",
    "WhoisResult",
    "parse_dns_result",
    "parse_domain_category",
    "parse_domain_report",
    "parse_domain_snapshot",
    "parse_monitor_report",
    "parse_whois_result",
]
