"""Structural Protocol interfaces for DomainIQ clients.

Use these Protocols for type annotations when you need to accept either the
sync or async client without depending on a concrete implementation.

Sub-protocols (e.g. ``WhoisProtocol``) let callers depend only on the
capability they need.  The full ``DomainIQClientProtocol`` and
``AsyncDomainIQClientProtocol`` compose all sub-protocols.
"""

from typing import Any, Protocol, Unpack, runtime_checkable

from .constants import TYPO_STRENGTH_MAX
from .models import (
    BulkWhoisType,
    DNSRecordType,
    DNSResult,
    DomainCategory,
    DomainReport,
    DomainSearchFilters,
    DomainSnapshot,
    EmailReportResult,
    IpReportResult,
    KeywordMatchType,
    MonitorItemType,
    MonitorReport,
    MonitorReportType,
    NameReportResult,
    OrganizationReportResult,
    ReverseIpSearchType,
    ReverseMxSearchType,
    ReverseMatchType,
    ReverseSearchResult,
    ReverseSearchType,
    SearchResult,
    SnapshotOptions,
    WhoisResult,
)

# ---------------------------------------------------------------------------
# Sync sub-protocols
# ---------------------------------------------------------------------------


@runtime_checkable
class WhoisProtocol(Protocol):
    def whois_lookup(
        self,
        domain: str | None = None,
        ip: str | None = None,
        full: bool = False,
        current_only: bool = False,
    ) -> WhoisResult: ...


@runtime_checkable
class DNSProtocol(Protocol):
    def dns_lookup(
        self,
        query: str,
        record_types: list[str | DNSRecordType] | None = None,
    ) -> DNSResult: ...


@runtime_checkable
class DomainAnalysisProtocol(Protocol):
    def domain_categorize(self, domains: list[str]) -> list[DomainCategory]: ...

    def domain_snapshot(
        self,
        domain: str,
        options: SnapshotOptions | None = None,
    ) -> DomainSnapshot: ...

    def domain_snapshot_history(
        self,
        domain: str,
        width: int = 250,
        height: int = 125,
        limit: int = 10,
    ) -> list[DomainSnapshot]: ...


@runtime_checkable
class ReportProtocol(Protocol):
    def domain_report(self, domain: str) -> DomainReport: ...

    def name_report(self, name: str) -> NameReportResult: ...

    def organization_report(self, organization: str) -> OrganizationReportResult: ...

    def email_report(self, email: str) -> EmailReportResult: ...

    def ip_report(self, ip: str) -> IpReportResult: ...


@runtime_checkable
class SearchProtocol(Protocol):
    def domain_search(
        self,
        keywords: list[str],
        conditions: list[str] | None = None,
        match: KeywordMatchType = KeywordMatchType.ANY,
        filters: DomainSearchFilters | None = None,
        **kwargs: Unpack[DomainSearchFilters],
    ) -> SearchResult: ...

    def reverse_search(
        self,
        search_type: str | ReverseSearchType,
        search_term: str,
        match: ReverseMatchType = ReverseMatchType.CONTAINS,
    ) -> ReverseSearchResult: ...

    def reverse_dns(self, domain: str) -> ReverseSearchResult: ...

    def reverse_ip(self, search_type: ReverseIpSearchType | str, data: str) -> ReverseSearchResult: ...

    def reverse_mx(
        self,
        search_type: ReverseMxSearchType | str,
        data: str,
        recursive: bool = False,
    ) -> ReverseSearchResult: ...


@runtime_checkable
class BulkProtocol(Protocol):
    def bulk_dns(self, domains: list[str]) -> list[dict[str, Any]]: ...

    def bulk_whois(
        self,
        items: list[str],
        lookup_type: BulkWhoisType = BulkWhoisType.LIVE,
    ) -> list[dict[str, Any]]: ...

    def bulk_whois_ip(self, domains: list[str]) -> list[dict[str, Any]]: ...


@runtime_checkable
class MonitorProtocol(Protocol):
    def monitor_list(self) -> list[MonitorReport]: ...

    def monitor_report_items(self, report_id: int) -> dict[str, Any]: ...

    def monitor_report_summary(
        self,
        report_id: int,
        item_id: int | None = None,
        days_range: int | None = None,
    ) -> dict[str, Any]: ...

    def monitor_report_changes(
        self, report_id: int, change_id: int
    ) -> dict[str, Any]: ...

    def create_monitor_report(
        self, report_type: MonitorReportType | str, name: str, email_alert: bool = True
    ) -> dict[str, Any]: ...

    def add_monitor_item(
        self,
        report_id: int,
        item_type: MonitorItemType | str,
        items: list[str],
        enabled: bool | None = None,
    ) -> dict[str, Any]: ...

    def enable_typos(
        self, report_id: int, item_id: int, strength: int = TYPO_STRENGTH_MAX
    ) -> dict[str, Any]: ...

    def disable_typos(self, report_id: int, item_id: int) -> dict[str, Any]: ...

    def modify_typo_strength(
        self, report_id: int, item_id: int, strength: int
    ) -> dict[str, Any]: ...

    def delete_monitor_item(self, item_id: int) -> dict[str, Any]: ...

    def delete_monitor_report(self, report_id: int) -> dict[str, Any]: ...


# ---------------------------------------------------------------------------
# Async sub-protocols
# ---------------------------------------------------------------------------


@runtime_checkable
class AsyncWhoisProtocol(Protocol):
    async def whois_lookup(
        self,
        domain: str | None = None,
        ip: str | None = None,
        full: bool = False,
        current_only: bool = False,
    ) -> WhoisResult: ...


@runtime_checkable
class AsyncDNSProtocol(Protocol):
    async def dns_lookup(
        self,
        query: str,
        record_types: list[str | DNSRecordType] | None = None,
    ) -> DNSResult: ...


@runtime_checkable
class AsyncDomainAnalysisProtocol(Protocol):
    async def domain_categorize(self, domains: list[str]) -> list[DomainCategory]: ...

    async def domain_snapshot(
        self,
        domain: str,
        options: SnapshotOptions | None = None,
    ) -> DomainSnapshot: ...

    async def domain_snapshot_history(
        self,
        domain: str,
        width: int = 250,
        height: int = 125,
        limit: int = 10,
    ) -> list[DomainSnapshot]: ...


@runtime_checkable
class AsyncReportProtocol(Protocol):
    async def domain_report(self, domain: str) -> DomainReport: ...

    async def name_report(self, name: str) -> NameReportResult: ...

    async def organization_report(self, organization: str) -> OrganizationReportResult: ...

    async def email_report(self, email: str) -> EmailReportResult: ...

    async def ip_report(self, ip: str) -> IpReportResult: ...


@runtime_checkable
class AsyncSearchProtocol(Protocol):
    async def domain_search(
        self,
        keywords: list[str],
        conditions: list[str] | None = None,
        match: KeywordMatchType = KeywordMatchType.ANY,
        filters: DomainSearchFilters | None = None,
        **kwargs: Unpack[DomainSearchFilters],
    ) -> SearchResult: ...

    async def reverse_search(
        self,
        search_type: str | ReverseSearchType,
        search_term: str,
        match: ReverseMatchType = ReverseMatchType.CONTAINS,
    ) -> ReverseSearchResult: ...

    async def reverse_dns(self, domain: str) -> ReverseSearchResult: ...

    async def reverse_ip(self, search_type: ReverseIpSearchType | str, data: str) -> ReverseSearchResult: ...

    async def reverse_mx(
        self,
        search_type: ReverseMxSearchType | str,
        data: str,
        recursive: bool = False,
    ) -> ReverseSearchResult: ...


@runtime_checkable
class AsyncBulkProtocol(Protocol):
    async def bulk_dns(self, domains: list[str]) -> list[dict[str, Any]]: ...

    async def bulk_whois(
        self,
        items: list[str],
        lookup_type: BulkWhoisType = BulkWhoisType.LIVE,
    ) -> list[dict[str, Any]]: ...

    async def bulk_whois_ip(self, domains: list[str]) -> list[dict[str, Any]]: ...


@runtime_checkable
class AsyncMonitorProtocol(Protocol):
    async def monitor_list(self) -> list[MonitorReport]: ...

    async def monitor_report_items(self, report_id: int) -> dict[str, Any]: ...

    async def monitor_report_summary(
        self,
        report_id: int,
        item_id: int | None = None,
        days_range: int | None = None,
    ) -> dict[str, Any]: ...

    async def monitor_report_changes(
        self, report_id: int, change_id: int
    ) -> dict[str, Any]: ...

    async def create_monitor_report(
        self, report_type: MonitorReportType | str, name: str, email_alert: bool = True
    ) -> dict[str, Any]: ...

    async def add_monitor_item(
        self,
        report_id: int,
        item_type: MonitorItemType | str,
        items: list[str],
        enabled: bool | None = None,
    ) -> dict[str, Any]: ...

    async def enable_typos(
        self, report_id: int, item_id: int, strength: int = TYPO_STRENGTH_MAX
    ) -> dict[str, Any]: ...

    async def disable_typos(self, report_id: int, item_id: int) -> dict[str, Any]: ...

    async def modify_typo_strength(
        self, report_id: int, item_id: int, strength: int
    ) -> dict[str, Any]: ...

    async def delete_monitor_item(self, item_id: int) -> dict[str, Any]: ...

    async def delete_monitor_report(self, report_id: int) -> dict[str, Any]: ...


# ---------------------------------------------------------------------------
# Composite protocols (full client surfaces)
# ---------------------------------------------------------------------------


@runtime_checkable
class DomainIQClientProtocol(
    WhoisProtocol,
    DNSProtocol,
    DomainAnalysisProtocol,
    ReportProtocol,
    SearchProtocol,
    BulkProtocol,
    MonitorProtocol,
    Protocol,
):
    """Structural interface for the synchronous DomainIQ client.

    Implemented by :class:`domainiq.client.DomainIQClient`.
    For partial capability hints use the sub-protocols above.
    """

    def close(self) -> None: ...


@runtime_checkable
class AsyncDomainIQClientProtocol(
    AsyncWhoisProtocol,
    AsyncDNSProtocol,
    AsyncDomainAnalysisProtocol,
    AsyncReportProtocol,
    AsyncSearchProtocol,
    AsyncBulkProtocol,
    AsyncMonitorProtocol,
    Protocol,
):
    """Structural interface for the asynchronous DomainIQ client.

    Implemented by :class:`domainiq.async_client.AsyncDomainIQClient`.
    For partial capability hints use the ``Async*`` sub-protocols above.
    """

    async def close(self) -> None: ...
