"""Asynchronous structural protocols for DomainIQ clients."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, Unpack, runtime_checkable

from domainiq._models.enums import BulkWhoisType, KeywordMatchType, ReverseMatchType
from domainiq.constants import TYPO_STRENGTH_MAX

if TYPE_CHECKING:
    from domainiq._models import (
        BulkDNSResult,
        BulkWhoisResult,
        DNSRecordType,
        DNSResult,
        DomainCategory,
        DomainReport,
        DomainSearchFilters,
        DomainSnapshot,
        EmailReportResult,
        IpReportResult,
        MonitorActionResult,
        MonitorItemType,
        MonitorReport,
        MonitorReportType,
        NameReportResult,
        OrganizationReportResult,
        ReverseIpSearchType,
        ReverseMxSearchType,
        ReverseSearchResult,
        ReverseSearchType,
        SearchResult,
        SnapshotOptions,
        WhoisResult,
    )


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

    async def organization_report(
        self,
        organization: str,
    ) -> OrganizationReportResult: ...

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

    async def reverse_ip(
        self,
        search_type: ReverseIpSearchType | str,
        data: str,
    ) -> ReverseSearchResult: ...

    async def reverse_mx(
        self,
        search_type: ReverseMxSearchType | str,
        data: str,
        recursive: bool = False,
    ) -> ReverseSearchResult: ...


@runtime_checkable
class AsyncBulkProtocol(Protocol):
    async def bulk_dns(self, domains: list[str]) -> list[BulkDNSResult]: ...

    async def bulk_whois(
        self,
        items: list[str],
        lookup_type: BulkWhoisType = BulkWhoisType.LIVE,
    ) -> list[BulkWhoisResult]: ...

    async def bulk_whois_ip(self, domains: list[str]) -> list[BulkWhoisResult]: ...


@runtime_checkable
class AsyncMonitorProtocol(Protocol):
    async def monitor_list(self) -> list[MonitorReport]: ...

    async def monitor_report_items(self, report_id: int) -> MonitorActionResult: ...

    async def monitor_report_summary(
        self,
        report_id: int,
        item_id: int | None = None,
        days_range: int | None = None,
    ) -> MonitorActionResult: ...

    async def monitor_report_changes(
        self,
        report_id: int,
        change_id: int,
    ) -> MonitorActionResult: ...

    async def create_monitor_report(
        self,
        report_type: MonitorReportType | str,
        name: str,
        email_alert: bool = True,
    ) -> MonitorReport: ...

    async def add_monitor_item(
        self,
        report_id: int,
        item_type: MonitorItemType | str,
        items: list[str],
        enabled: bool | None = None,
    ) -> MonitorActionResult: ...

    async def enable_typos(
        self,
        report_id: int,
        item_id: int,
        strength: int = TYPO_STRENGTH_MAX,
    ) -> MonitorActionResult: ...

    async def disable_typos(
        self,
        report_id: int,
        item_id: int,
    ) -> MonitorActionResult: ...

    async def modify_typo_strength(
        self,
        report_id: int,
        item_id: int,
        strength: int,
    ) -> MonitorActionResult: ...

    async def delete_monitor_item(self, item_id: int) -> MonitorActionResult: ...

    async def delete_monitor_report(self, report_id: int) -> MonitorActionResult: ...


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
    """Structural interface for the asynchronous DomainIQ client."""

    async def close(self) -> None: ...


__all__ = [
    "AsyncBulkProtocol",
    "AsyncDNSProtocol",
    "AsyncDomainAnalysisProtocol",
    "AsyncDomainIQClientProtocol",
    "AsyncMonitorProtocol",
    "AsyncReportProtocol",
    "AsyncSearchProtocol",
    "AsyncWhoisProtocol",
]
