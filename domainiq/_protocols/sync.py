"""Synchronous structural protocols for DomainIQ clients."""

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

    def reverse_ip(
        self,
        search_type: ReverseIpSearchType | str,
        data: str,
    ) -> ReverseSearchResult: ...

    def reverse_mx(
        self,
        search_type: ReverseMxSearchType | str,
        data: str,
        recursive: bool = False,
    ) -> ReverseSearchResult: ...


@runtime_checkable
class BulkProtocol(Protocol):
    def bulk_dns(self, domains: list[str]) -> list[BulkDNSResult]: ...

    def bulk_whois(
        self,
        items: list[str],
        lookup_type: BulkWhoisType = BulkWhoisType.LIVE,
    ) -> list[BulkWhoisResult]: ...

    def bulk_whois_ip(self, domains: list[str]) -> list[BulkWhoisResult]: ...


@runtime_checkable
class MonitorProtocol(Protocol):
    def monitor_list(self) -> list[MonitorReport]: ...

    def monitor_report_items(self, report_id: int) -> MonitorActionResult: ...

    def monitor_report_summary(
        self,
        report_id: int,
        item_id: int | None = None,
        days_range: int | None = None,
    ) -> MonitorActionResult: ...

    def monitor_report_changes(
        self,
        report_id: int,
        change_id: int,
    ) -> MonitorActionResult: ...

    def create_monitor_report(
        self,
        report_type: MonitorReportType | str,
        name: str,
        email_alert: bool = True,
    ) -> MonitorReport: ...

    def add_monitor_item(
        self,
        report_id: int,
        item_type: MonitorItemType | str,
        items: list[str],
        enabled: bool | None = None,
    ) -> MonitorActionResult: ...

    def enable_typos(
        self,
        report_id: int,
        item_id: int,
        strength: int = TYPO_STRENGTH_MAX,
    ) -> MonitorActionResult: ...

    def disable_typos(self, report_id: int, item_id: int) -> MonitorActionResult: ...

    def modify_typo_strength(
        self,
        report_id: int,
        item_id: int,
        strength: int,
    ) -> MonitorActionResult: ...

    def delete_monitor_item(self, item_id: int) -> MonitorActionResult: ...

    def delete_monitor_report(self, report_id: int) -> MonitorActionResult: ...


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
    """Structural interface for the synchronous DomainIQ client."""

    def close(self) -> None: ...


__all__ = [
    "BulkProtocol",
    "DNSProtocol",
    "DomainAnalysisProtocol",
    "DomainIQClientProtocol",
    "MonitorProtocol",
    "ReportProtocol",
    "SearchProtocol",
    "WhoisProtocol",
]
