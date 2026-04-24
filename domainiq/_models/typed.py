"""TypedDict response models for DomainIQ API responses."""

from typing import Any, TypedDict


class MonitorActionResult(TypedDict, total=False):
    """Result returned by monitor mutation and read operations."""

    success: bool
    message: str
    data: dict[str, Any]


class BulkDNSResult(TypedDict, total=False):
    """Row from a bulk DNS CSV response."""

    domain: str
    type: str
    value: str
    ttl: str


class BulkWhoisResult(TypedDict, total=False):
    """Row from a bulk WHOIS or bulk WHOIS IP CSV response."""

    domain: str
    registrar: str
    creation_date: str
    expiration_date: str
    registrant_email: str
    nameservers: str


class IpReportResult(TypedDict, total=False):
    """Typed response for ip_report()."""

    ip: str
    country: str
    asn: str
    organization: str
    hostname: str
    domains: list[str]
    abuse_email: str


class SearchResult(TypedDict, total=False):
    """Typed response for domain_search()."""

    count: int
    domains: list[str]
    results: list[dict[str, Any]]


class ReverseSearchResult(TypedDict, total=False):
    """Typed response for reverse search endpoints."""

    count: int
    results: list[dict[str, Any]]
    domains: list[str]


class NameReportResult(TypedDict, total=False):
    """Typed response for name_report()."""

    name: str
    count: int
    domains: list[str]
    registrants: list[dict[str, Any]]


class OrganizationReportResult(TypedDict, total=False):
    """Typed response for organization_report()."""

    organization: str
    count: int
    domains: list[str]


class EmailReportResult(TypedDict, total=False):
    """Typed response for email_report()."""

    email: str
    count: int
    domains: list[str]
    registrants: list[dict[str, Any]]


__all__ = [
    "BulkDNSResult",
    "BulkWhoisResult",
    "EmailReportResult",
    "IpReportResult",
    "MonitorActionResult",
    "NameReportResult",
    "OrganizationReportResult",
    "ReverseSearchResult",
    "SearchResult",
]
