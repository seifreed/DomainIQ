"""Data models for DomainIQ API responses."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, TypedDict

from .constants import SNAPSHOT_DEFAULT_HEIGHT, SNAPSHOT_DEFAULT_WIDTH
from .validators import validate_positive_int


class DNSRecordType(Enum):
    """DNS record types supported by the DomainIQ DNS lookup endpoint."""

    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"
    TXT = "TXT"      #: Text record (SPF, DKIM, etc.)
    SOA = "SOA"
    PTR = "PTR"


class BulkWhoisType(Enum):
    """Types of bulk WHOIS lookups."""

    LIVE = "live"
    REGISTRY = "registry"
    CACHED = "cached"


class ReverseSearchType(Enum):
    """Fields that reverse search can match against."""

    EMAIL = "email"
    NAME = "name"
    ORG = "org"


class KeywordMatchType(Enum):
    """Match modes for keyword-based domain searches."""

    ANY = "any"
    ALL = "all"


class ReverseMatchType(Enum):
    """String-position match modes for reverse searches."""

    CONTAINS = "contains"
    BEGINS = "begins"
    ENDS = "ends"


# Backwards-compatible alias
MatchType = KeywordMatchType


@dataclass
class WhoisResult:
    """WHOIS lookup result."""

    domain: str | None = None
    ip: str | None = None
    registrar: str | None = None
    registrant_name: str | None = None
    registrant_organization: str | None = None
    registrant_email: list[str] | None = None
    creation_date: datetime | None = None
    expiration_date: datetime | None = None
    updated_date: datetime | None = None
    nameservers: list[str] = field(default_factory=list)
    status: list[str] = field(default_factory=list)
    raw_data: str | None = None


@dataclass
class DNSRecord:
    """Individual DNS record."""

    name: str
    type: str
    value: str
    ttl: int | None = None
    priority: int | None = None


@dataclass
class DNSResult:
    """DNS lookup result."""

    domain: str
    records: list[DNSRecord]


@dataclass
class DomainCategory:
    """Domain categorization result."""

    domain: str
    categories: list[str]
    confidence_score: float | None = None


@dataclass
class DomainSnapshot:
    """Domain snapshot result."""

    domain: str
    screenshot_url: str | None = None
    timestamp: datetime | None = None
    width: int | None = None
    height: int | None = None
    raw_data: bytes | None = None


@dataclass
class DomainReport:
    """Domain report result."""

    domain: str
    whois_data: WhoisResult | None = None
    dns_data: DNSResult | None = None
    categories: list[str] | None = None
    related_domains: list[str] | None = None
    risk_score: float | None = None


@dataclass
class MonitorItem:
    """Monitor item in a report."""

    id: int
    type: str
    value: str
    enabled: bool = True
    typos_enabled: bool = False
    typo_strength: int | None = None


@dataclass
class MonitorReport:
    """Monitor report."""

    id: int
    name: str
    type: str
    email_alerts: bool
    created_date: datetime | None = None
    items: list[MonitorItem] | None = None


@dataclass
class SnapshotOptions:
    """Options for domain snapshot requests."""

    full: bool = False
    no_cache: bool = False
    raw: bool = False
    width: int = SNAPSHOT_DEFAULT_WIDTH
    height: int = SNAPSHOT_DEFAULT_HEIGHT

    def __post_init__(self) -> None:
        validate_positive_int("SnapshotOptions.width", self.width)
        validate_positive_int("SnapshotOptions.height", self.height)


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
    """Typed response for reverse_search(), reverse_dns(), reverse_ip(), reverse_mx()."""

    count: int
    results: list[dict[str, Any]]
    domains: list[str]


class DomainSearchFilters(TypedDict, total=False):
    """Optional filters for domain_search. All fields are optional."""

    tld: str
    created_after: str
    created_before: str
    expired_after: str
    expired_before: str
    updated_after: str
    updated_before: str
    registrar: str
    registered_for: str
    changed_registrars: bool
    ns: str
    country: str
    no_parked: bool
    no_delisted: bool
    count_only: int
    exclude_dashed: bool
    exclude_numbers: bool
    exclude_idn: bool
    min_length: int
    max_length: int
    min_create_date: str
    max_create_date: str
    limit: int
