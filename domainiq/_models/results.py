"""Dataclass response models for DomainIQ API responses."""

from dataclasses import dataclass, field
from datetime import datetime

from domainiq.constants import SNAPSHOT_DEFAULT_HEIGHT, SNAPSHOT_DEFAULT_WIDTH


@dataclass
class WhoisResult:
    """WHOIS lookup result.

    All datetime fields are naive UTC because the API returns no timezone.
    """

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
    """Domain snapshot result.

    All datetime fields are naive UTC because the API returns no timezone.
    """

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
    """Monitor report.

    All datetime fields are naive UTC because the API returns no timezone.
    """

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


__all__ = [
    "DNSRecord",
    "DNSResult",
    "DomainCategory",
    "DomainReport",
    "DomainSnapshot",
    "MonitorItem",
    "MonitorReport",
    "SnapshotOptions",
    "WhoisResult",
]
