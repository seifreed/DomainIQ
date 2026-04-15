"""Data models for DomainIQ API responses."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any


class DNSRecordType(Enum):
    """DNS record types supported by DomainIQ."""

    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"
    TXT = "TXT"
    SOA = "SOA"
    PTR = "PTR"


class BulkWhoisType(Enum):
    """Types of bulk WHOIS lookups."""

    LIVE = "live"
    REGISTRY = "registry"
    CACHED = "cached"


class ReverseSearchType(Enum):
    """Types of reverse searches."""

    EMAIL = "email"
    NAME = "name"
    ORG = "org"


class MatchType(Enum):
    """Match types for searches."""

    ANY = "any"
    ALL = "all"
    CONTAINS = "contains"
    BEGINS = "begins"
    ENDS = "ends"


@dataclass
class WhoisResult:
    """WHOIS lookup result."""

    domain: str | None = None
    ip: str | None = None
    registrar: str | None = None
    registrant_name: str | None = None
    registrant_organization: str | None = None
    registrant_email: str | None = None
    creation_date: datetime | None = None
    expiration_date: datetime | None = None
    updated_date: datetime | None = None
    nameservers: list[str] | None = None
    status: list[str] | None = None
    raw_data: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "WhoisResult":
        """Create WhoisResult from API response dictionary."""
        # Handle DomainIQ API format which returns {'result': {...}}
        if "result" in data and isinstance(data["result"], dict):
            result = data["result"]
        else:
            result = data

        # Parse nameservers from ns_1, ns_2, etc.
        nameservers = []
        for i in range(1, 10):  # Check up to ns_9
            ns_key = f"ns_{i}"
            if ns_key in result and result[ns_key]:
                nameservers.append(result[ns_key])

        # If no numbered nameservers, check for nameservers list
        if not nameservers:
            nameservers = result.get("nameservers", [])

        # Parse status - might be comma-separated string or list
        status = result.get("status", [])
        if isinstance(status, str):
            status = [s.strip() for s in status.split(",")]

        # Parse emails - might be comma-separated string
        emails = result.get("emails", result.get("registrant_email"))
        if isinstance(emails, str) and "," in emails:
            emails = emails.split(",")[0].strip()  # Take first email

        return cls(
            domain=result.get("domain"),
            ip=result.get("ip"),
            registrar=result.get("registrar"),
            registrant_name=result.get("registrant_name", result.get("registrant")),
            registrant_organization=result.get(
                "registrant_organization", result.get("registrant")
            ),
            registrant_email=emails,
            creation_date=cls._parse_date(result.get("creation_date")),
            expiration_date=cls._parse_date(result.get("expiration_date")),
            updated_date=cls._parse_date(
                result.get("update_date", result.get("updated_date"))
            ),
            nameservers=nameservers,
            status=status,
            raw_data=result.get("raw", result.get("raw_data")),
        )

    @staticmethod
    def _parse_date(date_str: str | None) -> datetime | None:
        """Parse date string to datetime object."""
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None


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

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DNSResult":
        """Create DNSResult from API response dictionary."""
        records = []

        # Handle DomainIQ API format which returns {'results': [...]}
        results = data.get("results", data.get("records", []))

        # Extract domain from first result if not provided
        domain = data.get("domain", "")
        if not domain and results and isinstance(results[0], dict):
            domain = results[0].get("host", "")

        for record_data in results:
            # Map API fields to our model fields
            record_name = record_data.get("host", record_data.get("name", ""))
            record_type = record_data.get("type", "")

            # Value depends on record type
            if record_type == "A":
                record_value = record_data.get("ip", record_data.get("value", ""))
            elif record_type == "MX":
                record_value = record_data.get("target", record_data.get("value", ""))
            elif record_type == "CNAME":
                record_value = record_data.get("target", record_data.get("value", ""))
            elif record_type == "TXT":
                record_value = record_data.get("txt", record_data.get("value", ""))
            elif record_type == "NS":
                record_value = record_data.get("target", record_data.get("value", ""))
            else:
                record_value = record_data.get(
                    "value", record_data.get("ip", record_data.get("target", ""))
                )

            # Priority for MX records
            priority = record_data.get("pri", record_data.get("priority"))

            records.append(
                DNSRecord(
                    name=record_name,
                    type=record_type,
                    value=record_value,
                    ttl=record_data.get("ttl"),
                    priority=priority,
                )
            )

        return cls(domain=domain, records=records)


@dataclass
class DomainCategory:
    """Domain categorization result."""

    domain: str
    categories: list[str]
    confidence_score: float | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DomainCategory":
        """Create DomainCategory from API response dictionary."""
        return cls(
            domain=data.get("domain", ""),
            categories=data.get("categories", []),
            confidence_score=data.get("confidence_score"),
        )


@dataclass
class DomainSnapshot:
    """Domain snapshot result."""

    domain: str
    screenshot_url: str | None = None
    timestamp: datetime | None = None
    width: int | None = None
    height: int | None = None
    raw_data: bytes | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DomainSnapshot":
        """Create DomainSnapshot from API response dictionary."""
        return cls(
            domain=data.get("domain", ""),
            screenshot_url=data.get("screenshot_url"),
            timestamp=cls._parse_timestamp(data.get("timestamp")),
            width=data.get("width"),
            height=data.get("height"),
        )

    @staticmethod
    def _parse_timestamp(timestamp_str: str | None) -> datetime | None:
        """Parse timestamp string to datetime object."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None


@dataclass
class DomainReport:
    """Domain report result."""

    domain: str
    whois_data: WhoisResult | None = None
    dns_data: DNSResult | None = None
    categories: list[str] | None = None
    related_domains: list[str] | None = None
    risk_score: float | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DomainReport":
        """Create DomainReport from API response dictionary."""
        return cls(
            domain=data.get("domain", ""),
            whois_data=WhoisResult.from_dict(data["whois"])
            if data.get("whois")
            else None,
            dns_data=DNSResult.from_dict(data["dns"]) if data.get("dns") else None,
            categories=data.get("categories"),
            related_domains=data.get("related_domains"),
            risk_score=data.get("risk_score"),
        )


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

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MonitorReport":
        """Create MonitorReport from API response dictionary."""
        items = []
        if data.get("items"):
            for item_data in data["items"]:
                items.append(
                    MonitorItem(
                        id=item_data.get("id", 0),
                        type=item_data.get("type", ""),
                        value=item_data.get("value", ""),
                        enabled=item_data.get("enabled", True),
                        typos_enabled=item_data.get("typos_enabled", False),
                        typo_strength=item_data.get("typo_strength"),
                    )
                )

        return cls(
            id=data.get("id", 0),
            name=data.get("name", ""),
            type=data.get("type", ""),
            email_alerts=data.get("email_alerts", False),
            created_date=cls._parse_date(data.get("created_date")),
            items=items if items else None,
        )

    @staticmethod
    def _parse_date(date_str: str | None) -> datetime | None:
        """Parse date string to datetime object."""
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None
