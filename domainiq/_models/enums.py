"""Enum models for DomainIQ API requests."""

from enum import Enum, StrEnum


class DNSRecordType(Enum):
    """DNS record types supported by the DomainIQ DNS lookup endpoint."""

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


class MonitorReportType(StrEnum):
    """Report types supported by the DomainIQ monitor create endpoint."""

    DOMAIN = "domain"
    IP = "ip"
    NS = "ns"
    MX = "mx"


class MonitorItemType(StrEnum):
    """Item types supported by the DomainIQ monitor item-add endpoint."""

    DOMAIN = "domain"
    IP = "ip"
    NS = "ns"
    MX = "mx"


class ReverseIpSearchType(StrEnum):
    """Search modes for the reverse_ip endpoint."""

    IP = "ip"
    SUBNET = "subnet"
    BLOCK = "block"
    RANGE = "range"
    DOMAIN = "domain"


class ReverseMxSearchType(StrEnum):
    """Search modes for the reverse_mx endpoint."""

    DOMAIN = "domain"
    IP = "ip"


MatchType = KeywordMatchType

__all__ = [
    "BulkWhoisType",
    "DNSRecordType",
    "KeywordMatchType",
    "MatchType",
    "MonitorItemType",
    "MonitorReportType",
    "ReverseIpSearchType",
    "ReverseMatchType",
    "ReverseMxSearchType",
    "ReverseSearchType",
]
