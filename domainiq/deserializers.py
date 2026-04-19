"""Standalone API-response parsing functions.

These functions own all knowledge of the DomainIQ API envelope format.
``Model.from_dict`` classmethods delegate to these as thin wrappers so
that models stay pure data containers.
"""

from __future__ import annotations

import base64
import binascii
import logging
from typing import Any, cast

from .models import (
    DNSRecord,
    DNSResult,
    DomainCategory,
    DomainReport,
    DomainSnapshot,
    MonitorItem,
    MonitorReport,
    ReverseSearchResult,
    SearchResult,
    WhoisResult,
)
from .parsers import (
    parse_bool,
    parse_emails,
    parse_nameservers,
    parse_statuses,
    try_parse_date,
    unwrap_api_envelope,
)

logger = logging.getLogger(__name__)

# Maps DNS record type to the field name(s) the API uses for its value.
# Different record types use different key names (e.g. 'address' for A/AAAA,
# 'exchange' for MX); 'value' is the generic fallback for unknown types.
_RECORD_VALUE_KEYS: dict[str, tuple[str, ...]] = {
    "A":     ("ip", "value"),
    "AAAA":  ("ip", "value"),
    "MX":    ("target", "value"),
    "CNAME": ("target", "value"),
    "TXT":   ("txt", "value"),
    "NS":    ("target", "value"),
}


def _extract_record_value(record_data: dict[str, Any], record_type: str) -> str:
    """Extract the record value from a DNS record dict.

    The DomainIQ API uses different field names per record type
    (e.g. 'ip' for A/AAAA, 'target' for MX/CNAME). ``_RECORD_VALUE_KEYS``
    maps each type to its candidate fields; 'value' is the fallback for
    unknown types.
    """
    keys = _RECORD_VALUE_KEYS.get(record_type, ("value", "ip", "target"))
    for key in keys:
        if val := record_data.get(key):
            return str(val)
    return ""


def parse_whois_result(data: dict[str, Any]) -> WhoisResult:
    """Parse a DomainIQ API WHOIS response dict into a WhoisResult."""
    result = unwrap_api_envelope(data, ("domain", "ip", "registrar"))
    return WhoisResult(
        domain=result.get("domain"),
        ip=result.get("ip"),
        registrar=result.get("registrar"),
        registrant_name=result.get("registrant_name") or result.get("registrant"),
        registrant_organization=(
            result.get("registrant_organization") or result.get("org")
        ),
        registrant_email=parse_emails(result),
        creation_date=try_parse_date(result.get("creation_date")),
        expiration_date=try_parse_date(result.get("expiration_date")),
        updated_date=try_parse_date(
            result.get("update_date") or result.get("updated_date")
        ),
        nameservers=parse_nameservers(result),
        status=parse_statuses(result.get("status", [])),
        raw_data=result.get("raw") or result.get("raw_data"),
    )


def parse_dns_result(data: dict[str, Any]) -> DNSResult:
    """Parse a DomainIQ API DNS response dict into a DNSResult."""
    data = unwrap_api_envelope(data, ("results", "records", "domain"))
    results = data.get("results") or data.get("records") or []
    domain = data.get("domain", "")
    if not domain and results and isinstance(results[0], dict):
        # Prefer SOA or NS records for domain extraction
        for rec in results:
            if rec.get("type") in ("SOA", "NS") and rec.get("host"):
                domain = rec["host"]
                break
        else:
            domain = results[0].get("host", "")
    records = []
    for record_data in results:
        record_type = record_data.get("type", "")
        records.append(DNSRecord(
            name=record_data.get("host", record_data.get("name", "")),
            type=record_type,
            value=_extract_record_value(record_data, record_type),
            ttl=record_data.get("ttl"),
            priority=record_data.get("pri", record_data.get("priority")),
        ))
    return DNSResult(domain=domain, records=records)


def parse_domain_category(data: dict[str, Any]) -> DomainCategory:
    """Parse a DomainIQ API categorization response dict into a DomainCategory."""
    data = unwrap_api_envelope(data, ("domain", "categories"))
    return DomainCategory(
        domain=data.get("domain", ""),
        categories=data.get("categories", []) or [],
        confidence_score=data.get("confidence_score"),
    )


def parse_domain_snapshot(data: dict[str, Any]) -> DomainSnapshot:
    """Parse a DomainIQ API snapshot response dict into a DomainSnapshot."""
    data = unwrap_api_envelope(data, ("domain", "screenshot_url"))
    raw_str = data.get("raw_data") or data.get("raw")
    raw_bytes: bytes | None = None
    if isinstance(raw_str, str) and raw_str:
        try:
            raw_bytes = base64.b64decode(raw_str)
        except binascii.Error:
            logger.debug("Failed to base64-decode raw_data field: %r", raw_str[:50])
    return DomainSnapshot(
        domain=data.get("domain", ""),
        screenshot_url=data.get("screenshot_url"),
        timestamp=try_parse_date(data.get("timestamp")),
        width=data.get("width"),
        height=data.get("height"),
        raw_data=raw_bytes,
    )


def parse_domain_report(data: dict[str, Any]) -> DomainReport:
    """Parse a DomainIQ API domain report response dict into a DomainReport."""
    data = unwrap_api_envelope(data, ("domain", "whois"))
    return DomainReport(
        domain=data.get("domain", ""),
        whois_data=parse_whois_result(data["whois"]) if data.get("whois") else None,
        dns_data=parse_dns_result(data["dns"]) if data.get("dns") else None,
        categories=data.get("categories"),
        related_domains=data.get("related_domains"),
        risk_score=data.get("risk_score"),
    )


def parse_monitor_report(data: dict[str, Any]) -> MonitorReport:
    """Parse a DomainIQ API monitor report response dict into a MonitorReport."""
    data = unwrap_api_envelope(data, ("name", "items"))
    items = [
        MonitorItem(
            id=item_data.get("id", 0),
            type=item_data.get("type", ""),
            value=item_data.get("value", ""),
            enabled=parse_bool(item_data.get("enabled"), default=True),
            typos_enabled=parse_bool(item_data.get("typos_enabled"), default=False),
            typo_strength=item_data.get("typo_strength"),
        )
        for item_data in data.get("items", []) or []
    ]
    return MonitorReport(
        id=data.get("id", 0),
        name=data.get("name", ""),
        type=data.get("type", ""),
        email_alerts=parse_bool(data.get("email_alerts"), default=False),
        created_date=try_parse_date(data.get("created_date")),
        items=items,
    )


def parse_search_result(data: dict[str, Any]) -> SearchResult:
    """Wrap raw API dict as a SearchResult (passthrough cast, centralized for testability)."""
    return cast(SearchResult, data)


def parse_reverse_search_result(data: dict[str, Any]) -> ReverseSearchResult:
    """Wrap raw API dict as ReverseSearchResult (passthrough cast, centralized for testability)."""
    return cast(ReverseSearchResult, data)
