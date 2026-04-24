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

from ._models import (
    DNSRecord,
    DNSResult,
    DomainCategory,
    DomainReport,
    DomainSnapshot,
    IpReportResult,
    MonitorActionResult,
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
from .utils import assert_json_dict

logger = logging.getLogger(__name__)

# Maps DNS record type to the field name(s) the API uses for its value.
# Different record types use different key names (e.g. 'address' for A/AAAA,
# 'exchange' for MX); 'value' is the generic fallback for unknown types.
_RECORD_VALUE_KEYS: dict[str, tuple[str, ...]] = {
    "A": ("ip", "value"),
    "AAAA": ("ip", "value"),
    "MX": ("exchange", "target", "value"),
    "CNAME": ("target", "value"),
    "TXT": ("txt", "value"),
    "NS": ("nameserver", "target", "value"),
    "SOA": ("mname", "target", "value"),
    "PTR": ("ptrdname", "target", "value"),
}


def _extract_record_value(record_data: dict[str, Any], record_type: str) -> str:
    """Extract the record value from a DNS record dict.

    The DomainIQ API uses different field names per record type
    (e.g. 'ip' for A/AAAA, 'exchange' for MX, 'target' for CNAME).
    ``_RECORD_VALUE_KEYS``
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


def parse_dns_result(envelope: dict[str, Any]) -> DNSResult:
    """Parse a DomainIQ API DNS response dict into a DNSResult."""
    inner = unwrap_api_envelope(envelope, ("results", "records", "domain"))
    results = inner.get("results") or inner.get("records") or []
    domain = inner.get("domain", "")
    if not domain and results and isinstance(results[0], dict):
        # Prefer SOA or NS records for domain extraction
        for rec in results:
            if rec.get("type") in ("SOA", "NS"):
                domain = rec.get("host") or rec.get("name", "")
            if domain:
                break
        else:
            domain = results[0].get("host") or results[0].get("name", "")
    records = []
    for record_data in results:
        record_type = record_data.get("type", "")
        records.append(
            DNSRecord(
                name=record_data.get("host", record_data.get("name", "")),
                type=record_type,
                value=_extract_record_value(record_data, record_type),
                ttl=record_data.get("ttl"),
                priority=record_data.get("pri", record_data.get("priority")),
            )
        )
    return DNSResult(domain=domain, records=records)


def parse_domain_category(envelope: dict[str, Any]) -> DomainCategory:
    """Parse a DomainIQ API categorization response dict into a DomainCategory."""
    inner = unwrap_api_envelope(envelope, ("domain", "categories"))
    return DomainCategory(
        domain=inner.get("domain", ""),
        categories=inner.get("categories", []) or [],
        confidence_score=inner.get("confidence_score"),
    )


def parse_domain_snapshot(envelope: dict[str, Any]) -> DomainSnapshot:
    """Parse a DomainIQ API snapshot response dict into a DomainSnapshot."""
    inner = unwrap_api_envelope(envelope, ("domain", "screenshot_url"))
    raw_str = inner.get("raw_data") or inner.get("raw")
    raw_bytes: bytes | None = None
    if isinstance(raw_str, str) and raw_str:
        try:
            raw_bytes = base64.b64decode(raw_str, validate=True)
        except binascii.Error:
            logger.debug("Failed to base64-decode raw_data field: %r", raw_str[:50])
    return DomainSnapshot(
        domain=inner.get("domain", ""),
        screenshot_url=inner.get("screenshot_url"),
        timestamp=try_parse_date(inner.get("timestamp")),
        width=inner.get("width"),
        height=inner.get("height"),
        raw_data=raw_bytes,
    )


def parse_domain_report(envelope: dict[str, Any]) -> DomainReport:
    """Parse a DomainIQ API domain report response dict into a DomainReport."""
    inner = unwrap_api_envelope(envelope, ("domain", "whois"))
    return DomainReport(
        domain=inner.get("domain", ""),
        whois_data=parse_whois_result(inner["whois"]) if inner.get("whois") else None,
        dns_data=parse_dns_result(inner["dns"]) if inner.get("dns") else None,
        categories=inner.get("categories"),
        related_domains=inner.get("related_domains"),
        risk_score=inner.get("risk_score"),
    )


def parse_monitor_report(envelope: dict[str, Any]) -> MonitorReport:
    """Parse a DomainIQ API monitor report response dict into a MonitorReport."""
    inner = unwrap_api_envelope(envelope, ("name", "items"))
    items = [
        MonitorItem(
            id=item_data.get("id", 0),
            type=item_data.get("type", ""),
            value=item_data.get("value", ""),
            enabled=parse_bool(item_data.get("enabled"), default=True),
            typos_enabled=parse_bool(item_data.get("typos_enabled"), default=False),
            typo_strength=item_data.get("typo_strength"),
        )
        for item_data in inner.get("items", []) or []
    ]
    return MonitorReport(
        id=inner.get("id", 0),
        name=inner.get("name", ""),
        type=inner.get("type", ""),
        email_alerts=parse_bool(inner.get("email_alerts"), default=False),
        created_date=try_parse_date(inner.get("created_date")),
        items=items,
    )


def parse_monitor_action_result(data: dict[str, Any]) -> MonitorActionResult:
    """Validate and cast a monitor action/read response."""
    return cast("MonitorActionResult", data)


def parse_search_result(data: dict[str, Any]) -> SearchResult:
    """Wrap raw API dict as a SearchResult."""
    return cast("SearchResult", data)


def parse_reverse_search_result(data: dict[str, Any]) -> ReverseSearchResult:
    """Wrap raw API dict as ReverseSearchResult."""
    return cast("ReverseSearchResult", data)


def parse_ip_report_result(raw: dict[str, Any] | list[Any] | str) -> IpReportResult:
    """Validate and cast a raw API response to IpReportResult."""
    return cast("IpReportResult", assert_json_dict(raw))
