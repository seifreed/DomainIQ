"""Stateless parameter builders for DomainIQ API requests.

All functions are pure: they take inputs and return dicts, with no side effects.
Both DomainIQClient (sync) and AsyncDomainIQClient (async) import this module
directly, and callers can also use the builders standalone without a client.
"""

import logging
from typing import Any

from .constants import (
    API_BOOL_FALSE,
    API_BOOL_TRUE,
    API_FLAG_ENABLED,
    TYPO_STRENGTH_MAX,
    TYPO_STRENGTH_MIN,
)
from .models import (
    BulkWhoisType,
    DNSRecordType,
    DomainSearchFilters,
    KeywordMatchType,
    MonitorItemType,
    MonitorReportType,
    ReverseIpSearchType,
    ReverseMxSearchType,
    ReverseMatchType,
    ReverseSearchType,
    SnapshotOptions,
)
from .validators import ensure_positive_int, validate_whois_target

logger = logging.getLogger(__name__)

# Re-exported so callers can reference _params.TYPO_STRENGTH_MIN/MAX directly
__all__ = ["TYPO_STRENGTH_MIN", "TYPO_STRENGTH_MAX"]


def _require_non_empty(name: str, items: list) -> None:
    if not items:
        msg = f"{name} must not be empty"
        raise ValueError(msg)


def _validate_typo_strength(strength: int) -> None:
    if not (TYPO_STRENGTH_MIN <= strength <= TYPO_STRENGTH_MAX):
        msg = f"strength must be between {TYPO_STRENGTH_MIN} and {TYPO_STRENGTH_MAX}"
        raise ValueError(msg)


def _simple_service_params(service: str, key: str, value: str) -> dict[str, Any]:
    return {"service": service, key: value}


# -- WHOIS --


def build_whois_params(
    domain: str | None,
    ip: str | None,
    full: bool,
    current_only: bool,
) -> dict[str, Any]:
    domain, ip = validate_whois_target(domain, ip)
    params: dict[str, Any] = {"service": "whois"}
    if domain:
        params["domain"] = domain
    if ip:
        params["ip"] = ip
    if full:
        params["full"] = API_FLAG_ENABLED
    if current_only:
        params["current_only"] = API_FLAG_ENABLED
    return params


# -- DNS --


def build_dns_params(
    query: str,
    record_types: list[str | DNSRecordType] | None,
) -> dict[str, Any]:
    params: dict[str, Any] = {"service": "dns", "q": query}
    if record_types:
        params["types"] = ",".join(
            t.value if isinstance(t, DNSRecordType) else str(t)
            for t in record_types
        )
    return params


# -- Domain Analysis --


def build_domain_categorize_params(domains: list[str]) -> dict[str, Any]:
    _require_non_empty("domains", domains)
    return {"service": "categorize", "domains": ",".join(domains)}


def build_domain_snapshot_params(
    domain: str,
    options: SnapshotOptions,
) -> dict[str, Any]:
    params: dict[str, Any] = {
        "service": "snapshot",
        "domain": domain,
        "width": options.width,
        "height": options.height,
    }
    if options.full:
        params["full"] = API_FLAG_ENABLED
    if options.no_cache:
        params["no_cache"] = API_FLAG_ENABLED
    if options.raw:
        params["raw"] = API_FLAG_ENABLED
    return params


def build_domain_snapshot_history_params(
    domain: str,
    width: int,
    height: int,
    limit: int,
) -> dict[str, Any]:
    ensure_positive_int("width", width)
    ensure_positive_int("height", height)
    ensure_positive_int("limit", limit)
    return {
        "service": "snapshot_history",
        "domain": domain,
        "width": width,
        "height": height,
        "limit": limit,
    }


# -- Reports --


def build_domain_report_params(domain: str) -> dict[str, Any]:
    return _simple_service_params("domain_report", "domain", domain)


def build_name_report_params(name: str) -> dict[str, Any]:
    return _simple_service_params("name_report", "name", name)


def build_organization_report_params(organization: str) -> dict[str, Any]:
    return _simple_service_params("organization_report", "organization", organization)


def build_email_report_params(email: str) -> dict[str, Any]:
    return _simple_service_params("email_report", "email", email)


def build_ip_report_params(ip: str) -> dict[str, Any]:
    return _simple_service_params("ip_report", "ip", ip)


# -- Search --


def build_domain_search_params(
    keywords: list[str],
    conditions: list[str] | None,
    match: KeywordMatchType,
    filters: DomainSearchFilters | None,
) -> dict[str, Any]:
    if not keywords:
        msg = "keywords list cannot be empty"
        raise ValueError(msg)
    params: dict[str, Any] = {
        "service": "domain_search",
        "match": match.value if isinstance(match, KeywordMatchType) else match,
    }
    for idx, keyword in enumerate(keywords, 1):
        params[f"keyword[{idx}]"] = keyword
    if conditions and len(conditions) > len(keywords):
        msg = "conditions list cannot be longer than keywords list"
        raise ValueError(msg)
    if conditions:
        if len(conditions) < len(keywords):
            logger.warning(
                "Fewer conditions (%d) than keywords (%d); "
                "keywords without conditions will use API defaults",
                len(conditions),
                len(keywords),
            )
        for idx, condition in enumerate(conditions, 1):
            params[f"condition[{idx}]"] = condition
    if filters:
        params.update(filters)
    return params


def build_reverse_search_params(
    search_type: str | ReverseSearchType,
    search_term: str,
    match: ReverseMatchType,
) -> dict[str, Any]:
    return {
        "service": "reverse_search",
        "type": (
            search_type.value
            if isinstance(search_type, ReverseSearchType)
            else search_type
        ),
        "search": search_term,
        "match": match.value if isinstance(match, ReverseMatchType) else match,
    }


def build_reverse_dns_params(domain: str) -> dict[str, Any]:
    return {"service": "reverse_dns", "domain": domain}


def build_reverse_ip_params(search_type: ReverseIpSearchType | str, data: str) -> dict[str, Any]:
    return {"service": "reverse_ip", "type": search_type, "data": data}


def build_reverse_mx_params(
    search_type: ReverseMxSearchType | str,
    data: str,
    recursive: bool,
) -> dict[str, Any]:
    params: dict[str, Any] = {
        "service": "reverse_mx",
        "type": search_type,
        "data": data,
    }
    if recursive:
        params["recursive"] = API_FLAG_ENABLED
    return params


# -- Bulk --


def build_bulk_dns_params(domains: list[str]) -> dict[str, Any]:
    _require_non_empty("domains", domains)
    return {"service": "bulk_dns", "domains": domains}


def build_bulk_whois_params(
    items: list[str],
    lookup_type: BulkWhoisType,
) -> dict[str, Any]:
    _require_non_empty("items", items)
    return {
        "service": "bulk_whois",
        "type": (
            lookup_type.value
            if isinstance(lookup_type, BulkWhoisType)
            else lookup_type
        ),
        "domains": items,
    }


def build_bulk_whois_ip_params(domains: list[str]) -> dict[str, Any]:
    _require_non_empty("domains", domains)
    return {"service": "bulk_whois_ip", "domains": domains}


# -- Monitoring --


def build_monitor_list_params() -> dict[str, Any]:
    return {"service": "monitor", "action": "list"}


def build_monitor_report_items_params(report_id: int) -> dict[str, Any]:
    return {"service": "monitor", "action": "report_items", "report": report_id}


def build_monitor_report_summary_params(
    report_id: int,
    item_id: int | None,
    days_range: int | None,
) -> dict[str, Any]:
    params: dict[str, Any] = {
        "service": "monitor",
        "action": "report_summary",
        "report": report_id,
    }
    if item_id is not None:
        params["item"] = item_id
    if days_range is not None:
        params["range"] = days_range
    return params


def build_monitor_report_changes_params(
    report_id: int, change_id: int
) -> dict[str, Any]:
    return {
        "service": "monitor",
        "action": "report_changes",
        "report": report_id,
        "change": change_id,
    }


def build_create_monitor_report_params(
    report_type: MonitorReportType | str, name: str, email_alert: bool
) -> dict[str, Any]:
    return {
        "service": "monitor",
        "action": "report_create",
        "type": report_type,
        "name": name,
        "email_alert": API_BOOL_TRUE if email_alert else API_BOOL_FALSE,
    }


def build_add_monitor_item_params(
    report_id: int,
    item_type: MonitorItemType | str,
    items: list[str],
    enabled: bool | None = None,
) -> dict[str, Any]:
    params: dict[str, Any] = {
        "service": "monitor",
        "action": "report_item_add",
        "report_id": report_id,
        "type": item_type,
        "items": items,
    }
    if enabled is not None:
        params["enabled"] = enabled
    return params


def build_enable_typos_params(
    report_id: int, item_id: int, strength: int
) -> dict[str, Any]:
    _validate_typo_strength(strength)
    return {
        "service": "monitor",
        "action": "enable_typos",
        "report_id": report_id,
        "item_id": item_id,
        "strength": strength,
    }


def build_disable_typos_params(report_id: int, item_id: int) -> dict[str, Any]:
    return {
        "service": "monitor",
        "action": "disable_typos",
        "report_id": report_id,
        "item_id": item_id,
    }


def build_modify_typo_strength_params(
    report_id: int, item_id: int, strength: int
) -> dict[str, Any]:
    _validate_typo_strength(strength)
    return {
        "service": "monitor",
        "action": "modify_typo_strength",
        "report_id": report_id,
        "item_id": item_id,
        "strength": strength,
    }


def build_delete_monitor_item_params(item_id: int) -> dict[str, Any]:
    return {
        "service": "monitor",
        "action": "report_item_delete",
        "item_id": item_id,
    }


def build_delete_monitor_report_params(report_id: int) -> dict[str, Any]:
    return {
        "service": "monitor",
        "action": "report_delete",
        "report_id": report_id,
    }
