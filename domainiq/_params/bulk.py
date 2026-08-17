"""Bulk-operation request-parameter builders."""

from __future__ import annotations

from typing import Any

from domainiq._models import BulkWhoisType, DNSRecordType
from domainiq._models.enums import DNS_RECORD_TYPE_VALUES
from domainiq.exceptions import DomainIQValidationError
from domainiq.validators import is_ip_address, validate_domain

from ._shared import require_non_empty, require_valid_domains, validate_type_value

_BULK_WHOIS_TYPES = {member.value for member in BulkWhoisType}


def build_bulk_dns_params(
    domains: list[str],
    record_type: DNSRecordType | str | None = None,
) -> dict[str, Any]:
    """Build parameters for bulk DNS.

    ``record_type`` is optional; when omitted the API defaults to ``NS``.
    """
    require_non_empty("domains", domains)
    require_valid_domains(domains, "domains")
    params: dict[str, Any] = {"service": "bulk_dns", "domains": domains}
    if record_type is not None:
        params["type"] = validate_type_value(
            record_type, DNS_RECORD_TYPE_VALUES, "record_type"
        )
    return params


def build_bulk_whois_params(
    items: list[str],
    lookup_type: BulkWhoisType | str,
) -> dict[str, Any]:
    """Build parameters for bulk WHOIS."""
    require_non_empty("items", items)
    require_valid_domains(items, "items")
    lookup_type_value = validate_type_value(
        lookup_type, _BULK_WHOIS_TYPES, "lookup_type"
    )
    return {
        "service": "bulk_whois",
        "type": lookup_type_value,
        "domains": items,
    }


def build_bulk_whois_ip_params(domains: list[str]) -> dict[str, Any]:
    """Build parameters for bulk WHOIS IP."""
    require_non_empty("domains", domains)
    for entry in domains:
        stripped = entry.strip()
        if not validate_domain(stripped) and not is_ip_address(stripped):
            msg = f"Invalid domain or IP address: {entry}"
            raise DomainIQValidationError(msg, param_name="domains")
    return {"service": "bulk_whois_ip", "domains": [d.strip() for d in domains]}
