"""Bulk-operation request-parameter builders."""

from __future__ import annotations

from typing import Any

from domainiq._models import BulkWhoisType
from domainiq.exceptions import DomainIQValidationError
from domainiq.utils import enum_value
from domainiq.validators import validate_domain

from ._shared import require_non_empty

_BULK_WHOIS_TYPES = {member.value for member in BulkWhoisType}


def _validate_domain_items(items: list[str], param_name: str) -> None:
    for item in items:
        if not validate_domain(item):
            msg = f"Invalid domain: {item}"
            raise DomainIQValidationError(msg, param_name=param_name)


def _validate_lookup_type(lookup_type: BulkWhoisType | str) -> str:
    lookup_type_value = enum_value(lookup_type)
    if (
        not isinstance(lookup_type_value, str)
        or lookup_type_value not in _BULK_WHOIS_TYPES
    ):
        msg = f"Invalid lookup_type: {lookup_type_value}"
        raise DomainIQValidationError(msg, param_name="lookup_type")
    return lookup_type_value


def build_bulk_dns_params(domains: list[str]) -> dict[str, Any]:
    """Build parameters for bulk DNS."""
    require_non_empty("domains", domains)
    _validate_domain_items(domains, "domains")
    return {"service": "bulk_dns", "domains": domains}


def build_bulk_whois_params(
    items: list[str],
    lookup_type: BulkWhoisType | str,
) -> dict[str, Any]:
    """Build parameters for bulk WHOIS."""
    require_non_empty("items", items)
    _validate_domain_items(items, "items")
    lookup_type_value = _validate_lookup_type(lookup_type)
    return {
        "service": "bulk_whois",
        "type": lookup_type_value,
        "domains": items,
    }


def build_bulk_whois_ip_params(domains: list[str]) -> dict[str, Any]:
    """Build parameters for bulk WHOIS IP."""
    require_non_empty("domains", domains)
    return {"service": "bulk_whois_ip", "domains": domains}
