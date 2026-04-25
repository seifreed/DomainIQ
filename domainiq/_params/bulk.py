"""Bulk-operation request-parameter builders."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from domainiq.exceptions import DomainIQValidationError
from domainiq.utils import enum_value
from domainiq.validators import validate_domain

from ._shared import require_non_empty

if TYPE_CHECKING:
    from domainiq._models import BulkWhoisType


def _validate_domain_items(items: list[str], param_name: str) -> None:
    for item in items:
        if not validate_domain(item):
            msg = f"Invalid domain: {item}"
            raise DomainIQValidationError(msg, param_name=param_name)


def build_bulk_dns_params(domains: list[str]) -> dict[str, Any]:
    """Build parameters for bulk DNS."""
    require_non_empty("domains", domains)
    _validate_domain_items(domains, "domains")
    return {"service": "bulk_dns", "domains": domains}


def build_bulk_whois_params(
    items: list[str],
    lookup_type: BulkWhoisType,
) -> dict[str, Any]:
    """Build parameters for bulk WHOIS."""
    require_non_empty("items", items)
    _validate_domain_items(items, "items")
    return {
        "service": "bulk_whois",
        "type": enum_value(lookup_type),
        "domains": items,
    }


def build_bulk_whois_ip_params(domains: list[str]) -> dict[str, Any]:
    """Build parameters for bulk WHOIS IP."""
    require_non_empty("domains", domains)
    return {"service": "bulk_whois_ip", "domains": domains}
