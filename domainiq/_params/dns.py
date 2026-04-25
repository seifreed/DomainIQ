"""DNS request-parameter builders."""

from __future__ import annotations

from typing import Any

from domainiq._models import DNSRecordType
from domainiq.exceptions import DomainIQValidationError
from domainiq.validators import validate_domain

_DNS_RECORD_TYPES = {record.value for record in DNSRecordType}


def _normalize_record_type(record_type: str | DNSRecordType) -> str:
    value = (
        record_type.value
        if isinstance(record_type, DNSRecordType)
        else str(record_type).strip().upper()
    )
    if not value:
        msg = "record_types must not contain empty values"
        raise DomainIQValidationError(msg, param_name="record_types")
    if value not in _DNS_RECORD_TYPES:
        msg = f"Invalid record type: {value}"
        raise DomainIQValidationError(msg, param_name="record_types")
    return value


def build_dns_params(
    query: str,
    record_types: list[str | DNSRecordType] | None,
) -> dict[str, Any]:
    """Build parameters for the DNS endpoint."""
    if not validate_domain(query):
        msg = f"Invalid query: {query}"
        raise DomainIQValidationError(msg, param_name="query")

    params: dict[str, Any] = {"service": "dns", "q": query}
    if record_types:
        type_values = [_normalize_record_type(record) for record in record_types]
        params["types"] = ",".join(type_values)
    return params
