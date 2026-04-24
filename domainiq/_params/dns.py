"""DNS request-parameter builders."""

from __future__ import annotations

from typing import Any

from domainiq._models import DNSRecordType
from domainiq.exceptions import DomainIQValidationError


def build_dns_params(
    query: str,
    record_types: list[str | DNSRecordType] | None,
) -> dict[str, Any]:
    """Build parameters for the DNS endpoint."""
    params: dict[str, Any] = {"service": "dns", "q": query}
    if record_types:
        type_values = [
            record.value if isinstance(record, DNSRecordType) else str(record).strip()
            for record in record_types
        ]
        if any(not record_type for record_type in type_values):
            msg = "record_types must not contain empty values"
            raise DomainIQValidationError(msg, param_name="record_types")
        params["types"] = ",".join(type_values)
    return params
