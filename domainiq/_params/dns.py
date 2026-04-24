"""DNS request-parameter builders."""

from __future__ import annotations

from typing import Any

from ..models import DNSRecordType


def build_dns_params(
    query: str,
    record_types: list[str | DNSRecordType] | None,
) -> dict[str, Any]:
    """Build parameters for the DNS endpoint."""
    params: dict[str, Any] = {"service": "dns", "q": query}
    if record_types:
        params["types"] = ",".join(
            record.value if isinstance(record, DNSRecordType) else str(record)
            for record in record_types
        )
    return params
