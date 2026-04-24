"""Primitive parsing utilities shared across model deserialization."""

import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "parse_bool",
    "parse_emails",
    "parse_nameservers",
    "parse_statuses",
    "try_parse_date",
    "unwrap_api_envelope",
]

# Date formats returned by DomainIQ API across different record types and regions.
_DATE_FORMATS = (
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%d-%b-%Y",
    "%m/%d/%Y",
    "%d/%m/%Y",
)

# Minimum digit count for a string to be treated as a Unix timestamp.
# 10 digits covers seconds-epoch from 2001-09-09 onward, excluding short
# numeric strings like "2023" that would produce absurd 1970-era dates.
_TIMESTAMP_MIN_DIGITS = 10


def try_parse_date(date_str: str | None) -> datetime | None:
    """Parse a date string using a 4-stage fallback chain.

    Tries in order:
    1. ``datetime.fromisoformat()`` — ISO 8601 / RFC 3339
    2. Unix timestamp — float string with '.' or >= 10 digits (avoids short
       numeric strings like "2023" producing absurd 1970-era dates)
    3. Six explicit strptime formats (see ``_DATE_FORMATS``)
    4. Returns ``None`` if all stages fail
    """
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str)
    except (ValueError, AttributeError):
        logger.debug("try_parse_date: fromisoformat failed for %r", date_str[:80])
    stripped = date_str.strip()
    digits = stripped.lstrip("-")
    if "." in stripped or (digits.isdigit() and len(digits) >= _TIMESTAMP_MIN_DIGITS):
        try:
            return datetime.fromtimestamp(float(stripped))  # noqa: DTZ006 — API returns naive UTC epoch; naive datetime is the project-wide contract for parsed dates
        except (ValueError, TypeError, OSError):
            logger.debug("try_parse_date: timestamp parse failed for %r", date_str[:80])
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(date_str, fmt)  # noqa: DTZ007 — same naive-datetime contract as DTZ006; API does not supply timezone in string formats
        except ValueError:
            continue
    return None


def parse_bool(value: object, default: bool = False) -> bool:
    """Parse a value to bool, handling string representations from API responses."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.lower() in ("1", "true", "yes")
    return default


def unwrap_api_envelope(
    data: dict[str, Any], exclude_keys: tuple[str, ...]
) -> dict[str, Any]:
    """Unwrap {'result': {...}} top-level API envelope when present."""
    result = data.get("result")
    if isinstance(result, dict) and not any(k in data for k in exclude_keys):
        return result
    return data


def parse_nameservers(result: dict[str, Any]) -> list[str]:
    """Extract nameservers ordered by index, tolerating gaps in numbering."""
    ns_indexed: list[tuple[int, Any]] = []
    for key, value in result.items():
        if isinstance(key, str) and key.startswith("ns_"):
            suffix = key[3:]
            if suffix.isdigit():
                ns_indexed.append((int(suffix), value))
    ns_indexed.sort(key=lambda kv: kv[0])
    nameservers: list[Any] = [ns for _, ns in ns_indexed]

    if not nameservers:
        raw_ns = result.get("nameservers", []) or []
        nameservers = [raw_ns] if isinstance(raw_ns, str) and raw_ns else list(raw_ns)

    normalized: list[str] = []
    for ns in nameservers:
        if isinstance(ns, str):
            normalized.append(ns)
        elif isinstance(ns, dict) and "host" in ns:
            normalized.append(str(ns["host"]))
        elif ns is not None:
            normalized.append(str(ns))
    return normalized


def parse_statuses(raw: object) -> list[str]:
    """Normalize status field to a list of strings."""
    status = raw or []
    if isinstance(status, str):
        return [s for s in (part.strip() for part in status.split(",")) if s]
    if isinstance(status, list):
        return [
            s for s in (str(part).strip() for part in status if part is not None) if s
        ]
    parsed = str(status).strip()
    return [parsed] if parsed else []


def parse_emails(result: dict[str, Any]) -> list[str] | None:
    """Parse registrant emails from comma-separated string or list."""
    raw_emails = result.get("emails") or result.get("registrant_email")
    if isinstance(raw_emails, list):
        return [
            s for s in (str(e).strip() for e in raw_emails if e is not None) if s
        ] or None
    if isinstance(raw_emails, str):
        return [e.strip() for e in raw_emails.split(",") if e.strip()] or None
    return None
