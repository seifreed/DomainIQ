"""Primitive parsing utilities shared across model deserialization."""

import logging
from datetime import UTC, datetime
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


def _parse_numeric_timestamp(value: float, raw_value: object) -> datetime | None:
    try:
        return datetime.fromtimestamp(value, UTC).replace(tzinfo=None)
    except (OSError, OverflowError, ValueError):
        logger.debug(
            "try_parse_date: numeric timestamp parse failed for %r",
            raw_value,
        )
        return None


def _normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


def _parse_date_string(date_str: str) -> datetime | None:
    stripped = date_str.strip()
    if not stripped:
        return None
    try:
        return _normalize_datetime(datetime.fromisoformat(stripped))
    except ValueError:
        logger.debug("try_parse_date: fromisoformat failed for %r", date_str[:80])

    digits = stripped.lstrip("-")
    if "." in stripped or (digits.isdigit() and len(digits) >= _TIMESTAMP_MIN_DIGITS):
        try:
            timestamp = float(stripped)
        except ValueError:
            logger.debug("try_parse_date: timestamp parse failed for %r", date_str[:80])
        else:
            parsed = _parse_numeric_timestamp(timestamp, date_str)
            if parsed is not None:
                return parsed

    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(stripped, fmt)  # noqa: DTZ007 — same naive-datetime contract as DTZ006; API does not supply timezone in string formats
        except ValueError:
            continue
    return None


def try_parse_date(date_str: object) -> datetime | None:
    """Parse a date value using a tolerant fallback chain.

    Tries in order:
    1. Numeric Unix timestamp
    2. ``datetime.fromisoformat()`` — ISO 8601 / RFC 3339
    3. Unix timestamp string — float string with '.' or >= 10 digits (avoids short
       numeric strings like "2023" producing absurd 1970-era dates)
    4. Six explicit strptime formats (see ``_DATE_FORMATS``)
    5. Returns ``None`` if all stages fail
    """
    if date_str is None or isinstance(date_str, bool):
        return None
    if isinstance(date_str, int | float):
        return _parse_numeric_timestamp(date_str, date_str)
    if isinstance(date_str, str):
        return _parse_date_string(date_str)
    return None


def parse_bool(value: object, default: bool = False) -> bool:
    """Parse a value to bool, handling string representations from API responses."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes")
    return default


def unwrap_api_envelope(
    data: dict[str, Any], exclude_keys: tuple[str, ...]
) -> dict[str, Any]:
    """Unwrap {'result': {...}} top-level API envelope when present."""
    result = data.get("result")
    if isinstance(result, dict) and not any(k in data for k in exclude_keys):
        return result
    return data


def _normalize_nameserver_value(ns: object) -> str | None:
    if isinstance(ns, dict) and "host" in ns:
        ns = ns["host"]
    if ns is None:
        return None
    normalized = str(ns).strip()
    return normalized or None


def _normalize_nameserver_values(nameservers: list[Any]) -> list[str]:
    normalized: list[str] = []
    for ns in nameservers:
        normalized_name = _normalize_nameserver_value(ns)
        if normalized_name:
            normalized.append(normalized_name)
    return normalized


def parse_nameservers(result: dict[str, Any]) -> list[str]:
    """Extract nameservers ordered by index, tolerating gaps in numbering."""
    ns_indexed: list[tuple[int, Any]] = []
    for key, value in result.items():
        if isinstance(key, str) and key.startswith("ns_"):
            suffix = key[3:]
            if suffix.isdigit():
                ns_indexed.append((int(suffix), value))
    ns_indexed.sort(key=lambda kv: kv[0])
    indexed_nameservers = _normalize_nameserver_values([ns for _, ns in ns_indexed])
    if indexed_nameservers:
        return indexed_nameservers

    raw_ns = result.get("nameservers", []) or []
    if isinstance(raw_ns, str):
        nameservers: list[Any] = raw_ns.split(",")
    elif isinstance(raw_ns, dict):
        nameservers = [raw_ns]
    else:
        nameservers = list(raw_ns)
    return _normalize_nameserver_values(nameservers)


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


def _normalize_email_values(raw_emails: object) -> list[str] | None:
    if isinstance(raw_emails, list):
        return [
            s for s in (str(e).strip() for e in raw_emails if e is not None) if s
        ] or None
    if isinstance(raw_emails, str):
        return [e.strip() for e in raw_emails.split(",") if e.strip()] or None
    return None


def parse_emails(result: dict[str, Any]) -> list[str] | None:
    """Parse registrant emails from comma-separated string or list."""
    return _normalize_email_values(result.get("emails")) or _normalize_email_values(
        result.get("registrant_email")
    )
