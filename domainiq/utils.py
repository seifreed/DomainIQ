"""Utility functions for the DomainIQ library."""

import csv
import logging
from collections.abc import Callable, Mapping
from enum import Enum
from io import StringIO
from typing import Any

from .exceptions import DomainIQAPIError, DomainIQError

logger = logging.getLogger(__name__)

__all__ = [
    "assert_json_dict",
    "compute_backoff",
    "csv_to_dict_list",
    "ensure_list_of_models",
    "enum_value",
    "parse_retry_after",
    "setup_logging",
    "truncate_repr",
]


def enum_value(x: object) -> object:
    """Return x.value if x is an Enum member, otherwise return x unchanged."""
    return x.value if isinstance(x, Enum) else x


def assert_json_dict(raw: dict[str, Any] | list[Any] | str) -> dict[str, Any]:
    """Raise DomainIQAPIError if raw is not a JSON object (dict)."""
    if isinstance(raw, dict):
        return raw
    msg = f"Expected JSON dict but got {type(raw).__name__}: {truncate_repr(raw)}"
    raise DomainIQAPIError(msg)


def truncate_repr(value: object, max_len: int = 200) -> str:
    """Return repr(value) truncated to max_len characters with ellipsis."""
    r = repr(value)
    return r[:max_len] + "..." if len(r) > max_len else r


def compute_backoff(retry_delay: int, attempt: int) -> float:
    """Exponential backoff: retry_delay * 2^attempt."""
    return float(retry_delay * (2**attempt))


def parse_retry_after(headers: Mapping[str, str]) -> int | None:
    """Parse the Retry-After header value to seconds, or None if absent/invalid."""
    value = None
    for key, header_value in headers.items():
        if key.lower() == "retry-after":
            value = header_value
            break
    if value:
        try:
            return int(value)
        except (ValueError, TypeError):
            logger.debug("Could not parse Retry-After header value: %r", value)
    return None


def csv_to_dict_list(csv_content: str) -> list[dict[str, Any]]:
    """Convert CSV content to a list of dictionaries.

    Args:
        csv_content: CSV content as string

    Returns:
        List of dictionaries representing CSV rows

    Raises:
        DomainIQError: If CSV parsing fails
    """
    try:
        content = csv_content.strip()
        if not content:
            logger.debug("csv_to_dict_list: received empty content, returning []")
            return []
        if content[0] in ("{", "["):
            msg = "Expected CSV but received JSON-like content"
            raise DomainIQError(msg)
        csv_file = StringIO(content)
        reader = csv.DictReader(csv_file, delimiter=",")
        return list(reader)
    except csv.Error as e:
        msg = f"Failed to parse CSV content: {e}"
        raise DomainIQError(msg) from e


def setup_logging(
    level: str = "INFO", format_string: str | None = None, filename: str | None = None
) -> None:
    """Setup logging configuration for the library.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format_string: Custom format string for log messages
        filename: Optional filename to write logs to
    """
    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    lib_logger = logging.getLogger("domainiq")
    lib_logger.setLevel(getattr(logging, level.upper()))

    if not lib_logger.handlers:
        formatter = logging.Formatter(format_string, datefmt="%Y-%m-%d %H:%M:%S")
        if filename:
            handler: logging.Handler = logging.FileHandler(filename)
        else:
            handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        lib_logger.addHandler(handler)


def ensure_list_of_models[M](
    response: dict[str, Any] | list[Any],
    factory: Callable[[dict[str, Any]], M],
) -> list[M]:
    """Wrap a single-item dict or a list of dicts through factory, returning a list."""
    if isinstance(response, dict):
        return [factory(response)]
    return [factory(item) for item in response]
