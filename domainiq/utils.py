"""Utility functions for the DomainIQ library."""

import csv
import logging
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from enum import Enum
from io import StringIO
from math import ceil
from typing import TYPE_CHECKING, Any

from .exceptions import DomainIQAPIError, DomainIQError

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

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
    "validate_api_dict",
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


def validate_api_dict(
    raw: dict[str, Any],
    expected_type_name: str,
    required_keys: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Validate that a raw API dict is non-empty and contains expected keys.

    Args:
        raw: The dict to validate (already confirmed dict by assert_json_dict).
        expected_type_name: Human-readable type name for error messages.
        required_keys: At least one of these keys must be present. If empty,
            only checks that the dict itself is non-empty.

    Returns:
        The same dict reference (passthrough).

    Raises:
        DomainIQAPIError: If the dict is empty or missing all required keys.
    """
    if not raw:
        msg = f"Expected {expected_type_name} but got empty dict"
        raise DomainIQAPIError(msg)
    if required_keys and not any(k in raw for k in required_keys):
        msg = (
            f"Expected {expected_type_name} with at least one of "
            f"{required_keys!r} but got {truncate_repr(raw)}"
        )
        raise DomainIQAPIError(msg)
    return raw


def truncate_repr(value: object, max_len: int = 200) -> str:
    """Return repr(value) truncated to max_len characters with ellipsis."""
    r = repr(value)
    max_len = max(max_len, 0)
    if len(r) > max_len:
        ellipsis = "..."
        if max_len < len(ellipsis):
            return r[:max_len]
        return r[: max_len - len(ellipsis)] + ellipsis
    return r


def compute_backoff(retry_delay: int, attempt: int) -> float:
    """Exponential backoff: retry_delay * 2^attempt."""
    capped_attempt = min(attempt, 10)
    return float(retry_delay * (2**capped_attempt))


def parse_retry_after(headers: Mapping[str, str]) -> int | None:
    """Parse the Retry-After header value to seconds, or None if absent/invalid."""
    value = None
    for key, header_value in headers.items():
        if key.lower() == "retry-after":
            value = header_value
            break
    if value:
        try:
            seconds = int(value)
        except ValueError, TypeError:
            try:
                retry_at = parsedate_to_datetime(value)
            except TypeError, ValueError, IndexError, OverflowError:
                logger.debug("Could not parse Retry-After header value: %r", value)
                return None
            if retry_at.tzinfo is None:
                retry_at = retry_at.replace(tzinfo=UTC)
            seconds = ceil((retry_at - datetime.now(UTC)).total_seconds())
            return seconds if seconds > 0 else None
        else:
            return seconds if seconds >= 0 else None
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
    if not isinstance(csv_content, str):
        msg = f"Expected CSV content as string, got {type(csv_content).__name__}"
        raise DomainIQError(msg)
    try:
        content = csv_content.strip()
        if not content:
            logger.debug("csv_to_dict_list: received empty content, returning []")
            return []
        with StringIO(content) as csv_file:
            reader = csv.DictReader(csv_file, delimiter=",")
            result = list(reader)
        if result:
            return result
        return []  # noqa: TRY300
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
    try:
        lib_logger.setLevel(getattr(logging, level.upper()))
    except AttributeError as exc:
        msg = f"Invalid logging level: {level}"
        raise ValueError(msg) from exc

    for old_handler in lib_logger.handlers[:]:
        lib_logger.removeHandler(old_handler)
        old_handler.close()

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
