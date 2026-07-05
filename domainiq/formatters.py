"""API parameter formatting and log sanitization utilities."""

import json
import logging
from enum import Enum
from typing import Any

from .constants import API_BOOL_FALSE, API_BOOL_TRUE

logger = logging.getLogger(__name__)

# 8 asterisks: intentionally opaque; length does not hint at key length
_API_KEY_LOG_MASK = "********"

# API parameter keys that use ">>" as list separator (bulk endpoints)
_BULK_SEPARATOR_KEYS = frozenset({"domains"})


def _sanitize_value(value: object) -> object:
    if isinstance(value, dict):
        return {
            k: _API_KEY_LOG_MASK if k in ("key", "api_key") else _sanitize_value(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_value(v) for v in value]
    return value


def sanitize_params_for_log(params: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of params with the API key masked for logging."""
    return {
        k: _API_KEY_LOG_MASK if k in ("key", "api_key") else _sanitize_value(v)
        for k, v in params.items()
    }


def _format_single_value(value: object) -> str:
    """Format a single value for API serialization."""
    if isinstance(value, bool):
        return API_BOOL_TRUE if value else API_BOOL_FALSE
    if isinstance(value, Enum):
        return str(value.value)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, (dict, list, tuple, set)):
        return json.dumps(_preprocess_for_json(value), default=str)
    return str(value)


def _preprocess_for_json(value: object) -> object:
    """Recursively format nested values before JSON serialization."""
    if isinstance(value, bool):
        return API_BOOL_TRUE if value else API_BOOL_FALSE
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {k: _preprocess_for_json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_preprocess_for_json(v) for v in value]
    return value


def _format_list_param(
    key: str,
    values: list[Any] | tuple[Any, ...] | set[Any],
) -> str | None:
    """Format a list/tuple parameter for API serialization."""
    if not values:
        return None
    if key in _BULK_SEPARATOR_KEYS:
        return ">>".join(_format_single_value(v) for v in values)
    if any(isinstance(v, (dict, list, tuple)) for v in values):
        return json.dumps(_preprocess_for_json(list(values)))
    # Sort sets for deterministic ordering; lists/tuples preserve caller order.
    if isinstance(values, set):
        try:
            values = sorted(values)
        except TypeError:
            values = sorted(values, key=str)
    return ",".join(_format_single_value(v) for v in values)


def format_api_params(params: dict[str, Any]) -> dict[str, str]:
    """Format parameters for API requests.

    Args:
        params: Dictionary of parameters

    Returns:
        Dictionary with properly formatted string values
    """
    formatted: dict[str, str] = {}

    for key, value in params.items():
        if value is None:
            continue

        if isinstance(value, bool):
            formatted[key] = API_BOOL_TRUE if value else API_BOOL_FALSE
        elif isinstance(value, Enum):
            formatted[key] = str(value.value)
        elif isinstance(value, dict):
            formatted[key] = json.dumps(_preprocess_for_json(value), default=str)
        elif isinstance(value, list | tuple | set):
            result = _format_list_param(key, value)
            if result is None:
                continue
            formatted[key] = result
        elif isinstance(value, bytes):
            formatted[key] = value.decode("utf-8", errors="replace")
        else:
            formatted[key] = str(value)

    return formatted
