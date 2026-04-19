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


def sanitize_params_for_log(params: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of params with the API key masked for logging."""
    sanitized = params.copy()
    if "key" in sanitized:
        sanitized["key"] = _API_KEY_LOG_MASK
    return sanitized


def _format_single_value(value: object) -> str:
    """Format a single value for API serialization."""
    if isinstance(value, Enum):
        return str(value.value)
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, default=str)
    return str(value)


def _format_list_param(key: str, values: list | tuple) -> str:
    """Format a list/tuple parameter for API serialization."""
    if key in _BULK_SEPARATOR_KEYS:
        return ">>".join(_format_single_value(v) for v in values)
    if any(isinstance(v, (dict, list, tuple)) for v in values):
        return json.dumps(list(values), default=str)
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
            formatted[key] = json.dumps(value)
        elif isinstance(value, list | tuple):
            formatted[key] = _format_list_param(key, value)
        else:
            formatted[key] = str(value)

    return formatted
