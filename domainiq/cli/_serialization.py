"""CLI result serialization and output helpers."""

from __future__ import annotations

import base64
import dataclasses
import json
import sys
from datetime import datetime
from enum import Enum

from domainiq.exceptions import DomainIQError

_MAX_SERIALIZE_DEPTH = 100


def serialize_result(obj: object, _depth: int = 0) -> object:
    """Serialize an API result object for JSON output."""
    if _depth > _MAX_SERIALIZE_DEPTH:
        msg = "Maximum serialization depth exceeded"
        raise DomainIQError(msg)
    if isinstance(obj, datetime):
        result: object = obj.isoformat()
    elif isinstance(obj, bytes):
        result = base64.b64encode(obj).decode("ascii")
    elif isinstance(obj, Enum):
        result = obj.value
    elif isinstance(obj, dict):
        result = {
            key: serialize_result(value, _depth + 1) for key, value in obj.items()
        }
    elif isinstance(obj, (list, tuple)):
        result = [serialize_result(item, _depth + 1) for item in obj]
    elif dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        result = {
            key: serialize_result(value, _depth + 1) for key, value in vars(obj).items()
        }
    else:
        result = obj
    return result


def print_result(result: object, indent: int = 2) -> None:
    """Print API result in formatted JSON."""
    if result is None:
        sys.stdout.write("No data returned\n")
        return

    try:
        serialized = serialize_result(result)
        sys.stdout.write(f"{json.dumps(serialized, indent=indent, default=str)}\n")
    except (TypeError, ValueError, DomainIQError) as exc:
        msg = f"Failed to serialize result as JSON: {exc}"
        raise DomainIQError(msg) from exc


__all__ = ["print_result", "serialize_result"]
