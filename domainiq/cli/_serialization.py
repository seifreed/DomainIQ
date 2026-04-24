"""CLI result serialization and output helpers."""

from __future__ import annotations

import base64
import dataclasses
import json
import sys
from datetime import datetime

from domainiq.exceptions import DomainIQError


def serialize_result(obj: object) -> object:
    """Serialize an API result object for JSON output."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode("ascii")
    if isinstance(obj, dict):
        return {key: serialize_result(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [serialize_result(item) for item in obj]
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {key: serialize_result(value) for key, value in vars(obj).items()}
    return obj


def print_result(result: object, indent: int = 2) -> None:
    """Print API result in formatted JSON."""
    if result is None:
        sys.stdout.write("No data returned\n")
        return

    try:
        serialized = serialize_result(result)
        sys.stdout.write(f"{json.dumps(serialized, indent=indent, default=str)}\n")
    except (TypeError, ValueError) as exc:
        msg = f"Failed to serialize result as JSON: {exc}"
        raise DomainIQError(msg) from exc


__all__ = ["print_result", "serialize_result"]
