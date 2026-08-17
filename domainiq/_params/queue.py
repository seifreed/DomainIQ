"""Queue-management request-parameter builders."""

from __future__ import annotations

from typing import Any

from ._shared import require_non_empty_string


def build_submit_queued_params(service: str, params: dict[str, Any]) -> dict[str, Any]:
    """Build parameters for submitting any service request in queued mode."""
    require_non_empty_string(service, "service")
    return {**params, "service": service.strip(), "queued": 1}


def build_queue_params(request_hash: str, action: str) -> dict[str, Any]:
    """Build parameters for the queued-request management endpoint."""
    require_non_empty_string(request_hash, "hash")
    require_non_empty_string(action, "action")
    return {
        "service": "queue",
        "hash": request_hash.strip(),
        "action": action.strip(),
    }
