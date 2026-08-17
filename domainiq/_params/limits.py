"""Account-limits request-parameter builders."""

from __future__ import annotations

from typing import Any


def build_limits_params() -> dict[str, Any]:
    """Build parameters for the account limits endpoint."""
    return {"service": "limits"}
