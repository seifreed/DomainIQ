"""WHOIS request-parameter builders."""

from __future__ import annotations

from typing import Any

from ..constants import API_FLAG_ENABLED
from ..validators import validate_whois_target


def build_whois_params(
    domain: str | None,
    ip: str | None,
    full: bool,
    current_only: bool,
) -> dict[str, Any]:
    """Build parameters for the WHOIS endpoint."""
    domain, ip = validate_whois_target(domain, ip)
    params: dict[str, Any] = {"service": "whois"}
    if domain:
        params["domain"] = domain
    if ip:
        params["ip"] = ip
    if full:
        params["full"] = API_FLAG_ENABLED
    if current_only:
        params["current_only"] = API_FLAG_ENABLED
    return params
