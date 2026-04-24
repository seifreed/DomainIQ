"""Domain-analysis request-parameter builders."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from domainiq.constants import API_FLAG_ENABLED
from domainiq.validators import ensure_positive_int

from ._shared import require_non_empty

if TYPE_CHECKING:
    from domainiq._models import SnapshotOptions


def build_domain_categorize_params(domains: list[str]) -> dict[str, Any]:
    """Build parameters for the categorize endpoint."""
    require_non_empty("domains", domains)
    return {"service": "categorize", "domains": ",".join(domains)}


def build_domain_snapshot_params(
    domain: str,
    options: SnapshotOptions,
) -> dict[str, Any]:
    """Build parameters for the snapshot endpoint."""
    ensure_positive_int("SnapshotOptions.width", options.width)
    ensure_positive_int("SnapshotOptions.height", options.height)
    params: dict[str, Any] = {
        "service": "snapshot",
        "domain": domain,
        "width": options.width,
        "height": options.height,
    }
    if options.full:
        params["full"] = API_FLAG_ENABLED
    if options.no_cache:
        params["no_cache"] = API_FLAG_ENABLED
    if options.raw:
        params["raw"] = API_FLAG_ENABLED
    return params


def build_domain_snapshot_history_params(
    domain: str,
    width: int,
    height: int,
    limit: int,
) -> dict[str, Any]:
    """Build parameters for the snapshot-history endpoint."""
    ensure_positive_int("width", width)
    ensure_positive_int("height", height)
    ensure_positive_int("limit", limit)
    return {
        "service": "snapshot_history",
        "domain": domain,
        "width": width,
        "height": height,
        "limit": limit,
    }
