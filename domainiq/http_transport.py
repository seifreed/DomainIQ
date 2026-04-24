"""Backward-compatible HTTP transport exports.

Concrete transport definitions live in ``domainiq.http`` so response snapshots,
protocols, and sync/async backend implementations can evolve independently
without breaking existing ``domainiq.http_transport`` imports.
"""

from .http import (
    AiohttpTransport,
    AsyncResponse,
    AsyncTransport,
    RequestsTransport,
    SyncResponse,
    SyncTransport,
)

__all__ = [
    "AiohttpTransport",
    "AsyncResponse",
    "AsyncTransport",
    "RequestsTransport",
    "SyncResponse",
    "SyncTransport",
]
