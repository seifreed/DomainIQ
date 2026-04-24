"""Transport protocols for DomainIQ HTTP adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from ._responses import AsyncResponse, SyncResponse


@runtime_checkable
class SyncTransport(Protocol):
    """Contract for synchronous HTTP transports.

    Implementations must translate library-specific exceptions to standard
    Python exceptions:
        - TimeoutError  for request timeouts
        - OSError       for any other network/connection failure
    """

    def get(
        self,
        url: str,
        params: dict[str, str],
        timeout: float,
    ) -> SyncResponse: ...

    def close(self) -> None: ...


@runtime_checkable
class AsyncTransport(Protocol):
    """Contract for asynchronous HTTP transports."""

    async def get(
        self,
        url: str,
        params: dict[str, str],
        request_timeout: float,
    ) -> AsyncResponse: ...

    async def close(self) -> None: ...

    @property
    def is_open(self) -> bool: ...


__all__ = ["AsyncTransport", "SyncTransport"]
