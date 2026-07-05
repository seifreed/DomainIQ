"""Aiohttp-backed asynchronous HTTP transport."""

from __future__ import annotations

import asyncio
import contextlib
import importlib
from typing import TYPE_CHECKING, Any

from ._responses import AsyncResponse

if TYPE_CHECKING:
    from aiohttp import ClientSession


class AiohttpTransport:
    """AsyncTransport backed by aiohttp."""

    def __init__(
        self,
        timeout: float,
        connector_limit: int = 100,
        connector_limit_per_host: int = 30,
    ) -> None:
        try:
            self._aiohttp: Any = importlib.import_module("aiohttp")
        except ImportError as e:
            msg = (
                "aiohttp is required for AsyncDomainIQClient. "
                "Install it with: pip install aiohttp"
            )
            raise ImportError(msg) from e

        self._timeout = timeout
        self._connector_limit = connector_limit
        self._connector_limit_per_host = connector_limit_per_host
        self._session: ClientSession | None = None
        self._connector: Any = None
        self._closed = False
        self._lock = asyncio.Lock()

    async def _get_session(self) -> ClientSession:
        async with self._lock:
            if self._closed:
                msg = "Transport is closed"
                raise RuntimeError(msg)
            if self._session is None or self._session.closed:
                if self._connector is not None:
                    await self._connector.close()
                self._connector = self._aiohttp.TCPConnector(
                    limit=self._connector_limit,
                    limit_per_host=self._connector_limit_per_host,
                )
                try:
                    self._session = self._aiohttp.ClientSession(
                        connector=self._connector,
                    )
                except BaseException:
                    with contextlib.suppress(Exception):
                        await self._connector.close()
                    self._connector = None
                    raise
            return self._session

    async def get(
        self,
        url: str,
        params: dict[str, str],
        request_timeout: float,
    ) -> AsyncResponse:
        client_timeout = self._aiohttp.ClientTimeout(total=request_timeout)
        session = await self._get_session()
        try:
            async with session.get(url, params=params, timeout=client_timeout) as resp:
                body = await resp.text()
                return AsyncResponse(
                    status=resp.status,
                    headers=resp.headers,
                    _body=body,
                )
        except TimeoutError as e:
            raise TimeoutError(str(e)) from e
        except RuntimeError as e:
            if "closed" in str(e).lower():
                raise OSError(str(e)) from e
            raise
        except self._aiohttp.ClientError as e:
            raise OSError(str(e)) from e
        except UnicodeDecodeError as e:
            raise OSError(str(e)) from e

    async def close(self) -> None:
        async with self._lock:
            self._closed = True
            if self._session is not None and not self._session.closed:
                await self._session.close()
            self._connector = None

    @property
    def is_open(self) -> bool:
        """Check whether the transport is open.

        Note that in async contexts the result is a snapshot and may be
        stale by the time it is read — there is no lock held on the read
        path. Use :meth:`close` for a definitive transition to closed.
        """
        return not self._closed

    def try_sync_close(self) -> None:
        """Best-effort synchronous teardown for ``__del__`` / GC contexts.

        Async transports cannot be fully torn down from a sync context.
        This method marks the transport closed and attempts to close the
        underlying connector if it exposes a synchronous ``close``.
        Callers should prefer ``await transport.close()``.
        """
        self._closed = True
        connector = self._connector
        if connector is not None:
            close = getattr(connector, "close", None)
            if close is not None:
                close()
            self._connector = None


__all__ = ["AiohttpTransport"]
