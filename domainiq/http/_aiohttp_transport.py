"""Aiohttp-backed asynchronous HTTP transport."""

from __future__ import annotations

import asyncio
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
        self._lock = asyncio.Lock()

    async def _get_session(self) -> ClientSession:
        async with self._lock:
            if self._session is None or self._session.closed:
                self._session = self._aiohttp.ClientSession(
                    connector=self._aiohttp.TCPConnector(
                        limit=self._connector_limit,
                        limit_per_host=self._connector_limit_per_host,
                    ),
                )
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
        except self._aiohttp.ClientError as e:
            raise OSError(str(e)) from e

    async def close(self) -> None:
        async with self._lock:
            if self._session is not None and not self._session.closed:
                await self._session.close()

    @property
    def is_open(self) -> bool:
        return self._session is not None and not self._session.closed


__all__ = ["AiohttpTransport"]
