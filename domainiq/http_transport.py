"""HTTP transport abstractions for DomainIQ clients.

Decouples the sync and async clients from specific HTTP libraries (requests,
aiohttp). Concrete implementations translate library-specific exceptions to
standard Python exceptions so callers never need to import requests or aiohttp.
"""

from __future__ import annotations

import asyncio
import importlib
import json as _json
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

if TYPE_CHECKING:
    from collections.abc import Mapping

    from aiohttp import ClientSession


logger = logging.getLogger(__name__)


def _decode_json_body(text: str) -> dict[str, Any] | list[Any]:
    decoded = _json.loads(text)
    if isinstance(decoded, (dict, list)):
        return decoded
    msg = f"Expected JSON object or array, got {type(decoded).__name__}"
    raise ValueError(msg)


@dataclass
class SyncResponse:
    """Snapshot of a synchronous HTTP response."""

    status_code: int
    headers: Mapping[str, str]
    text: str
    _json_data: dict[str, Any] | list[Any] | None = field(default=None, repr=False)

    def json(self) -> dict[str, Any] | list[Any]:
        if self._json_data is None:
            self._json_data = _decode_json_body(self.text)
        return self._json_data


@dataclass
class AsyncResponse:
    """Snapshot of an asynchronous HTTP response (body already read)."""

    status: int
    headers: Mapping[str, str]
    _body: str
    _json_data: dict[str, Any] | list[Any] | None = field(default=None, repr=False)

    @property
    def status_code(self) -> int:
        return self.status

    @property
    def text(self) -> str:
        return self._body

    def json(self) -> dict[str, Any] | list[Any]:
        if self._json_data is None:
            self._json_data = _decode_json_body(self._body)
        return self._json_data


# ---------------------------------------------------------------------------
# Transport Protocols
# ---------------------------------------------------------------------------


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
    """Contract for asynchronous HTTP transports.

    Same exception contract as SyncTransport.
    """

    async def get(
        self,
        url: str,
        params: dict[str, str],
        request_timeout: float,
    ) -> AsyncResponse: ...

    async def close(self) -> None: ...

    @property
    def is_open(self) -> bool: ...


class RequestsTransport:
    """SyncTransport backed by the requests library."""

    def __init__(self) -> None:
        self._session = requests.Session()
        self._requests_timeout_exc = requests.exceptions.Timeout
        self._requests_request_exc = requests.exceptions.RequestException
        # Retries are handled in _make_request; disable urllib3 auto-retry
        adapter = HTTPAdapter(max_retries=Retry(total=0, connect=0, read=0))
        self._session.mount("https://", adapter)

    def get(
        self,
        url: str,
        params: dict[str, str],
        timeout: float,
    ) -> SyncResponse:
        try:
            resp = self._session.get(url, params=params, timeout=timeout)
        except self._requests_timeout_exc as e:
            raise TimeoutError(str(e)) from e
        except self._requests_request_exc as e:
            raise OSError(str(e)) from e

        return SyncResponse(
            status_code=resp.status_code,
            headers=resp.headers,
            text=resp.text,
        )

    def close(self) -> None:
        self._session.close()


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
