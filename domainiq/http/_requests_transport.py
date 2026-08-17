"""Requests-backed synchronous HTTP transport."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ._responses import SyncResponse

if TYPE_CHECKING:
    from collections.abc import Mapping


class _HttpResponse(Protocol):
    """The subset of a requests-style response the transport reads."""

    status_code: int
    text: str

    @property
    def headers(self) -> Mapping[str, str]: ...


class _HttpSession(Protocol):
    """The subset of ``requests.Session`` the transport drives.

    Both ``requests.Session`` and in-memory test doubles satisfy this, so the
    session can be injected without patching ``requests.Session``.
    """

    def get(
        self, url: str, *, params: dict[str, str], timeout: float
    ) -> _HttpResponse: ...

    def mount(self, prefix: str, adapter: object) -> None: ...

    def close(self) -> None: ...


class RequestsTransport:
    """SyncTransport backed by the requests library."""

    def __init__(self, session: _HttpSession | None = None) -> None:
        self._session: requests.Session | _HttpSession = (
            requests.Session() if session is None else session
        )
        self._requests_timeout_exc = requests.exceptions.Timeout
        self._requests_request_exc = requests.exceptions.RequestException
        self._closed = False
        # Retries are handled in _request_pipeline; disable urllib3 auto-retry.
        adapter = HTTPAdapter(max_retries=Retry(total=0, connect=0, read=0))
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)

    def get(
        self,
        url: str,
        params: dict[str, str],
        timeout: float,
    ) -> SyncResponse:
        try:
            resp = self._session.get(url, params=params, timeout=timeout)
            return SyncResponse(
                status_code=resp.status_code,
                headers=resp.headers,
                text=resp.text,
            )
        except self._requests_timeout_exc as e:
            raise TimeoutError(str(e)) from e
        except self._requests_request_exc as e:
            raise OSError(str(e)) from e

    @property
    def is_open(self) -> bool:
        """Best-effort check whether the transport has been closed."""
        return not self._closed

    def close(self) -> None:
        self._session.close()
        self._closed = True


__all__ = ["RequestsTransport"]
