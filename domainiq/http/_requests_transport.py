"""Requests-backed synchronous HTTP transport."""

from __future__ import annotations

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ._responses import SyncResponse


class RequestsTransport:
    """SyncTransport backed by the requests library."""

    def __init__(self) -> None:
        self._session = requests.Session()
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
        except UnicodeDecodeError as e:
            raise OSError(str(e)) from e

    @property
    def is_open(self) -> bool:
        """Best-effort check whether the transport has been closed."""
        return not self._closed

    def close(self) -> None:
        self._session.close()
        self._closed = True


__all__ = ["RequestsTransport"]
