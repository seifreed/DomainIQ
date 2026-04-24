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
        # Retries are handled in _request_pipeline; disable urllib3 auto-retry.
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


__all__ = ["RequestsTransport"]
