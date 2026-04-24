"""Shared fixtures for transport-based unit tests."""

from __future__ import annotations

from typing import Any

import pytest

from domainiq import DomainIQClient
from domainiq.async_client import AsyncDomainIQClient
from domainiq.config import Config
from domainiq.http_transport import AsyncResponse, SyncResponse

# ---------------------------------------------------------------------------
# Sync mock transport
# ---------------------------------------------------------------------------


class MockSyncTransport:
    """Enqueues responses or exceptions; records all calls."""

    def __init__(self) -> None:
        self._queue: list[SyncResponse | BaseException] = []
        self.calls: list[dict[str, Any]] = []

    def enqueue(self, item: SyncResponse | BaseException) -> None:
        self._queue.append(item)

    def get(self, url: str, params: dict[str, str], timeout: float) -> SyncResponse:
        self.calls.append({"url": url, "params": params, "timeout": timeout})
        if not self._queue:
            msg = (
                "MockSyncTransport: no more enqueued responses "
                f"(call #{len(self.calls)})"
            )
            raise AssertionError(msg)
        item = self._queue.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def close(self) -> None:
        pass


def make_sync_response(
    status_code: int = 200,
    body: str = "{}",
    headers: dict[str, str] | None = None,
) -> SyncResponse:
    return SyncResponse(
        status_code=status_code,
        headers=headers or {},
        text=body,
    )


# ---------------------------------------------------------------------------
# Async mock transport
# ---------------------------------------------------------------------------


class MockAsyncTransport:
    """Async version of MockSyncTransport."""

    def __init__(self) -> None:
        self._queue: list[AsyncResponse | BaseException] = []
        self.calls: list[dict[str, Any]] = []

    def enqueue(self, item: AsyncResponse | BaseException) -> None:
        self._queue.append(item)

    async def get(
        self, url: str, params: dict[str, str], request_timeout: float
    ) -> AsyncResponse:
        self.calls.append({"url": url, "params": params, "timeout": request_timeout})
        if not self._queue:
            msg = (
                "MockAsyncTransport: no more enqueued responses "
                f"(call #{len(self.calls)})"
            )
            raise AssertionError(msg)
        item = self._queue.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    async def close(self) -> None:
        pass


def make_async_response(
    status: int = 200,
    body: str = "{}",
    headers: dict[str, str] | None = None,
) -> AsyncResponse:
    return AsyncResponse(
        status=status,
        headers=headers or {},
        _body=body,
    )


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_transport() -> MockSyncTransport:
    return MockSyncTransport()


@pytest.fixture
def mock_client(mock_transport: MockSyncTransport) -> DomainIQClient:
    config = Config(api_key="test-key-fixture", timeout=5, max_retries=3, retry_delay=0)
    return DomainIQClient(config=config, transport=mock_transport)


@pytest.fixture
def mock_async_transport() -> MockAsyncTransport:
    return MockAsyncTransport()


@pytest.fixture
def mock_async_client(mock_async_transport: MockAsyncTransport) -> AsyncDomainIQClient:
    config = Config(api_key="test-key-fixture", timeout=5, max_retries=3, retry_delay=0)
    return AsyncDomainIQClient(config=config, transport=mock_async_transport)


@pytest.fixture(autouse=True)
def _disable_request_pipeline_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep retry tests deterministic by removing real sleep delays."""

    async def _async_noop_sleep(_: float) -> None:
        return None

    monkeypatch.setattr("domainiq._request_pipeline._sync_sleep", lambda _: None)
    monkeypatch.setattr("domainiq._request_pipeline._async_sleep", _async_noop_sleep)
