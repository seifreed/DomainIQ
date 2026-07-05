"""Tests for the shared request execution pipeline."""

from __future__ import annotations

import pytest

from domainiq._request_pipeline import execute_async_request, execute_sync_request
from domainiq.exceptions import DomainIQAPIError
from domainiq.http._responses import SyncResponse
from domainiq.request_policy import RequestPolicy


class _FakeSyncTransport:
    def __init__(self, outcomes: list[SyncResponse | BaseException]) -> None:
        self._outcomes = outcomes
        self._index = 0

    def get(self, url: str, params: dict[str, str], timeout: float) -> SyncResponse:
        outcome = self._outcomes[self._index]
        self._index += 1
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class _FakeAsyncTransport:
    def __init__(self, outcomes: list[SyncResponse | BaseException]) -> None:
        self._outcomes = outcomes
        self._index = 0

    async def get(
        self, url: str, params: dict[str, str], timeout: float
    ) -> SyncResponse:
        outcome = self._outcomes[self._index]
        self._index += 1
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def _policy(max_retries: int = 2) -> RequestPolicy:
    return RequestPolicy(
        base_url="https://api.example.test",
        timeout=5.0,
        max_retries=max_retries,
        retry_delay=1,
    )


def _ok_response(text: str = '{"ok": true}') -> SyncResponse:
    return SyncResponse(status_code=200, headers={}, text=text)


class TestExecuteSyncRequest:
    def test_success_on_first_attempt(self) -> None:
        transport = _FakeSyncTransport([_ok_response()])
        result = execute_sync_request(
            transport,  # type: ignore[arg-type]
            {"service": "whois"},
            "json",
            _policy(max_retries=0),
        )
        assert result == {"ok": True}

    def test_unicode_decode_error_raises_immediately(self) -> None:
        transport = _FakeSyncTransport(
            [UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid")]
        )
        with pytest.raises(DomainIQAPIError):
            execute_sync_request(
                transport,  # type: ignore[arg-type]
                {"service": "whois"},
                "json",
                _policy(max_retries=3),
            )

    def test_runtime_error_closed_retried(self) -> None:
        transport = _FakeSyncTransport(
            [
                RuntimeError("Session is closed"),
                _ok_response(),
            ]
        )
        result = execute_sync_request(
            transport,  # type: ignore[arg-type]
            {"service": "whois"},
            "json",
            _policy(max_retries=1),
        )
        assert result == {"ok": True}

    def test_runtime_error_transport_closed_variant_retried_regression(self) -> None:
        """Regression: RuntimeError with 'shut' instead of 'closed' was not retried."""
        transport = _FakeSyncTransport(
            [
                RuntimeError("Transport connection shut unexpectedly"),
                _ok_response(),
            ]
        )
        result = execute_sync_request(
            transport,  # type: ignore[arg-type]
            {"service": "whois"},
            "json",
            _policy(max_retries=1),
        )
        assert result == {"ok": True}

    def test_runtime_error_unrelated_not_retried(self) -> None:
        transport = _FakeSyncTransport(
            [
                RuntimeError("Something else"),
            ]
        )
        with pytest.raises(RuntimeError, match="Something else"):
            execute_sync_request(
                transport,  # type: ignore[arg-type]
                {"service": "whois"},
                "json",
                _policy(max_retries=1),
            )


@pytest.mark.asyncio
class TestExecuteAsyncRequest:
    async def test_success_on_first_attempt(self) -> None:
        transport = _FakeAsyncTransport([_ok_response()])
        result = await execute_async_request(
            transport,  # type: ignore[arg-type]
            {"service": "whois"},
            "json",
            _policy(max_retries=0),
        )
        assert result == {"ok": True}

    async def test_unicode_decode_error_raises_immediately(self) -> None:
        transport = _FakeAsyncTransport(
            [UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid")]
        )
        with pytest.raises(DomainIQAPIError):
            await execute_async_request(
                transport,  # type: ignore[arg-type]
                {"service": "whois"},
                "json",
                _policy(max_retries=3),
            )

    async def test_runtime_error_closed_retried(self) -> None:
        transport = _FakeAsyncTransport(
            [
                RuntimeError("Session is closed"),
                _ok_response(),
            ]
        )
        result = await execute_async_request(
            transport,  # type: ignore[arg-type]
            {"service": "whois"},
            "json",
            _policy(max_retries=1),
        )
        assert result == {"ok": True}

    async def test_runtime_error_transport_closed_variant_retried_regression(
        self,
    ) -> None:
        """Regression: RuntimeError with 'shut' instead of 'closed' was not retried."""
        transport = _FakeAsyncTransport(
            [
                RuntimeError("Transport connection shut unexpectedly"),
                _ok_response(),
            ]
        )
        result = await execute_async_request(
            transport,  # type: ignore[arg-type]
            {"service": "whois"},
            "json",
            _policy(max_retries=1),
        )
        assert result == {"ok": True}

    async def test_runtime_error_unrelated_not_retried(self) -> None:
        transport = _FakeAsyncTransport(
            [
                RuntimeError("Something else"),
            ]
        )
        with pytest.raises(RuntimeError, match="Something else"):
            await execute_async_request(
                transport,  # type: ignore[arg-type]
                {"service": "whois"},
                "json",
                _policy(max_retries=1),
            )

    def test_negative_max_retries_raises_value_error_regression(self) -> None:
        """Regression: negative max_retries reached unreachable AssertionError."""
        with pytest.raises(ValueError, match="max_retries must be non-negative"):
            RequestPolicy(
                base_url="https://api.example.test",
                timeout=5.0,
                max_retries=-1,
                retry_delay=1,
            )

    def test_unicode_decode_error_preserves_cause_regression(self) -> None:
        """Regression: UnicodeDecodeError is raised immediately with cause preserved."""
        original = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid")
        transport = _FakeSyncTransport([original])
        with pytest.raises(DomainIQAPIError) as exc_info:
            execute_sync_request(
                transport,  # type: ignore[arg-type]
                {"service": "whois"},
                "json",
                _policy(max_retries=3),
            )
        assert exc_info.value.__cause__ is original

    def test_runtime_error_closed_preserves_cause_regression(self) -> None:
        """Regression: RuntimeError cause was lost during retry wrapping."""
        original = RuntimeError("Session is closed")
        transport = _FakeSyncTransport([original, _ok_response()])
        execute_sync_request(
            transport,  # type: ignore[arg-type]
            {"service": "whois"},
            "json",
            _policy(max_retries=1),
        )
        assert transport._index == 2
