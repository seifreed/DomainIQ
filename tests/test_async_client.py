"""Unit and regression tests for the async DomainIQ client."""

from __future__ import annotations

import asyncio
import importlib.util

import pytest

from domainiq import DomainIQError
from domainiq.models import WhoisResult

AIOHTTP_AVAILABLE = importlib.util.find_spec("aiohttp") is not None

if AIOHTTP_AVAILABLE:
    from domainiq.async_client import AsyncDomainIQClient


class TestAsyncClientUnit:
    """Unit tests that do not require real API access."""

    @pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
    def test_async_client_requires_aiohttp(self):
        assert AsyncDomainIQClient is not None

    def test_async_client_import_error_without_aiohttp(self):
        if AIOHTTP_AVAILABLE:
            pytest.skip("aiohttp is available")

        with pytest.raises(DomainIQError, match="aiohttp is required"):
            AsyncDomainIQClient(api_key="test_key")


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
class TestConcurrentLookupCriticalCancel:
    """Regression for critical errors cancelling concurrent work."""

    async def test_critical_error_attaches_partial_results(self):
        from domainiq.async_client import _run_with_critical_cancel
        from domainiq.exceptions import (
            DomainIQAuthenticationError,
            DomainIQPartialResultsError,
        )

        async def ok() -> WhoisResult:
            await asyncio.sleep(0)
            return WhoisResult(domain="ok.com")

        async def fail() -> WhoisResult:
            await asyncio.sleep(0)
            raise DomainIQAuthenticationError("bad key")

        async def slow() -> WhoisResult:
            await asyncio.sleep(10)
            return WhoisResult(domain="slow.com")

        with pytest.raises(DomainIQPartialResultsError) as exc_info:
            await _run_with_critical_cancel([ok(), fail(), slow()], WhoisResult)

        err = exc_info.value
        assert isinstance(err.__cause__, DomainIQAuthenticationError)
        partial = err.partial_results
        assert isinstance(partial, list)
        assert len(partial) == 3
        assert partial[2] is None
        assert any(isinstance(result, WhoisResult) for result in partial)

    async def test_all_success_returns_ordered_results(self):
        from domainiq.async_client import _run_with_critical_cancel

        async def make(name: str) -> WhoisResult:
            await asyncio.sleep(0)
            return WhoisResult(domain=name)

        results = await _run_with_critical_cancel(
            [make("a"), make("b"), make("c")],
            WhoisResult,
        )
        assert [result.domain for result in results] == ["a", "b", "c"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
