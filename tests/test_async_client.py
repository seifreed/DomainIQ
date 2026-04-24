"""Unit and regression tests for the async DomainIQ client."""

from __future__ import annotations

import asyncio
import importlib.util
from typing import TYPE_CHECKING

import pytest

from domainiq import DomainIQError
from domainiq.async_client import _run_with_critical_cancel
from domainiq.exceptions import (
    DomainIQAPIError,
    DomainIQAuthenticationError,
    DomainIQPartialResultsError,
    DomainIQRateLimitError,
)
from domainiq.models import DNSResult, WhoisResult

if TYPE_CHECKING:
    from domainiq.async_client import AsyncDomainIQClient

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
        async def ok() -> WhoisResult:
            await asyncio.sleep(0)
            return WhoisResult(domain="ok.com")

        async def fail() -> WhoisResult:
            await asyncio.sleep(0)
            msg = "bad key"
            raise DomainIQAuthenticationError(msg)

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
        async def make(name: str) -> WhoisResult:
            await asyncio.sleep(0)
            return WhoisResult(domain=name)

        results = await _run_with_critical_cancel(
            [make("a"), make("b"), make("c")],
            WhoisResult,
        )
        assert [result.domain for result in results] == ["a", "b", "c"]


@pytest.mark.asyncio
class TestAsyncClientConcurrentLookup:
    """Unit tests for AsyncDomainIQClient concurrent lookup orchestration."""

    async def test_noncritical_lookup_failures_become_none_and_warn(
        self,
        mock_async_client: AsyncDomainIQClient,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        async def lookup(target: str) -> WhoisResult:
            if target == "bad":
                msg = "temporary API failure"
                raise DomainIQAPIError(msg)
            return WhoisResult(domain=target)

        with caplog.at_level("WARNING", logger="domainiq.async_client"):
            results = await mock_async_client._concurrent_lookup(
                lookup,
                ["ok", "bad", "later"],
                max_concurrent=2,
                label="WHOIS",
                result_type=WhoisResult,
            )

        assert [result.domain if result else None for result in results] == [
            "ok",
            None,
            "later",
        ]
        assert "WHOIS lookup failed for bad" in caplog.text

    async def test_concurrent_lookup_respects_max_concurrent(
        self, mock_async_client: AsyncDomainIQClient
    ) -> None:
        active = 0
        max_seen = 0

        async def lookup(target: str) -> WhoisResult:
            nonlocal active, max_seen
            active += 1
            max_seen = max(max_seen, active)
            await asyncio.sleep(0)
            active -= 1
            return WhoisResult(domain=target)

        results = await mock_async_client._concurrent_lookup(
            lookup,
            ["a.com", "b.com", "c.com", "d.com"],
            max_concurrent=2,
            label="WHOIS",
            result_type=WhoisResult,
        )

        assert max_seen <= 2
        assert [result.domain for result in results if result is not None] == [
            "a.com",
            "b.com",
            "c.com",
            "d.com",
        ]

    async def test_critical_lookup_error_raises_partial_results(
        self, mock_async_client: AsyncDomainIQClient
    ) -> None:
        async def lookup(target: str) -> WhoisResult:
            if target == "limited":
                msg = "rate limited"
                raise DomainIQRateLimitError(msg)
            await asyncio.sleep(0)
            return WhoisResult(domain=target)

        with pytest.raises(DomainIQPartialResultsError) as exc_info:
            await mock_async_client._concurrent_lookup(
                lookup,
                ["ok", "limited", "late"],
                max_concurrent=3,
                label="WHOIS",
                result_type=WhoisResult,
            )

        assert isinstance(exc_info.value.__cause__, DomainIQRateLimitError)
        assert len(exc_info.value.partial_results) == 3

    async def test_concurrent_whois_routes_domains_and_ips(
        self,
        mock_async_client: AsyncDomainIQClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        calls: list[dict[str, str | None]] = []

        async def whois_lookup(
            domain: str | None = None, ip: str | None = None, **_: object
        ) -> WhoisResult:
            calls.append({"domain": domain, "ip": ip})
            return WhoisResult(domain=domain, ip=ip)

        monkeypatch.setattr(mock_async_client, "whois_lookup", whois_lookup)

        results = await mock_async_client.concurrent_whois_lookup(
            ["example.com", "8.8.8.8"], max_concurrent=1
        )

        assert calls == [
            {"domain": "example.com", "ip": None},
            {"domain": None, "ip": "8.8.8.8"},
        ]
        assert [result.domain or result.ip for result in results if result] == [
            "example.com",
            "8.8.8.8",
        ]

    async def test_concurrent_dns_forwards_record_types(
        self,
        mock_async_client: AsyncDomainIQClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        calls: list[tuple[str, list[str] | None]] = []

        async def dns_lookup(
            domain: str, record_types: list[str] | None = None
        ) -> DNSResult:
            calls.append((domain, record_types))
            return DNSResult(domain=domain, records=[])

        monkeypatch.setattr(mock_async_client, "dns_lookup", dns_lookup)

        results = await mock_async_client.concurrent_dns_lookup(
            ["example.com", "example.net"], record_types=["A", "MX"], max_concurrent=1
        )

        assert calls == [
            ("example.com", ["A", "MX"]),
            ("example.net", ["A", "MX"]),
        ]
        assert [result.domain for result in results if result] == [
            "example.com",
            "example.net",
        ]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
