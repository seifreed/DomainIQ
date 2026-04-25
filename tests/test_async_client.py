"""Unit and regression tests for the async DomainIQ client."""

from __future__ import annotations

import asyncio
import importlib.util
import warnings

import pytest

import domainiq.async_client as async_client_module
from domainiq import DomainIQError
from domainiq.async_client import AsyncDomainIQClient, _run_with_critical_cancel
from domainiq.config import Config
from domainiq.exceptions import (
    DomainIQAPIError,
    DomainIQAuthenticationError,
    DomainIQPartialResultsError,
    DomainIQRateLimitError,
    DomainIQValidationError,
)
from domainiq.models import DNSResult, WhoisResult

AIOHTTP_AVAILABLE = importlib.util.find_spec("aiohttp") is not None

if AIOHTTP_AVAILABLE:
    from domainiq.async_client import AsyncDomainIQClient as AiohttpAsyncDomainIQClient


class LifecycleAsyncTransport:
    def __init__(self, is_open: bool = False) -> None:
        self.is_open = is_open
        self.closed = False

    async def get(
        self, _url: str, _params: dict[str, str], _request_timeout: float
    ) -> object:
        msg = "Lifecycle transport should not issue requests"
        raise AssertionError(msg)

    async def close(self) -> None:
        self.closed = True
        self.is_open = False


class TestAsyncClientUnit:
    """Unit tests that do not require real API access."""

    @pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
    def test_async_client_requires_aiohttp(self):
        assert AiohttpAsyncDomainIQClient is not None

    def test_async_client_import_error_without_aiohttp(self):
        if AIOHTTP_AVAILABLE:
            pytest.skip("aiohttp is available")

        with pytest.raises(DomainIQError, match="aiohttp is required"):
            AsyncDomainIQClient(api_key="test_key")

    def test_make_default_async_transport_forwards_config(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeAiohttpTransport:
            def __init__(
                self,
                timeout: float,
                connector_limit: int,
                connector_limit_per_host: int,
            ) -> None:
                self.timeout = timeout
                self.connector_limit = connector_limit
                self.connector_limit_per_host = connector_limit_per_host

        monkeypatch.setattr(
            async_client_module,
            "AiohttpTransport",
            FakeAiohttpTransport,
        )
        config = Config(
            api_key="key",
            timeout=7,
            connector_limit=11,
            connector_limit_per_host=3,
        )

        transport = async_client_module._make_default_async_transport(config)

        assert transport.timeout == 7
        assert transport.connector_limit == 11
        assert transport.connector_limit_per_host == 3

    def test_make_default_async_transport_maps_import_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class MissingAiohttpTransport:
            def __init__(self, *_args: object, **_kwargs: object) -> None:
                msg = "missing aiohttp"
                raise ImportError(msg)

        monkeypatch.setattr(
            async_client_module,
            "AiohttpTransport",
            MissingAiohttpTransport,
        )
        config = Config(api_key="key")

        with pytest.raises(DomainIQError, match="aiohttp is required"):
            async_client_module._make_default_async_transport(config)

    @pytest.mark.asyncio
    async def test_close_and_async_context_close_transport(self) -> None:
        first_transport = LifecycleAsyncTransport(is_open=True)
        client = AsyncDomainIQClient(api_key="key", transport=first_transport)

        await client.close()

        assert first_transport.closed is True
        assert first_transport.is_open is False

        second_transport = LifecycleAsyncTransport(is_open=True)
        async with AsyncDomainIQClient(
            api_key="key", transport=second_transport
        ) as context_client:
            assert context_client._transport is second_transport

        assert second_transport.closed is True
        assert second_transport.is_open is False

    def test_del_noops_without_transport(self) -> None:
        client = AsyncDomainIQClient.__new__(AsyncDomainIQClient)

        client.__del__()

    def test_del_noops_when_transport_is_closed(self) -> None:
        client = AsyncDomainIQClient.__new__(AsyncDomainIQClient)
        client._transport = LifecycleAsyncTransport(is_open=False)

        with warnings.catch_warnings(record=True) as caught:
            client.__del__()

        assert caught == []

    def test_del_warns_when_transport_is_still_open(self) -> None:
        client = AsyncDomainIQClient.__new__(AsyncDomainIQClient)
        transport = LifecycleAsyncTransport(is_open=True)
        client._transport = transport

        with pytest.warns(ResourceWarning, match="Unclosed AsyncDomainIQClient"):
            client.__del__()

        transport.is_open = False


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

    async def test_concurrent_lookup_accepts_empty_targets(
        self,
        mock_async_client: AsyncDomainIQClient,
    ) -> None:
        async def lookup(_target: str) -> WhoisResult:
            msg = "empty target list should not call lookup"
            raise AssertionError(msg)

        results = await mock_async_client._concurrent_lookup(
            lookup,
            [],
            max_concurrent=2,
            label="WHOIS",
            result_type=WhoisResult,
        )

        assert results == []

    @pytest.mark.parametrize("max_concurrent", [0, -1, True, 1.5, "2"])
    async def test_concurrent_lookup_rejects_invalid_max_concurrent(
        self,
        mock_async_client: AsyncDomainIQClient,
        max_concurrent: object,
    ) -> None:
        async def lookup(target: str) -> WhoisResult:
            return WhoisResult(domain=target)

        with pytest.raises(DomainIQValidationError) as exc_info:
            await asyncio.wait_for(
                mock_async_client._concurrent_lookup(
                    lookup,
                    ["example.com"],
                    max_concurrent,
                    label="WHOIS",
                    result_type=WhoisResult,
                ),
                timeout=0.1,
            )

        assert exc_info.value.param_name == "max_concurrent"

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
