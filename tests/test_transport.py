"""Unit tests for retry logic, rate-limit, timeout, auth, and error paths.

These tests use MockSyncTransport / MockAsyncTransport from conftest.py to
exercise DomainIQClient and AsyncDomainIQClient without real HTTP calls.
"""

from __future__ import annotations

import argparse
import importlib.util
from typing import TYPE_CHECKING

import pytest

from domainiq import (
    DomainIQAPIError,
    DomainIQAuthenticationError,
    DomainIQClient,
    DomainIQRateLimitError,
    DomainIQTimeoutError,
)
from domainiq.cli._dispatch import _dispatch_dns, _dispatch_whois

from .conftest import (
    MockAsyncTransport,
    MockSyncTransport,
    make_async_response,
    make_sync_response,
)

if TYPE_CHECKING:
    from domainiq.async_client import AsyncDomainIQClient

AIOHTTP_AVAILABLE = importlib.util.find_spec("aiohttp") is not None

if AIOHTTP_AVAILABLE:
    pass


# ---------------------------------------------------------------------------
# Sync: Retry logic
# ---------------------------------------------------------------------------


class TestRetryLogic:
    """DomainIQClient retries on 500/502/503/504 up to max_retries times."""

    def test_exhausted_retries_on_500_raises_api_error(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        for _ in range(4):  # max_retries=3 → 4 total attempts
            mock_transport.enqueue(make_sync_response(500, '{"error": "server error"}'))

        with pytest.raises(DomainIQAPIError) as exc_info:
            mock_client.whois_lookup(domain="example.com")

        assert exc_info.value.status_code == 500
        assert len(mock_transport.calls) == 4

    def test_recovers_after_transient_500(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        mock_transport.enqueue(make_sync_response(500, '{"error": "server error"}'))
        mock_transport.enqueue(make_sync_response(200, '{"domain": "example.com"}'))

        result = mock_client.whois_lookup(domain="example.com")

        assert result is not None
        assert len(mock_transport.calls) == 2

    def test_retries_on_502(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        mock_transport.enqueue(make_sync_response(502, "Bad Gateway"))
        mock_transport.enqueue(make_sync_response(200, '{"domain": "example.com"}'))

        mock_client.whois_lookup(domain="example.com")

        assert len(mock_transport.calls) == 2

    def test_retries_on_503(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        mock_transport.enqueue(make_sync_response(503, "Service Unavailable"))
        mock_transport.enqueue(make_sync_response(200, '{"domain": "example.com"}'))

        mock_client.whois_lookup(domain="example.com")

        assert len(mock_transport.calls) == 2

    def test_retries_on_504(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        mock_transport.enqueue(make_sync_response(504, "Gateway Timeout"))
        mock_transport.enqueue(make_sync_response(200, '{"domain": "example.com"}'))

        mock_client.whois_lookup(domain="example.com")

        assert len(mock_transport.calls) == 2

    def test_no_retry_on_404(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        mock_transport.enqueue(make_sync_response(404, '{"error": "not found"}'))

        with pytest.raises(DomainIQAPIError) as exc_info:
            mock_client.whois_lookup(domain="example.com")

        assert exc_info.value.status_code == 404
        assert len(mock_transport.calls) == 1  # no retries


# ---------------------------------------------------------------------------
# Sync: Rate limiting (429)
# ---------------------------------------------------------------------------


class TestRateLimitHandling:
    """DomainIQClient handles 429 with Retry-After header and retries."""

    def test_exhausted_429_raises_rate_limit_error_with_retry_after(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        for _ in range(4):
            mock_transport.enqueue(
                make_sync_response(429, "{}", headers={"Retry-After": "5"})
            )

        with pytest.raises(DomainIQRateLimitError) as exc_info:
            mock_client.whois_lookup(domain="example.com")

        assert exc_info.value.retry_after == 5

    def test_429_then_200_succeeds(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        mock_transport.enqueue(
            make_sync_response(429, "{}", headers={"Retry-After": "1"})
        )
        mock_transport.enqueue(make_sync_response(200, '{"domain": "example.com"}'))

        result = mock_client.whois_lookup(domain="example.com")

        assert result is not None
        assert len(mock_transport.calls) == 2

    def test_429_without_retry_after_uses_exponential_backoff(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        mock_transport.enqueue(make_sync_response(429, "{}"))  # no Retry-After header
        mock_transport.enqueue(make_sync_response(200, '{"domain": "example.com"}'))

        result = mock_client.whois_lookup(domain="example.com")

        assert result is not None

    def test_exhausted_429_without_retry_after_raises(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        for _ in range(4):
            mock_transport.enqueue(make_sync_response(429, "{}"))

        with pytest.raises(DomainIQRateLimitError) as exc_info:
            mock_client.whois_lookup(domain="example.com")

        assert exc_info.value.retry_after is None


# ---------------------------------------------------------------------------
# Sync: Timeout handling
# ---------------------------------------------------------------------------


class TestTimeoutHandling:
    """DomainIQClient converts TimeoutError to DomainIQTimeoutError."""

    def test_exhausted_timeouts_raise_timeout_error(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        for _ in range(4):
            mock_transport.enqueue(TimeoutError("connection timed out"))

        with pytest.raises(DomainIQTimeoutError):
            mock_client.whois_lookup(domain="example.com")

        assert len(mock_transport.calls) == 4

    def test_timeout_then_success_recovers(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        mock_transport.enqueue(TimeoutError("connection timed out"))
        mock_transport.enqueue(make_sync_response(200, '{"domain": "example.com"}'))

        result = mock_client.whois_lookup(domain="example.com")

        assert result is not None
        assert len(mock_transport.calls) == 2


# ---------------------------------------------------------------------------
# Sync: Authentication errors (401)
# ---------------------------------------------------------------------------


class TestAuthErrors:
    """DomainIQClient raises DomainIQAuthenticationError immediately on 401."""

    def test_401_raises_auth_error_without_retrying(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        mock_transport.enqueue(make_sync_response(401, '{"error": "invalid key"}'))

        with pytest.raises(DomainIQAuthenticationError):
            mock_client.whois_lookup(domain="example.com")

        assert len(mock_transport.calls) == 1  # no retries on auth failure


# ---------------------------------------------------------------------------
# Sync: Network errors (OSError)
# ---------------------------------------------------------------------------


class TestNetworkErrors:
    """DomainIQClient retries on OSError (connection failure)."""

    def test_exhausted_connection_errors_raise_api_error(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        for _ in range(4):
            mock_transport.enqueue(OSError("Connection refused"))

        with pytest.raises(DomainIQAPIError):
            mock_client.whois_lookup(domain="example.com")

        assert len(mock_transport.calls) == 4

    def test_connection_error_then_success_recovers(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        mock_transport.enqueue(OSError("Connection refused"))
        mock_transport.enqueue(make_sync_response(200, '{"domain": "example.com"}'))

        result = mock_client.whois_lookup(domain="example.com")

        assert result is not None


# ---------------------------------------------------------------------------
# Async: Retry and rate-limit (mirrors sync tests)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not installed")
class TestAsyncRetryLogic:
    """AsyncDomainIQClient retries on 5xx up to max_retries times."""

    @pytest.mark.asyncio
    async def test_exhausted_retries_on_500_raises_api_error(
        self,
        mock_async_transport: MockAsyncTransport,
        mock_async_client: AsyncDomainIQClient,
    ) -> None:
        for _ in range(4):
            mock_async_transport.enqueue(make_async_response(500, '{"error": "err"}'))

        with pytest.raises(DomainIQAPIError) as exc_info:
            await mock_async_client.whois_lookup(domain="example.com")

        assert exc_info.value.status_code == 500
        assert len(mock_async_transport.calls) == 4

    @pytest.mark.asyncio
    async def test_recovers_after_transient_500(
        self,
        mock_async_transport: MockAsyncTransport,
        mock_async_client: AsyncDomainIQClient,
    ) -> None:
        mock_async_transport.enqueue(make_async_response(500, '{"error": "err"}'))
        mock_async_transport.enqueue(
            make_async_response(200, '{"domain": "example.com"}')
        )

        result = await mock_async_client.whois_lookup(domain="example.com")

        assert result is not None
        assert len(mock_async_transport.calls) == 2


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not installed")
class TestAsyncRateLimitHandling:
    """AsyncDomainIQClient handles 429 with Retry-After."""

    @pytest.mark.asyncio
    async def test_exhausted_429_raises_rate_limit_error(
        self,
        mock_async_transport: MockAsyncTransport,
        mock_async_client: AsyncDomainIQClient,
    ) -> None:
        for _ in range(4):
            mock_async_transport.enqueue(
                make_async_response(429, "{}", headers={"Retry-After": "3"})
            )

        with pytest.raises(DomainIQRateLimitError) as exc_info:
            await mock_async_client.whois_lookup(domain="example.com")

        assert exc_info.value.retry_after == 3

    @pytest.mark.asyncio
    async def test_401_no_retries_async(
        self,
        mock_async_transport: MockAsyncTransport,
        mock_async_client: AsyncDomainIQClient,
    ) -> None:
        mock_async_transport.enqueue(make_async_response(401, '{"error": "bad key"}'))

        with pytest.raises(DomainIQAuthenticationError):
            await mock_async_client.whois_lookup(domain="example.com")

        assert len(mock_async_transport.calls) == 1

    @pytest.mark.asyncio
    async def test_timeout_then_success_async(
        self,
        mock_async_transport: MockAsyncTransport,
        mock_async_client: AsyncDomainIQClient,
    ) -> None:
        mock_async_transport.enqueue(TimeoutError("async timeout"))
        mock_async_transport.enqueue(
            make_async_response(200, '{"domain": "example.com"}')
        )

        result = await mock_async_client.whois_lookup(domain="example.com")

        assert result is not None


# ---------------------------------------------------------------------------
# CLI dispatch
# ---------------------------------------------------------------------------


class TestCLIDispatch:
    """_dispatch_* functions route commands correctly."""

    def test_dispatch_whois_executes_when_arg_set(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        mock_transport.enqueue(make_sync_response(200, '{"domain": "example.com"}'))

        args = argparse.Namespace(
            whois_lookup="example.com",
            full=False,
            current_only=False,
        )
        executed, errored = _dispatch_whois(mock_client, args)

        assert executed is True
        assert errored is False

    def test_dispatch_whois_skips_when_arg_not_set(
        self, mock_client: DomainIQClient
    ) -> None:
        args = argparse.Namespace(whois_lookup=None)
        executed, errored = _dispatch_whois(mock_client, args)

        assert executed is False
        assert errored is False

    def test_dispatch_dns_executes_when_arg_set(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        mock_transport.enqueue(
            make_sync_response(200, '{"domain": "example.com", "records": []}')
        )

        args = argparse.Namespace(dns_lookup="example.com", types=None)
        executed, errored = _dispatch_dns(mock_client, args)

        assert executed is True
        assert errored is False

    def test_dispatch_dns_skips_when_arg_not_set(
        self, mock_client: DomainIQClient
    ) -> None:
        args = argparse.Namespace(dns_lookup=None)
        executed, errored = _dispatch_dns(mock_client, args)

        assert executed is False
        assert errored is False

    def test_dispatch_whois_returns_error_on_api_failure(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        # 401 exhausts immediately (no retries) → DomainIQAuthenticationError
        mock_transport.enqueue(make_sync_response(401, '{"error": "bad key"}'))

        args = argparse.Namespace(
            whois_lookup="example.com",
            full=False,
            current_only=False,
        )
        executed, errored = _dispatch_whois(mock_client, args)

        assert executed is True
        assert errored is True
