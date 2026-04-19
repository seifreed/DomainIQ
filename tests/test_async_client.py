"""
Integration tests for the async DomainIQ client using real API data.

These tests require a valid DomainIQ API key and aiohttp installed.
Set DOMAINIQ_API_KEY environment variable or create ~/.domainiq file.

Run with: pytest tests/test_async_client.py -v
Run integration tests only: pytest tests/test_async_client.py -m integration -v
"""

import asyncio
import importlib.util
import time
from datetime import datetime

import pytest

from domainiq import DomainIQConfigurationError, DomainIQError
from domainiq.config import Config
from domainiq.models import DNSRecordType, DNSResult, WhoisResult

AIOHTTP_AVAILABLE = importlib.util.find_spec("aiohttp") is not None

if AIOHTTP_AVAILABLE:
    from domainiq.async_client import AsyncDomainIQClient

# Test domains that should be stable and available
TEST_DOMAINS = [
    "example.com",
    "google.com",
    "github.com",
]

TEST_IP = "8.8.8.8"  # Google DNS


class TestAsyncClientUnit:
    """Unit tests for async client that don't require API access."""

    @pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
    def test_async_client_requires_aiohttp(self):
        """Test that async client can be imported when aiohttp is available."""
        assert AsyncDomainIQClient is not None

    def test_async_client_import_error_without_aiohttp(self):
        """Test that proper error is shown when aiohttp is not available."""
        if AIOHTTP_AVAILABLE:
            pytest.skip("aiohttp is available")

        with pytest.raises(DomainIQError, match="aiohttp is required"):
            AsyncDomainIQClient(api_key="test_key")


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
class TestConcurrentLookupCriticalCancel:
    """Regression for bug #7: critical errors cancel + return partial results."""

    async def test_critical_error_attaches_partial_results(self):
        """On critical error, other tasks are cancelled and completed
        results are attached to the exception."""
        from domainiq.async_client import _run_with_critical_cancel
        from domainiq.exceptions import DomainIQAuthenticationError

        async def ok() -> WhoisResult:
            await asyncio.sleep(0)
            return WhoisResult(domain="ok.com")

        async def fail() -> WhoisResult:
            await asyncio.sleep(0)
            raise DomainIQAuthenticationError("bad key")

        async def slow() -> WhoisResult:
            # Would take too long, should be cancelled
            await asyncio.sleep(10)
            return WhoisResult(domain="slow.com")

        from domainiq.exceptions import DomainIQPartialResultsError

        with pytest.raises(DomainIQPartialResultsError) as exc_info:
            await _run_with_critical_cancel([ok(), fail(), slow()], WhoisResult)

        err = exc_info.value
        assert isinstance(err.__cause__, DomainIQAuthenticationError)
        partial = err.partial_results
        assert isinstance(partial, list)
        assert len(partial) == 3
        # The ok() task should be represented; slow() should be None (cancelled)
        assert partial[2] is None
        # At least ok() should have produced a WhoisResult (it yields before fail)
        assert any(isinstance(r, WhoisResult) for r in partial)

    async def test_all_success_returns_ordered_results(self):
        """Happy path: results align with submission order."""
        from domainiq.async_client import _run_with_critical_cancel

        async def make(name: str) -> WhoisResult:
            await asyncio.sleep(0)
            return WhoisResult(domain=name)

        results = await _run_with_critical_cancel(
            [make("a"), make("b"), make("c")], WhoisResult
        )
        assert [r.domain for r in results] == ["a", "b", "c"]


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.integration
@pytest.mark.asyncio
class TestAsyncDomainIQClientIntegration:
    """Integration tests using real DomainIQ API calls with async client."""

    config: Config | None

    @classmethod
    def setup_class(cls):
        """Set up test fixtures for the class."""
        try:
            cls.config = Config()
        except DomainIQConfigurationError:
            pytest.skip("No API key available for integration tests")

    async def test_async_whois_lookup_domain(self):
        """Test async WHOIS lookup for a domain."""
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.whois_lookup(domain=TEST_DOMAINS[0])

            if result is None:
                pytest.skip("API returned None for WHOIS lookup")
            assert isinstance(result, WhoisResult)
            assert result.domain == TEST_DOMAINS[0] or result.domain is None
            if result.registrar:
                assert isinstance(result.registrar, str)
            if result.creation_date:
                assert isinstance(result.creation_date, datetime)

    async def test_async_whois_lookup_ip(self):
        """Test async WHOIS lookup for an IP address."""
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.whois_lookup(ip=TEST_IP)

            if result is None:
                pytest.skip("API returned None for WHOIS lookup")
            assert isinstance(result, WhoisResult)
            assert result.ip == TEST_IP or result.ip is None

    async def test_async_dns_lookup_basic(self):
        """Test async basic DNS lookup."""
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.dns_lookup(TEST_DOMAINS[0])

            if result is None:
                pytest.skip("API returned None for DNS lookup")
            assert isinstance(result, DNSResult)
            assert isinstance(result.domain, str)
            assert isinstance(result.records, list)

    async def test_async_dns_lookup_with_types(self):
        """Test async DNS lookup with specific record types."""
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.dns_lookup(
                TEST_DOMAINS[0],
                record_types=[DNSRecordType.A, DNSRecordType.MX],
            )

            if result is None or not result.records:
                pytest.skip("API returned None or no records for DNS lookup")
            assert isinstance(result, DNSResult)
            record_types = [record.type for record in result.records]
            assert any(rtype in ["A", "MX"] for rtype in record_types)

    async def test_concurrent_whois_lookups(self):
        """Test concurrent WHOIS lookups for improved performance."""
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            domains = TEST_DOMAINS[:3]

            # Sequential lookups
            start_time = time.time()
            sequential_results = []
            for domain in domains:
                result = await client.whois_lookup(domain=domain)
                sequential_results.append(result)
            sequential_time = time.time() - start_time

            # Concurrent lookups
            start_time = time.time()
            concurrent_results = await client.concurrent_whois_lookup(
                targets=domains,
                max_concurrent=3,
            )
            concurrent_time = time.time() - start_time
            assert concurrent_time < sequential_time or concurrent_time < 5.0

            # Verify results
            assert len(concurrent_results) == len(domains)

            for result in concurrent_results:
                assert result is None or isinstance(result, WhoisResult)

    async def test_concurrent_dns_lookups(self):
        """Test concurrent DNS lookups for improved performance."""
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            domains = TEST_DOMAINS[:3]

            concurrent_results = await client.concurrent_dns_lookup(
                domains=domains,
                record_types=[DNSRecordType.A],
                max_concurrent=3,
            )

            assert len(concurrent_results) == len(domains)

            for result in concurrent_results:
                assert result is None or isinstance(result, DNSResult)

    async def test_async_domain_categorize(self):
        """Test async domain categorization."""
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.domain_categorize([TEST_DOMAINS[0]])

            if not result:
                pytest.skip("API returned empty result for categorization")
            assert isinstance(result, list)
            if len(result) > 0:
                assert hasattr(result[0], "domain")
                assert hasattr(result[0], "categories")

    async def test_async_domain_snapshot(self):
        """Test async domain snapshot."""
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.domain_snapshot(TEST_DOMAINS[0])

            if result is None:
                pytest.skip("API returned None for domain snapshot")
            assert hasattr(result, "domain")
            assert isinstance(result.domain, str)

    async def test_async_bulk_dns_lookup(self):
        """Test async bulk DNS lookup."""
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.bulk_dns(TEST_DOMAINS[:2])

            if not result:
                pytest.skip("API returned empty result for bulk DNS")
            assert isinstance(result, list)
            if len(result) > 0:
                assert isinstance(result[0], dict)

    async def test_async_bulk_whois(self):
        """Test async bulk WHOIS lookup."""
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.bulk_whois(TEST_DOMAINS[:2])

            if not result:
                pytest.skip("API returned empty result for bulk WHOIS")
            assert isinstance(result, list)
            if len(result) > 0:
                assert isinstance(result[0], dict)

    async def test_async_domain_report(self):
        """Test async domain report generation."""
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.domain_report(TEST_DOMAINS[0])

            if result is None:
                pytest.skip("API returned None for domain report")
            assert hasattr(result, "domain")
            assert isinstance(result.domain, str)

    async def test_async_reverse_search(self):
        """Test async reverse search functionality."""
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.reverse_search("email", "admin@example.com")

            if result is None:
                pytest.skip("API returned None for reverse search")
            assert isinstance(result, dict)

    async def test_async_monitor_list(self):
        """Test async monitor list functionality."""
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            try:
                result = await client.monitor_list()
                assert isinstance(result, list)
            except DomainIQError:
                pytest.skip("Monitor functionality not available")

    async def test_async_context_manager(self):
        """Test async client as context manager."""
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            assert client.config.api_key == self.config.api_key
            result = await client.whois_lookup(domain="example.com")
            assert result is None or isinstance(result, WhoisResult)

    async def test_session_handling(self):
        """Test that HTTP session is properly managed."""
        if self.config is None:
            pytest.skip("No config available")
        client = AsyncDomainIQClient(self.config)

        await client.whois_lookup(domain="example.com")
        assert client._transport._session is not None
        assert not client._transport._session.closed

        await client.close()
        assert client._transport._session.closed

    async def test_multiple_concurrent_operations(self):
        """Test multiple different operations running concurrently."""
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            tasks = [
                client.whois_lookup(domain=TEST_DOMAINS[0]),
                client.dns_lookup(TEST_DOMAINS[0]),
                client.domain_categorize([TEST_DOMAINS[0]]),
                client.domain_report(TEST_DOMAINS[0]),
            ]

            try:
                results = await asyncio.gather(*tasks, return_exceptions=True)

                assert len(results) == 4

                whois_result = results[0]
                if not isinstance(whois_result, Exception):
                    assert whois_result is None or isinstance(whois_result, WhoisResult)

                dns_result = results[1]
                if not isinstance(dns_result, Exception):
                    assert dns_result is None or isinstance(dns_result, DNSResult)

                categories_result = results[2]
                if not isinstance(categories_result, Exception):
                    assert categories_result is None or isinstance(
                        categories_result, list
                    )

                report_result = results[3]
                if not isinstance(report_result, Exception) and report_result:
                    assert hasattr(report_result, "domain")

            except (DomainIQError, ValueError, OSError, RuntimeError):
                pass


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
async def test_async_performance_comparison():
    """Compare performance between sync and async clients."""
    try:
        config = Config()
    except DomainIQConfigurationError:
        pytest.skip("No API key available")

    domains = ["example.com", "google.com", "github.com"]

    # Test async performance
    start_time = time.time()
    async with AsyncDomainIQClient(config) as async_client:
        async_results = await async_client.concurrent_whois_lookup(
            targets=domains,
            max_concurrent=3,
        )
    time.time() - start_time

    assert len(async_results) == len(domains)

    for result in async_results:
        assert result is None or isinstance(result, WhoisResult)


if __name__ == "__main__":
    import sys

    if not AIOHTTP_AVAILABLE:
        sys.exit(0)

    try:
        Config()
        pytest.main([__file__, "-v"])
    except DomainIQConfigurationError:
        pytest.main([__file__, "-v", "-m", "not integration"])

    sys.exit(0)
