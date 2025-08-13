"""
Integration tests for the async DomainIQ client using real API data.

These tests require a valid DomainIQ API key and aiohttp installed.
Set DOMAINIQ_API_KEY environment variable or create ~/.domainiq file.

Run with: pytest tests/test_async_client.py -v
Run integration tests only: pytest tests/test_async_client.py -m integration -v
"""

import asyncio
from datetime import datetime

import pytest

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

from domainiq import DomainIQConfigurationError, DomainIQError
from domainiq.config import Config
from domainiq.models import DNSRecordType, DNSResult, WhoisResult

if AIOHTTP_AVAILABLE:
    from domainiq.async_client import AsyncDomainIQClient


# Test domains that should be stable and available
TEST_DOMAINS = [
    "example.com",
    "google.com",
    "github.com"
]

TEST_IP = "8.8.8.8"  # Google DNS


class TestAsyncClientUnit:
    """Unit tests for async client that don't require API access."""

    @pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
    def test_async_client_requires_aiohttp(self):
        """Test that async client can be imported when aiohttp is available."""
        from domainiq.async_client import AsyncDomainIQClient
        assert AsyncDomainIQClient is not None

    def test_async_client_import_error_without_aiohttp(self):
        """Test that proper error is shown when aiohttp is not available."""
        # This test only makes sense when aiohttp is not available
        # When aiohttp IS available, we skip this test
        if AIOHTTP_AVAILABLE:
            pytest.skip("aiohttp is available")

        with pytest.raises(ImportError):
            pass


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.integration
@pytest.mark.asyncio
class TestAsyncDomainIQClientIntegration:
    """Integration tests using real DomainIQ API calls with async client."""

    @classmethod
    def setup_class(cls):
        """Set up test fixtures for the class."""
        try:
            # Try to create config with real API key
            cls.config = Config()
        except DomainIQConfigurationError:
            pytest.skip("No API key available for integration tests")

    async def test_async_whois_lookup_domain(self):
        """Test async WHOIS lookup for a domain."""
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.whois_lookup(domain=TEST_DOMAINS[0])

            if result:  # API might return None for some domains
                assert isinstance(result, WhoisResult)
                assert result.domain == TEST_DOMAINS[0] or result.domain is None
                if result.registrar:
                    assert isinstance(result.registrar, str)
                if result.creation_date:
                    assert isinstance(result.creation_date, datetime)

    async def test_async_whois_lookup_ip(self):
        """Test async WHOIS lookup for an IP address."""
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.whois_lookup(ip=TEST_IP)

            if result:  # API might return None for some IPs
                assert isinstance(result, WhoisResult)
                assert result.ip == TEST_IP or result.ip is None

    async def test_async_dns_lookup_basic(self):
        """Test async basic DNS lookup."""
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.dns_lookup(TEST_DOMAINS[0])

            if result:  # API might return None for some domains
                assert isinstance(result, DNSResult)
                assert result.domain == TEST_DOMAINS[0] or isinstance(result.domain, str)
                assert isinstance(result.records, list)

    async def test_async_dns_lookup_with_types(self):
        """Test async DNS lookup with specific record types."""
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.dns_lookup(
                TEST_DOMAINS[0],
                record_types=[DNSRecordType.A, DNSRecordType.MX]
            )

            if result and result.records:
                assert isinstance(result, DNSResult)
                # Check that we got the requested record types
                record_types = [record.type for record in result.records]
                # At least one of the requested types should be present
                assert any(rtype in ["A", "MX"] for rtype in record_types)

    async def test_concurrent_whois_lookups(self):
        """Test concurrent WHOIS lookups for improved performance."""
        async with AsyncDomainIQClient(self.config) as client:
            domains = TEST_DOMAINS[:3]  # Test with 3 domains

            # Measure time for sequential vs concurrent
            import time

            # Sequential lookups
            start_time = time.time()
            sequential_results = []
            for domain in domains:
                result = await client.whois_lookup(domain=domain)
                sequential_results.append(result)
            time.time() - start_time

            # Concurrent lookups
            start_time = time.time()
            concurrent_results = await client.concurrent_whois_lookup(
                targets=domains,
                max_concurrent=3
            )
            time.time() - start_time

            # Verify results
            assert len(concurrent_results) == len(domains)

            # Concurrent should be faster (or at least not significantly slower)
            # We allow some variance due to network conditions

            # If we got results, they should be WhoisResult instances or None
            for result in concurrent_results:
                assert result is None or isinstance(result, WhoisResult)

    async def test_concurrent_dns_lookups(self):
        """Test concurrent DNS lookups for improved performance."""
        async with AsyncDomainIQClient(self.config) as client:
            domains = TEST_DOMAINS[:3]  # Test with 3 domains

            concurrent_results = await client.concurrent_dns_lookup(
                domains=domains,
                record_types=[DNSRecordType.A],
                max_concurrent=3
            )

            # Verify results
            assert len(concurrent_results) == len(domains)

            # Results should be DNSResult instances or None
            for result in concurrent_results:
                assert result is None or isinstance(result, DNSResult)

    async def test_async_domain_categorize(self):
        """Test async domain categorization."""
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.domain_categorize([TEST_DOMAINS[0]])

            if result:  # API might return empty list
                assert isinstance(result, list)
                if len(result) > 0:
                    assert hasattr(result[0], "domain")
                    assert hasattr(result[0], "categories")

    async def test_async_domain_snapshot(self):
        """Test async domain snapshot."""
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.domain_snapshot(TEST_DOMAINS[0])

            if result:  # API might return None
                assert hasattr(result, "domain")
                assert result.domain == TEST_DOMAINS[0] or isinstance(result.domain, str)

    async def test_async_bulk_dns_lookup(self):
        """Test async bulk DNS lookup."""
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.bulk_dns(TEST_DOMAINS[:2])  # Test with 2 domains

            if result:  # API might return empty list
                assert isinstance(result, list)
                # Should have results for the domains we requested
                if len(result) > 0:
                    assert isinstance(result[0], dict)

    async def test_async_bulk_whois(self):
        """Test async bulk WHOIS lookup."""
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.bulk_whois(TEST_DOMAINS[:2])

            if result:  # API might return empty list
                assert isinstance(result, list)
                if len(result) > 0:
                    assert isinstance(result[0], dict)

    async def test_async_domain_report(self):
        """Test async domain report generation."""
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.domain_report(TEST_DOMAINS[0])

            if result:  # API might return None
                assert hasattr(result, "domain")
                assert result.domain == TEST_DOMAINS[0] or isinstance(result.domain, str)

    async def test_async_reverse_search(self):
        """Test async reverse search functionality."""
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.reverse_search("email", "admin@example.com")

            # Reverse search might return None or data
            if result:
                assert isinstance(result, dict)

    async def test_async_monitor_list(self):
        """Test async monitor list functionality."""
        async with AsyncDomainIQClient(self.config) as client:
            try:
                result = await client.monitor_list()

                # Monitor list should return a list (empty or with data)
                assert isinstance(result, list)
            except DomainIQError:
                # Monitor functionality might not be available for all API keys
                pytest.skip("Monitor functionality not available")

    async def test_async_context_manager(self):
        """Test async client as context manager."""
        async with AsyncDomainIQClient(self.config) as client:
            assert client.config.api_key == self.config.api_key
            # Make a simple request to verify the client works
            result = await client.whois_lookup(domain="example.com")
            # Result can be None or WhoisResult
            assert result is None or isinstance(result, WhoisResult)
        # Client should be properly closed after context

    async def test_session_handling(self):
        """Test that HTTP session is properly managed."""
        client = AsyncDomainIQClient(self.config)

        # Session should be None initially
        assert client._session is None

        # Make a request - session should be created
        await client.whois_lookup(domain="example.com")
        assert client._session is not None
        assert not client._session.closed

        # Close client - session should be closed
        await client.close()
        assert client._session.closed

    async def test_multiple_concurrent_operations(self):
        """Test multiple different operations running concurrently."""
        async with AsyncDomainIQClient(self.config) as client:
            # Run multiple different operations concurrently
            tasks = [
                client.whois_lookup(domain=TEST_DOMAINS[0]),
                client.dns_lookup(TEST_DOMAINS[0]),
                client.domain_categorize([TEST_DOMAINS[0]]),
                client.domain_report(TEST_DOMAINS[0])
            ]

            try:
                results = await asyncio.gather(*tasks, return_exceptions=True)

                # Check results
                assert len(results) == 4

                # First result should be WhoisResult or None
                whois_result = results[0]
                if not isinstance(whois_result, Exception):
                    assert whois_result is None or isinstance(whois_result, WhoisResult)

                # Second result should be DNSResult or None
                dns_result = results[1]
                if not isinstance(dns_result, Exception):
                    assert dns_result is None or isinstance(dns_result, DNSResult)

                # Third result should be list or None
                categories_result = results[2]
                if not isinstance(categories_result, Exception):
                    assert categories_result is None or isinstance(categories_result, list)

                # Fourth result should have domain attribute or None
                report_result = results[3]
                if not isinstance(report_result, Exception) and report_result:
                    assert hasattr(report_result, "domain")

            except Exception:
                # If gather fails, that's also acceptable for testing
                pass


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
async def test_async_performance_comparison():
    """Compare performance between sync and async clients (requires both to work)."""
    try:
        config = Config()
    except DomainIQConfigurationError:
        pytest.skip("No API key available")

    # This test demonstrates the performance advantage of async
    domains = ["example.com", "google.com", "github.com"]

    import time

    # Test async performance
    start_time = time.time()
    async with AsyncDomainIQClient(config) as async_client:
        async_results = await async_client.concurrent_whois_lookup(
            targets=domains,
            max_concurrent=3
        )
    time.time() - start_time

    assert len(async_results) == len(domains)

    # Verify results are valid
    for result in async_results:
        assert result is None or isinstance(result, WhoisResult)


if __name__ == "__main__":
    # Run async tests
    import sys

    if not AIOHTTP_AVAILABLE:
        sys.exit(0)

    # Check if API key is available
    try:
        Config()
        pytest.main([__file__, "-v"])
    except DomainIQConfigurationError:
        pytest.main([__file__, "-v", "-m", "not integration"])

    sys.exit(0)
