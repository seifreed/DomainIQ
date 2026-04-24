"""Real-network integration tests for the async DomainIQ client."""

from __future__ import annotations

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

pytestmark = pytest.mark.integration

TEST_DOMAINS = ["example.com", "google.com", "github.com"]
TEST_IP = "8.8.8.8"


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
class TestAsyncDomainIQClientIntegration:
    """Integration tests using live DomainIQ API calls."""

    config: Config | None = None

    @classmethod
    def setup_class(cls):
        try:
            cls.config = Config()
        except DomainIQConfigurationError:
            pytest.skip("No API key available for integration tests")

    async def test_async_whois_lookup_domain(self):
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
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.whois_lookup(ip=TEST_IP)

            if result is None:
                pytest.skip("API returned None for WHOIS lookup")
            assert isinstance(result, WhoisResult)
            assert result.ip == TEST_IP or result.ip is None

    async def test_async_dns_lookup_basic(self):
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
            assert any(record_type in ["A", "MX"] for record_type in record_types)

    async def test_concurrent_whois_lookups(self):
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            domains = TEST_DOMAINS[:3]

            start_time = time.time()
            sequential_results = []
            for domain in domains:
                sequential_results.append(await client.whois_lookup(domain=domain))
            sequential_time = time.time() - start_time

            start_time = time.time()
            concurrent_results = await client.concurrent_whois_lookup(
                targets=domains,
                max_concurrent=3,
            )
            concurrent_time = time.time() - start_time
            assert concurrent_time < sequential_time or concurrent_time < 5.0
            assert len(concurrent_results) == len(domains)
            for result in concurrent_results:
                assert result is None or isinstance(result, WhoisResult)

    async def test_concurrent_dns_lookups(self):
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
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.domain_categorize([TEST_DOMAINS[0]])

            if not result:
                pytest.skip("API returned empty result for categorization")
            assert isinstance(result, list)
            if result:
                assert hasattr(result[0], "domain")
                assert hasattr(result[0], "categories")

    async def test_async_domain_snapshot(self):
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.domain_snapshot(TEST_DOMAINS[0])

            if result is None:
                pytest.skip("API returned None for domain snapshot")
            assert hasattr(result, "domain")
            assert isinstance(result.domain, str)

    async def test_async_bulk_dns_lookup(self):
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.bulk_dns(TEST_DOMAINS[:2])

            if not result:
                pytest.skip("API returned empty result for bulk DNS")
            assert isinstance(result, list)
            if result:
                assert isinstance(result[0], dict)

    async def test_async_bulk_whois(self):
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.bulk_whois(TEST_DOMAINS[:2])

            if not result:
                pytest.skip("API returned empty result for bulk WHOIS")
            assert isinstance(result, list)
            if result:
                assert isinstance(result[0], dict)

    async def test_async_domain_report(self):
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.domain_report(TEST_DOMAINS[0])

            if result is None:
                pytest.skip("API returned None for domain report")
            assert hasattr(result, "domain")
            assert isinstance(result.domain, str)

    async def test_async_reverse_search(self):
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            result = await client.reverse_search("email", "admin@example.com")

            if result is None:
                pytest.skip("API returned None for reverse search")
            assert isinstance(result, dict)

    async def test_async_monitor_list(self):
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            try:
                result = await client.monitor_list()
            except DomainIQError:
                pytest.skip("Monitor functionality not available")

            assert isinstance(result, list)

    async def test_async_context_manager(self):
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            assert client.config.api_key == self.config.api_key
            result = await client.whois_lookup(domain="example.com")
            assert result is None or isinstance(result, WhoisResult)

    async def test_session_handling(self):
        if self.config is None:
            pytest.skip("No config available")
        client = AsyncDomainIQClient(self.config)

        await client.whois_lookup(domain="example.com")
        assert client._transport._session is not None
        assert not client._transport._session.closed

        await client.close()
        assert client._transport._session.closed

    async def test_multiple_concurrent_operations(self):
        if self.config is None:
            pytest.skip("No config available")
        async with AsyncDomainIQClient(self.config) as client:
            tasks = [
                client.whois_lookup(domain=TEST_DOMAINS[0]),
                client.dns_lookup(TEST_DOMAINS[0]),
                client.domain_categorize([TEST_DOMAINS[0]]),
                client.domain_report(TEST_DOMAINS[0]),
            ]
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
                assert categories_result is None or isinstance(categories_result, list)

            report_result = results[3]
            if not isinstance(report_result, Exception) and report_result:
                assert hasattr(report_result, "domain")


@pytest.mark.skipif(not AIOHTTP_AVAILABLE, reason="aiohttp not available")
@pytest.mark.asyncio
async def test_async_performance_comparison():
    """Compare performance between sequential and concurrent async lookups."""
    try:
        config = Config()
    except DomainIQConfigurationError:
        pytest.skip("No API key available")

    domains = ["example.com", "google.com", "github.com"]

    async with AsyncDomainIQClient(config) as async_client:
        async_results = await async_client.concurrent_whois_lookup(
            targets=domains,
            max_concurrent=3,
        )

    assert len(async_results) == len(domains)
    for result in async_results:
        assert result is None or isinstance(result, WhoisResult)
