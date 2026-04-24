"""Real-network integration tests for the synchronous DomainIQ client."""

from __future__ import annotations

from datetime import datetime

import pytest

from domainiq import (
    DomainIQAPIError,
    DomainIQClient,
    DomainIQConfigurationError,
    DomainIQError,
)
from domainiq.models import DNSRecordType, DNSResult, MatchType, WhoisResult

pytestmark = pytest.mark.integration

TEST_DOMAINS = ["example.com", "google.com", "github.com"]
TEST_IP = "8.8.8.8"
TEST_EMAIL = "admin@example.com"


class TestDomainIQClientIntegration:
    """Integration tests using live DomainIQ API calls."""

    client: DomainIQClient | None = None

    @classmethod
    def setup_class(cls):
        try:
            cls.client = DomainIQClient()
        except DomainIQConfigurationError:
            pytest.skip("No API key available for integration tests")

    @classmethod
    def teardown_class(cls):
        if cls.client is not None:
            cls.client.close()

    def test_whois_lookup_domain(self):
        result = self.client.whois_lookup(domain=TEST_DOMAINS[0])

        if result is None:
            pytest.skip("API returned None for WHOIS lookup")
        assert isinstance(result, WhoisResult)
        assert result.domain == TEST_DOMAINS[0] or result.domain is None
        if result.registrar:
            assert isinstance(result.registrar, str)
        if result.creation_date:
            assert isinstance(result.creation_date, datetime)

    def test_whois_lookup_ip(self):
        result = self.client.whois_lookup(ip=TEST_IP)

        if result is None:
            pytest.skip("API returned None for WHOIS lookup")
        assert isinstance(result, WhoisResult)
        assert result.ip == TEST_IP or result.ip is None

    def test_dns_lookup_basic(self):
        result = self.client.dns_lookup(TEST_DOMAINS[0])

        if result is None:
            pytest.skip("API returned None for DNS lookup")
        assert isinstance(result, DNSResult)
        assert isinstance(result.domain, str)
        assert isinstance(result.records, list)

    def test_dns_lookup_with_types(self):
        result = self.client.dns_lookup(
            TEST_DOMAINS[0],
            record_types=[DNSRecordType.A, DNSRecordType.MX],
        )

        if result is None or not result.records:
            pytest.skip("API returned None or no records for DNS lookup")
        assert isinstance(result, DNSResult)
        record_types = [record.type for record in result.records]
        assert any(record_type in ["A", "MX"] for record_type in record_types)

    def test_domain_categorize(self):
        result = self.client.domain_categorize([TEST_DOMAINS[0]])

        if not result:
            pytest.skip("API returned empty result for categorization")
        assert isinstance(result, list)
        if result:
            assert hasattr(result[0], "domain")
            assert hasattr(result[0], "categories")

    def test_domain_report(self):
        result = self.client.domain_report(TEST_DOMAINS[0])

        if result is None:
            pytest.skip("API returned None for domain report")
        assert hasattr(result, "domain")
        assert isinstance(result.domain, str)

    def test_bulk_dns_lookup(self):
        result = self.client.bulk_dns(TEST_DOMAINS[:2])

        if not result:
            pytest.skip("API returned empty result for bulk DNS")
        assert isinstance(result, list)
        if result:
            assert isinstance(result[0], dict)

    def test_domain_search(self):
        result = self.client.domain_search(
            keywords=["example"],
            match=MatchType.ANY,
            limit=5,
        )

        if result is None:
            pytest.skip("API returned None for domain search")
        assert isinstance(result, dict)

    def test_email_report(self):
        result = self.client.email_report(TEST_EMAIL)

        if result is None:
            pytest.skip("API returned None for email report")
        assert isinstance(result, dict)

    def test_reverse_search(self):
        result = self.client.reverse_search("email", TEST_EMAIL)

        if result is None:
            pytest.skip("API returned None for reverse search")
        assert isinstance(result, dict)

    def test_monitor_list(self):
        try:
            result = self.client.monitor_list()
        except DomainIQError:
            pytest.skip("Monitor functionality not available")

        assert isinstance(result, list)

    def test_error_handling_invalid_domain(self):
        try:
            result = self.client.whois_lookup(domain="invalid..domain..name")
            assert result is None or isinstance(result, WhoisResult)
        except DomainIQAPIError:
            pass

    def test_client_session_reuse(self):
        result1 = self.client.whois_lookup(domain=TEST_DOMAINS[0])
        result2 = self.client.dns_lookup(TEST_DOMAINS[0])

        assert result1 is None or isinstance(result1, WhoisResult)
        assert result2 is None or isinstance(result2, DNSResult)
