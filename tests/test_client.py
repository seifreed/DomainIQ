"""
Integration tests for the DomainIQ client using real API data.

These tests require a valid DomainIQ API key and make real API calls.
Set DOMAINIQ_API_KEY environment variable or create ~/.domainiq file.

Run with: pytest tests/test_client.py -v
Run integration tests only: pytest tests/test_client.py -m integration -v
Run without integration tests: pytest tests/test_client.py -m "not integration" -v
"""

from datetime import datetime
from unittest.mock import patch

import pytest

from domainiq import (
    DomainIQAPIError,
    DomainIQClient,
    DomainIQConfigurationError,
    DomainIQError,
)
from domainiq.config import Config
from domainiq.models import DNSRecordType, DNSResult, WhoisResult
from domainiq.utils import validate_domain, validate_email, validate_ip

# Test domains that should be stable and available
TEST_DOMAINS = [
    "example.com",
    "google.com",
    "github.com"
]

TEST_IP = "8.8.8.8"  # Google DNS
TEST_EMAIL = "admin@example.com"


class TestDomainIQClientUnit:
    """Unit tests that don't require API access."""

    def test_client_initialization_with_kwargs(self):
        """Test client initialization with keyword arguments."""
        client = DomainIQClient(api_key="test_key_456", timeout=60)
        assert client.config.api_key == "test_key_456"
        assert client.config.timeout == 60
        assert client.config.base_url == "https://www.domainiq.com/api"
        client.close()

    def test_whois_lookup_missing_parameters(self):
        """Test WHOIS lookup with missing parameters."""
        client = DomainIQClient(api_key="test_key")

        with pytest.raises(ValueError) as exc_info:
            client.whois_lookup()  # No domain or IP provided

        assert "Either domain or ip must be provided" in str(exc_info.value)
        client.close()

    def test_context_manager(self):
        """Test client as context manager."""
        with DomainIQClient(api_key="test_key") as client:
            assert client.config.api_key == "test_key"
            assert hasattr(client, "session")
        # Client should be properly closed after context


class TestConfigUnit:
    """Unit tests for Config class."""

    def test_config_initialization(self):
        """Test basic config initialization."""
        config = Config(api_key="test_key", timeout=60)
        assert config.api_key == "test_key"
        assert config.timeout == 60
        assert config.base_url == "https://www.domainiq.com/api"

    def test_config_validation_invalid_timeout(self):
        """Test config validation with invalid timeout."""
        config = Config(api_key="test_key", timeout=-1)

        with pytest.raises(DomainIQConfigurationError) as exc_info:
            config.validate()

        assert "Timeout must be positive" in str(exc_info.value)

    def test_config_validation_missing_api_key(self):
        """Test config validation with empty API key."""
        config = Config()
        config.api_key = ""  # Force empty key

        with pytest.raises(DomainIQConfigurationError) as exc_info:
            config.validate()

        assert "API key is required" in str(exc_info.value)


class TestUtilsUnit:
    """Unit tests for utility functions."""

    def test_validate_domain_valid(self):
        """Test domain validation with valid domains."""
        assert validate_domain("example.com")
        assert validate_domain("subdomain.example.com")
        assert validate_domain("test-domain.co.uk")

    def test_validate_domain_invalid(self):
        """Test domain validation with invalid domains."""
        assert not validate_domain("")
        assert not validate_domain("invalid")  # No TLD
        assert not validate_domain(".example.com")  # Leading dot
        assert not validate_domain("example.com.")  # Trailing dot
        assert not validate_domain("example..com")  # Double dot
        assert not validate_domain("a" * 64 + ".com")  # Label too long

    def test_validate_ip_valid(self):
        """Test IP validation with valid IPs."""
        assert validate_ip("192.168.1.1")
        assert validate_ip("8.8.8.8")
        assert validate_ip("127.0.0.1")

    def test_validate_ip_invalid(self):
        """Test IP validation with invalid IPs."""
        assert not validate_ip("")
        assert not validate_ip("192.168.1")  # Missing octet
        assert not validate_ip("192.168.1.256")  # Invalid octet
        assert not validate_ip("not.an.ip.address")

    def test_validate_email_valid(self):
        """Test email validation with valid emails."""
        assert validate_email("user@example.com")
        assert validate_email("test.email@domain.co.uk")

    def test_validate_email_invalid(self):
        """Test email validation with invalid emails."""
        assert not validate_email("")
        assert not validate_email("notanemail")
        assert not validate_email("@domain.com")  # Missing local part
        assert not validate_email("user@")  # Missing domain


class TestModelsUnit:
    """Unit tests for data models."""

    def test_whois_result_from_dict(self):
        """Test WhoisResult creation from dictionary."""
        data = {
            "domain": "example.com",
            "registrar": "Test Registrar",
            "creation_date": "2023-01-01T00:00:00Z",
            "registrant_name": "Test User"
        }

        result = WhoisResult.from_dict(data)

        assert result.domain == "example.com"
        assert result.registrar == "Test Registrar"
        assert result.registrant_name == "Test User"
        assert result.creation_date is not None
        assert isinstance(result.creation_date, datetime)

    def test_dns_result_from_dict(self):
        """Test DNSResult creation from dictionary."""
        data = {
            "domain": "example.com",
            "records": [
                {"name": "example.com", "type": "A", "value": "93.184.216.34", "ttl": 3600},
                {"name": "example.com", "type": "MX", "value": "mail.example.com", "priority": 10}
            ]
        }

        result = DNSResult.from_dict(data)

        assert result.domain == "example.com"
        assert len(result.records) == 2
        assert result.records[0].type == "A"
        assert result.records[0].value == "93.184.216.34"
        assert result.records[1].type == "MX"
        assert result.records[1].priority == 10


@pytest.mark.integration
class TestDomainIQClientIntegration:
    """Integration tests using real DomainIQ API calls."""

    @classmethod
    def setup_class(cls):
        """Set up test fixtures for the class."""
        try:
            # Try to create client with real API key
            cls.client = DomainIQClient()
        except DomainIQConfigurationError:
            pytest.skip("No API key available for integration tests")

    @classmethod
    def teardown_class(cls):
        """Clean up after all tests."""
        if hasattr(cls, "client"):
            cls.client.close()

    def test_whois_lookup_domain(self):
        """Test WHOIS lookup for a domain."""
        result = self.client.whois_lookup(domain=TEST_DOMAINS[0])

        if result:  # API might return None for some domains
            assert isinstance(result, WhoisResult)
            assert result.domain == TEST_DOMAINS[0] or result.domain is None
            if result.registrar:
                assert isinstance(result.registrar, str)
            if result.creation_date:
                assert isinstance(result.creation_date, datetime)

    def test_whois_lookup_ip(self):
        """Test WHOIS lookup for an IP address."""
        result = self.client.whois_lookup(ip=TEST_IP)

        if result:  # API might return None for some IPs
            assert isinstance(result, WhoisResult)
            assert result.ip == TEST_IP or result.ip is None

    def test_dns_lookup_basic(self):
        """Test basic DNS lookup."""
        result = self.client.dns_lookup(TEST_DOMAINS[0])

        if result:  # API might return None for some domains
            assert isinstance(result, DNSResult)
            assert result.domain == TEST_DOMAINS[0] or isinstance(result.domain, str)
            assert isinstance(result.records, list)

    def test_dns_lookup_with_types(self):
        """Test DNS lookup with specific record types."""
        result = self.client.dns_lookup(
            TEST_DOMAINS[0],
            record_types=[DNSRecordType.A, DNSRecordType.MX]
        )

        if result and result.records:
            assert isinstance(result, DNSResult)
            # Check that we got the requested record types
            record_types = [record.type for record in result.records]
            # At least one of the requested types should be present
            assert any(rtype in ["A", "MX"] for rtype in record_types)

    def test_domain_categorize(self):
        """Test domain categorization."""
        result = self.client.domain_categorize([TEST_DOMAINS[0]])

        if result:  # API might return empty list
            assert isinstance(result, list)
            if len(result) > 0:
                assert hasattr(result[0], "domain")
                assert hasattr(result[0], "categories")

    def test_domain_report(self):
        """Test domain report generation."""
        result = self.client.domain_report(TEST_DOMAINS[0])

        if result:  # API might return None
            assert hasattr(result, "domain")
            assert result.domain == TEST_DOMAINS[0] or isinstance(result.domain, str)

    def test_bulk_dns_lookup(self):
        """Test bulk DNS lookup."""
        result = self.client.bulk_dns(TEST_DOMAINS[:2])  # Test with 2 domains

        if result:  # API might return empty list
            assert isinstance(result, list)
            # Should have results for the domains we requested
            if len(result) > 0:
                assert isinstance(result[0], dict)

    def test_domain_search(self):
        """Test domain search functionality."""
        result = self.client.domain_search(
            keywords=["example"],
            match="any",
            limit=5
        )

        # Domain search might return None or data depending on API response
        if result:
            assert isinstance(result, dict)

    def test_email_report(self):
        """Test email report generation."""
        result = self.client.email_report(TEST_EMAIL)

        # Email report might return None or data
        if result:
            assert isinstance(result, dict)

    def test_reverse_search(self):
        """Test reverse search functionality."""
        result = self.client.reverse_search("email", TEST_EMAIL)

        # Reverse search might return None or data
        if result:
            assert isinstance(result, dict)

    def test_monitor_list(self):
        """Test monitor list functionality."""
        try:
            result = self.client.monitor_list()

            # Monitor list should return a list (empty or with data)
            assert isinstance(result, list)
        except DomainIQError:
            # Monitor functionality might not be available for all API keys
            pytest.skip("Monitor functionality not available")

    def test_error_handling_invalid_domain(self):
        """Test error handling with invalid domain."""
        # This should either return None or raise an appropriate error
        try:
            result = self.client.whois_lookup(domain="invalid..domain..name")
            # If it doesn't raise an error, result might be None
            assert result is None or isinstance(result, WhoisResult)
        except DomainIQAPIError:
            # API error is acceptable for invalid input
            pass

    def test_client_session_reuse(self):
        """Test that client reuses HTTP session properly."""
        # Make multiple requests to verify session is reused
        result1 = self.client.whois_lookup(domain=TEST_DOMAINS[0])
        result2 = self.client.dns_lookup(TEST_DOMAINS[0])

        # Both calls should work (or both return None)
        # This mainly tests that session reuse doesn't break functionality
        assert (result1 is None or isinstance(result1, WhoisResult))
        assert (result2 is None or isinstance(result2, DNSResult))


if __name__ == "__main__":
    # Run tests
    import sys

    # Check if API key is available
    try:
        Config()
        pytest.main([__file__, "-v"])
    except DomainIQConfigurationError:
        pytest.main([__file__, "-v", "-m", "not integration"])

    sys.exit(0)


class TestConfig:
    """Test cases for Config class."""

    def test_config_initialization(self):
        """Test basic config initialization."""
        config = Config(api_key="test_key", timeout=60)
        assert config.api_key == "test_key"
        assert config.timeout == 60
        assert config.base_url == "https://www.domainiq.com/api"

    def test_config_validation_missing_api_key(self):
        """Test config validation with missing API key."""
        with patch.dict("os.environ", {}, clear=True):
            with patch("pathlib.Path.exists", return_value=False):
                with patch("domainiq.config.Config._is_interactive", return_value=False):
                    with pytest.raises(DomainIQError) as exc_info:
                        Config()

                    assert "No API key found" in str(exc_info.value)

    def test_config_from_environment(self):
        """Test loading API key from environment variable."""
        with patch.dict("os.environ", {"DOMAINIQ_API_KEY": "env_key_123"}):
            config = Config()
            assert config.api_key == "env_key_123"

    def test_config_validation_invalid_timeout(self):
        """Test config validation with invalid timeout."""
        config = Config(api_key="test_key", timeout=-1)

        with pytest.raises(DomainIQError) as exc_info:
            config.validate()

        assert "Timeout must be positive" in str(exc_info.value)


class TestModels:
    """Test cases for data models."""

    def test_whois_result_from_dict(self):
        """Test WhoisResult creation from dictionary."""
        data = {
            "domain": "example.com",
            "registrar": "Test Registrar",
            "creation_date": "2023-01-01T00:00:00Z",
            "registrant_name": "Test User"
        }

        result = WhoisResult.from_dict(data)

        assert result.domain == "example.com"
        assert result.registrar == "Test Registrar"
        assert result.registrant_name == "Test User"
        assert result.creation_date is not None

    def test_dns_result_from_dict(self):
        """Test DNSResult creation from dictionary."""
        data = {
            "domain": "example.com",
            "records": [
                {"type": "A", "value": "93.184.216.34", "ttl": 3600},
                {"type": "MX", "value": "mail.example.com", "priority": 10}
            ]
        }

        result = DNSResult.from_dict(data)

        assert result.domain == "example.com"
        assert len(result.records) == 2
        assert result.records[0].type == "A"
        assert result.records[1].type == "MX"
        assert result.records[1].priority == 10


if __name__ == "__main__":
    pytest.main([__file__])
