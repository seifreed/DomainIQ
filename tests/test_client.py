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
    parse_dns_result,
    parse_whois_result,
)
from domainiq.config import Config
from domainiq.models import DNSRecordType, DNSResult, MatchType, WhoisResult
from domainiq.validators import validate_domain, validate_email, validate_ipv4

# Test domains that should be stable and available
TEST_DOMAINS = ["example.com", "google.com", "github.com"]

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
        from domainiq.exceptions import DomainIQError
        client = DomainIQClient(api_key="test_key")

        with pytest.raises(DomainIQError, match="Either domain or ip") as exc_info:
            client.whois_lookup()  # No domain or IP provided

        assert "Either domain or ip must be provided" in str(exc_info.value)
        client.close()

    def test_context_manager(self):
        """Test client as context manager."""
        with DomainIQClient(api_key="test_key") as client:
            assert client.config.api_key == "test_key"
            assert hasattr(client, "_transport")
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

    def test_config_no_key_anywhere(self):
        """Test Config() raises when no key is available anywhere."""
        with (
            patch.dict("os.environ", {}, clear=True),
            patch("pathlib.Path.exists", return_value=False),
            patch(
                "domainiq.config._ApiKeyLoader._is_interactive",
                return_value=False,
            ),
            pytest.raises(DomainIQError) as exc_info,
        ):
            Config()

        assert "No API key found" in str(exc_info.value)

    def test_config_from_environment(self):
        """Test loading API key from environment variable."""
        with patch.dict("os.environ", {"DOMAINIQ_API_KEY": "env_key_123"}):
            config = Config()
            assert config.api_key == "env_key_123"


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

    def test_validate_ipv4_valid(self):
        """Test IP validation with valid IPs."""
        assert validate_ipv4("192.168.1.1")
        assert validate_ipv4("8.8.8.8")
        assert validate_ipv4("127.0.0.1")

    def test_validate_ipv4_invalid(self):
        """Test IP validation with invalid IPs."""
        assert not validate_ipv4("")
        assert not validate_ipv4("192.168.1")  # Missing octet
        assert not validate_ipv4("192.168.1.256")  # Invalid octet
        assert not validate_ipv4("not.an.ip.address")

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
            "registrant_name": "Test User",
        }

        result = parse_whois_result(data)

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
                {
                    "name": "example.com",
                    "type": "A",
                    "value": "93.184.216.34",
                    "ttl": 3600,
                },
                {
                    "name": "example.com",
                    "type": "MX",
                    "value": "mail.example.com",
                    "priority": 10,
                },
            ],
        }

        result = parse_dns_result(data)

        assert result.domain == "example.com"
        assert len(result.records) == 2
        assert result.records[0].type == "A"
        assert result.records[0].value == "93.184.216.34"
        assert result.records[1].type == "MX"
        assert result.records[1].priority == 10


@pytest.mark.integration
class TestDomainIQClientIntegration:
    """Integration tests using real DomainIQ API calls."""

    client: DomainIQClient | None

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
        if cls.client is not None:
            cls.client.close()

    def test_whois_lookup_domain(self):
        """Test WHOIS lookup for a domain."""
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
        """Test WHOIS lookup for an IP address."""
        result = self.client.whois_lookup(ip=TEST_IP)

        if result is None:
            pytest.skip("API returned None for WHOIS lookup")
        assert isinstance(result, WhoisResult)
        assert result.ip == TEST_IP or result.ip is None

    def test_dns_lookup_basic(self):
        """Test basic DNS lookup."""
        result = self.client.dns_lookup(TEST_DOMAINS[0])

        if result is None:
            pytest.skip("API returned None for DNS lookup")
        assert isinstance(result, DNSResult)
        assert isinstance(result.domain, str)
        assert isinstance(result.records, list)

    def test_dns_lookup_with_types(self):
        """Test DNS lookup with specific record types."""
        result = self.client.dns_lookup(
            TEST_DOMAINS[0], record_types=[DNSRecordType.A, DNSRecordType.MX]
        )

        if result is None or not result.records:
            pytest.skip("API returned None or no records for DNS lookup")
        assert isinstance(result, DNSResult)
        # Check that we got the requested record types
        record_types = [record.type for record in result.records]
        # At least one of the requested types should be present
        assert any(rtype in ["A", "MX"] for rtype in record_types)

    def test_domain_categorize(self):
        """Test domain categorization."""
        result = self.client.domain_categorize([TEST_DOMAINS[0]])

        if not result:
            pytest.skip("API returned empty result for categorization")
        assert isinstance(result, list)
        if len(result) > 0:
            assert hasattr(result[0], "domain")
            assert hasattr(result[0], "categories")

    def test_domain_report(self):
        """Test domain report generation."""
        result = self.client.domain_report(TEST_DOMAINS[0])

        if result is None:
            pytest.skip("API returned None for domain report")
        assert hasattr(result, "domain")
        assert isinstance(result.domain, str)

    def test_bulk_dns_lookup(self):
        """Test bulk DNS lookup."""
        result = self.client.bulk_dns(TEST_DOMAINS[:2])  # Test with 2 domains

        if not result:
            pytest.skip("API returned empty result for bulk DNS")
        assert isinstance(result, list)
        if len(result) > 0:
            assert isinstance(result[0], dict)

    def test_domain_search(self):
        """Test domain search functionality."""
        result = self.client.domain_search(
            keywords=["example"], match=MatchType.ANY, limit=5
        )

        # Domain search might return None or data depending on API response
        if result is None:
            pytest.skip("API returned None for domain search")
        assert isinstance(result, dict)

    def test_email_report(self):
        """Test email report generation."""
        result = self.client.email_report(TEST_EMAIL)

        # Email report might return None or data
        if result is None:
            pytest.skip("API returned None for email report")
        assert isinstance(result, dict)

    def test_reverse_search(self):
        """Test reverse search functionality."""
        result = self.client.reverse_search("email", TEST_EMAIL)

        # Reverse search might return None or data
        if result is None:
            pytest.skip("API returned None for reverse search")
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
        assert result1 is None or isinstance(result1, WhoisResult)
        assert result2 is None or isinstance(result2, DNSResult)


class TestLogicBugRegressions:
    """Regression tests for logic bugs identified in analysis (2026-04-16)."""

    # Bug 1: _try_parse_date numeric fallback
    def test_try_parse_date_rejects_short_numeric_string(self):
        """Short numeric strings must NOT silently become 1970-era timestamps."""
        from domainiq.parsers import try_parse_date as _try_parse_date

        # "2023" is not a valid ISO date; before the fix it became
        # 1970-01-01T00:33:43 via fromtimestamp. Now it must return None.
        assert _try_parse_date("2023") is None
        # "123" — clearly too short for an epoch and not ISO.
        assert _try_parse_date("123") is None

    def test_try_parse_date_accepts_plausible_timestamp(self):
        """A 10-digit epoch value should still parse as a datetime."""
        from domainiq.parsers import try_parse_date as _try_parse_date

        parsed = _try_parse_date("1700000000")
        assert isinstance(parsed, datetime)
        assert parsed.year >= 2020

    def test_try_parse_date_accepts_float_timestamp(self):
        """Float timestamps (with decimal) remain valid."""
        from domainiq.parsers import try_parse_date as _try_parse_date

        parsed = _try_parse_date("1700000000.5")
        assert isinstance(parsed, datetime)

    def test_try_parse_date_still_parses_iso(self):
        """ISO-format dates keep the original fast path."""
        from domainiq.parsers import try_parse_date as _try_parse_date

        parsed = _try_parse_date("2023-01-01T00:00:00")
        assert isinstance(parsed, datetime)
        assert parsed.year == 2023

    # Bug 2: email whitespace filter
    def test_whois_emails_filter_whitespace_entries(self):
        data = {
            "domain": "example.com",
            "emails": ["a@b.com", "  ", "", None, "  c@d.com "],
        }
        result = parse_whois_result(data)
        assert result.registrant_email == ["a@b.com", "c@d.com"]

    def test_whois_emails_all_empty_returns_none(self):
        data = {"domain": "example.com", "emails": ["", "  ", None]}
        result = parse_whois_result(data)
        assert result.registrant_email is None

    # Bug 3: nameserver gap handling
    def test_whois_nameservers_tolerate_gaps(self):
        data = {
            "domain": "example.com",
            "ns_1": "ns1.example.com",
            "ns_3": "ns3.example.com",
            "ns_5": "ns5.example.com",
        }
        result = parse_whois_result(data)
        assert result.nameservers == [
            "ns1.example.com",
            "ns3.example.com",
            "ns5.example.com",
        ]

    # Bug 4: validate_ipv4 signed octets
    def test_validate_ipv4_rejects_signed_octets(self):
        assert not validate_ipv4("-0.0.0.0")
        assert not validate_ipv4("+1.2.3.4")
        assert not validate_ipv4("1.-1.0.0")
        assert not validate_ipv4("1.+1.0.0")

    def test_validate_ipv4_rejects_empty_octet(self):
        assert not validate_ipv4("1..2.3")
        assert not validate_ipv4(".1.2.3")

    # Bug 5: AAAA value mapping
    def test_dns_result_maps_aaaa_from_ip_field(self):
        data = {
            "results": [
                {
                    "host": "example.com",
                    "type": "AAAA",
                    "ip": "2001:db8::1",
                }
            ]
        }
        result = parse_dns_result(data)
        assert len(result.records) == 1
        assert result.records[0].type == "AAAA"
        assert result.records[0].value == "2001:db8::1"

    # Bug 6: format_api_params JSON for nested dicts
    def test_format_api_params_serializes_nested_dicts_as_json(self):
        from domainiq.utils import format_api_params

        formatted = format_api_params({"payload": [{"a": 1}, {"b": 2}]})
        # JSON uses double quotes, not single quotes
        assert '"' in formatted["payload"]
        assert "'" not in formatted["payload"]
        # Round-trips as valid JSON
        import json

        assert json.loads(formatted["payload"]) == [{"a": 1}, {"b": 2}]

    # Bug 8: CLI --email-alert default
    def test_cli_email_alert_default_is_true(self):
        from domainiq.cli import create_parser

        parser = create_parser()
        args = parser.parse_args([])
        assert args.email_alert is True

    def test_cli_no_email_alert_flag_disables(self):
        from domainiq.cli import create_parser

        parser = create_parser()
        args = parser.parse_args(["--no-email-alert"])
        assert args.email_alert is False

    # Bug 9: _is_interactive requires stdout TTY
    def test_is_interactive_requires_both_stdin_and_stdout(self):
        with patch("os.isatty") as mock_isatty:
            mock_isatty.side_effect = lambda fd: fd == 0  # only stdin is TTY
            assert Config._is_interactive() is False

        with patch("os.isatty") as mock_isatty:
            mock_isatty.return_value = True
            assert Config._is_interactive() is True

    # Bug 10: set_config_path persists pending key
    def test_set_config_path_persists_pending_interactive_key(self, tmp_path):
        """Interactive-sourced keys must be flushed to disk by set_config_path."""
        target = tmp_path / "new_config"

        with (
            patch.dict("os.environ", {}, clear=True),
            patch(
                "domainiq.config._ApiKeyLoader._is_interactive",
                return_value=True,
            ),
            patch("builtins.input", return_value="interactive_key_xyz"),
        ):
            config = Config(config_file=str(tmp_path / "initial"))
            config.set_config_path(str(target), api_key=None)

        assert target.exists()
        assert target.read_text() == "interactive_key_xyz"


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
