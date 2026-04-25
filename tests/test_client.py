"""Unit and regression tests for the synchronous DomainIQ client."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

import domainiq
from domainiq import (
    DomainIQClient,
    DomainIQConfigurationError,
    DomainIQError,
    DomainIQValidationError,
)
from domainiq.cli import create_parser
from domainiq.config import Config
from domainiq.deserializers import parse_dns_result, parse_whois_result
from domainiq.formatters import format_api_params
from domainiq.parsers import try_parse_date as _try_parse_date
from domainiq.validators import (
    ensure_positive_int,
    validate_domain,
    validate_email,
    validate_ipv4,
)


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

        with pytest.raises(DomainIQError, match="Either domain or ip") as exc_info:
            client.whois_lookup()

        assert "Either domain or ip must be provided" in str(exc_info.value)
        client.close()

    def test_context_manager(self):
        """Test client as context manager."""
        with DomainIQClient(api_key="test_key") as client:
            assert client.config.api_key == "test_key"
            assert hasattr(client, "_transport")


class TestConfigUnit:
    """Unit tests for Config."""

    def test_config_initialization(self):
        config = Config(api_key="test_key", timeout=60)
        assert config.api_key == "test_key"
        assert config.timeout == 60
        assert config.base_url == "https://www.domainiq.com/api"

    def test_config_validation_invalid_timeout(self):
        config = Config(api_key="test_key", timeout=-1)

        with pytest.raises(DomainIQConfigurationError) as exc_info:
            config.validate()

        assert "Timeout must be positive" in str(exc_info.value)

    def test_config_validation_missing_api_key(self):
        config = Config(api_key="test_key")
        config.api_key = ""

        with pytest.raises(DomainIQConfigurationError) as exc_info:
            config.validate()

        assert "API key is required" in str(exc_info.value)

    def test_config_no_key_anywhere(self):
        with (
            patch.dict("os.environ", {}, clear=True),
            patch("pathlib.Path.exists", return_value=False),
            pytest.raises(DomainIQError) as exc_info,
        ):
            Config()

        assert "No API key found" in str(exc_info.value)

    def test_config_from_environment(self):
        with patch.dict("os.environ", {"DOMAINIQ_API_KEY": "env_key_123"}):
            config = Config()
            assert config.api_key == "env_key_123"

    def test_config_module_import_ignores_invalid_numeric_environment(self):
        env = os.environ | {"DOMAINIQ_MAX_RETRIES": "abc"}

        completed = subprocess.run(
            [sys.executable, "-c", "import domainiq.config"],
            cwd=Path(__file__).resolve().parents[1],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

        assert completed.returncode == 0, completed.stderr

    @pytest.mark.parametrize(
        "env_name",
        [
            "DOMAINIQ_TIMEOUT",
            "DOMAINIQ_MAX_RETRIES",
            "DOMAINIQ_RETRY_DELAY",
            "DOMAINIQ_CONNECTOR_LIMIT",
            "DOMAINIQ_CONNECTOR_LIMIT_PER_HOST",
        ],
    )
    def test_invalid_numeric_environment_values_raise_config_error(self, env_name):
        with (
            patch.dict("os.environ", {env_name: "abc"}, clear=True),
            pytest.raises(DomainIQConfigurationError, match=env_name),
        ):
            Config(api_key="test_key")

    def test_config_uses_numeric_environment_values(self):
        with patch.dict(
            "os.environ",
            {
                "DOMAINIQ_TIMEOUT": "12.5",
                "DOMAINIQ_MAX_RETRIES": "5",
                "DOMAINIQ_RETRY_DELAY": "2",
                "DOMAINIQ_CONNECTOR_LIMIT": "11",
                "DOMAINIQ_CONNECTOR_LIMIT_PER_HOST": "3",
            },
            clear=True,
        ):
            config = Config(api_key="test_key")

        assert config.timeout == 12.5
        assert config.max_retries == 5
        assert config.retry_delay == 2
        assert config.connector_limit == 11
        assert config.connector_limit_per_host == 3

    @pytest.mark.parametrize(
        ("env_name", "kwarg", "value"),
        [
            ("DOMAINIQ_TIMEOUT", "timeout", 20.0),
            ("DOMAINIQ_MAX_RETRIES", "max_retries", 6),
            ("DOMAINIQ_RETRY_DELAY", "retry_delay", 4),
            ("DOMAINIQ_CONNECTOR_LIMIT", "connector_limit", 9),
            ("DOMAINIQ_CONNECTOR_LIMIT_PER_HOST", "connector_limit_per_host", 2),
        ],
    )
    def test_explicit_numeric_config_values_override_invalid_environment(
        self,
        env_name,
        kwarg,
        value,
    ):
        with patch.dict("os.environ", {env_name: "abc"}, clear=True):
            config = Config(api_key="test_key", **{kwarg: value})

        assert getattr(config, kwarg) == value

    @pytest.mark.parametrize(
        ("kwargs", "message"),
        [
            ({"connector_limit": 0}, "Connector limit must be positive"),
            (
                {"connector_limit_per_host": -1},
                "Connector limit per host must be positive",
            ),
        ],
    )
    def test_config_validation_invalid_connector_limits(self, kwargs, message):
        config = Config(api_key="test_key", **kwargs)

        with pytest.raises(DomainIQConfigurationError, match=message):
            config.validate()

    def test_set_config_path_reloads_key_from_new_file(self, tmp_path):
        initial = tmp_path / "initial"
        target = tmp_path / "new_config"
        initial.write_text("initial_key")
        target.write_text("file_key_xyz")

        config = Config(config_file=str(initial))
        config.set_config_path(str(target), api_key=None)

        assert config.config_file_path == target
        assert config.api_key == "file_key_xyz"


class TestUtilsUnit:
    """Unit tests for utility functions."""

    def test_validate_domain_valid(self):
        assert validate_domain("example.com")
        assert validate_domain("subdomain.example.com")
        assert validate_domain("test-domain.co.uk")

    def test_validate_domain_invalid(self):
        assert not validate_domain("")
        assert not validate_domain("invalid")
        assert not validate_domain(".example.com")
        assert not validate_domain("example.com.")
        assert not validate_domain("example..com")
        assert not validate_domain("example\n.com")
        assert not validate_domain("example.com\n")
        assert not validate_domain("192.0.2.1")
        assert not validate_domain("999.999.999.999")
        assert not validate_domain("a" * 64 + ".com")

    def test_validate_ipv4_valid(self):
        assert validate_ipv4("192.168.1.1")
        assert validate_ipv4("8.8.8.8")
        assert validate_ipv4("127.0.0.1")

    def test_validate_ipv4_invalid(self):
        assert not validate_ipv4("")
        assert not validate_ipv4("192.168.1")
        assert not validate_ipv4("192.168.1.256")
        assert not validate_ipv4("not.an.ip.address")

    def test_validate_email_valid(self):
        assert validate_email("user@example.com")
        assert validate_email("test.email@domain.co.uk")

    def test_validate_email_invalid(self):
        assert not validate_email("")
        assert not validate_email("notanemail")
        assert not validate_email("@domain.com")
        assert not validate_email("user@")
        assert not validate_email("bad local@example.com")
        assert not validate_email(" user@example.com")
        assert not validate_email("user @example.com")
        assert not validate_email("user\n@example.com")
        assert not validate_email("user\t@example.com")
        assert not validate_email("user@example\n.com")
        assert not validate_email("user@example.com\n")
        assert not validate_email(".user@example.com")
        assert not validate_email("user.@example.com")
        assert not validate_email("user..name@example.com")

    @pytest.mark.parametrize("value", [True, False, 1.5, "3"])
    def test_ensure_positive_int_rejects_non_int_values(self, value):
        with pytest.raises(DomainIQValidationError) as exc_info:
            ensure_positive_int("report_id", value)

        assert exc_info.value.param_name == "report_id"


class TestModelsUnit:
    """Unit tests for data models."""

    def test_parse_helpers_are_not_root_exports(self):
        assert "parse_whois_result" not in domainiq.__all__
        assert not hasattr(domainiq, "parse_whois_result")

    def test_whois_result_from_dict(self):
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


class TestLogicBugRegressions:
    """Regression tests for previously identified logic bugs."""

    def test_try_parse_date_rejects_short_numeric_string(self):
        assert _try_parse_date("2023") is None
        assert _try_parse_date("123") is None

    def test_try_parse_date_accepts_plausible_timestamp(self):
        parsed = _try_parse_date("1700000000")
        assert isinstance(parsed, datetime)
        assert parsed.year >= 2020

    def test_try_parse_date_accepts_float_timestamp(self):
        parsed = _try_parse_date("1700000000.5")
        assert isinstance(parsed, datetime)

    def test_try_parse_date_accepts_numeric_timestamp(self):
        expected = datetime(2024, 1, 1, 0, 0, 0)  # noqa: DTZ001

        assert _try_parse_date(1704067200) == expected
        assert _try_parse_date("1704067200") == expected

    def test_try_parse_date_accepts_numeric_float_timestamp(self):
        expected = datetime(2024, 1, 1, 0, 0, 0, 500000)  # noqa: DTZ001

        assert _try_parse_date(1704067200.5) == expected
        assert _try_parse_date("1704067200.5") == expected

    def test_try_parse_date_timestamp_is_timezone_independent(self):
        if not hasattr(time, "tzset"):
            pytest.skip("time.tzset is unavailable on this platform")

        expected = datetime(2024, 1, 1, 0, 0, 0)  # noqa: DTZ001
        original_tz = os.environ.get("TZ")
        try:
            for tz_name in ("UTC", "Europe/Madrid", "America/New_York"):
                os.environ["TZ"] = tz_name
                time.tzset()

                assert _try_parse_date("1704067200") == expected
                assert _try_parse_date(1704067200) == expected
        finally:
            if original_tz is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = original_tz
            time.tzset()

    def test_try_parse_date_still_parses_iso(self):
        parsed = _try_parse_date("2023-01-01T00:00:00")
        assert isinstance(parsed, datetime)
        assert parsed.year == 2023

    def test_try_parse_date_normalizes_aware_iso_to_naive_utc(self):
        expected = datetime(2024, 1, 1, 0, 0, 0)  # noqa: DTZ001

        zulu = _try_parse_date("2024-01-01T00:00:00Z")
        offset = _try_parse_date("2024-01-01T01:00:00+01:00")

        assert zulu == expected
        assert offset == expected
        assert zulu is not None
        assert offset is not None
        assert zulu.tzinfo is None
        assert offset.tzinfo is None

    def test_try_parse_date_strips_surrounding_whitespace(self):
        parsed = _try_parse_date(" 2024-01-01 ")
        assert isinstance(parsed, datetime)
        assert parsed.year == 2024
        assert parsed.month == 1
        assert parsed.day == 1

    def test_try_parse_date_strips_surrounding_whitespace_for_iso_datetime(self):
        parsed = _try_parse_date(" 2023-01-01T00:00:00 ")
        assert isinstance(parsed, datetime)
        assert parsed.year == 2023

    def test_try_parse_date_whitespace_only_returns_none(self):
        assert _try_parse_date("   ") is None

    def test_whois_creation_date_strips_surrounding_whitespace(self):
        result = parse_whois_result(
            {"domain": "example.com", "creation_date": " 2024-01-01 "}
        )
        assert result.creation_date is not None
        assert result.creation_date.year == 2024
        assert result.creation_date.month == 1
        assert result.creation_date.day == 1

    def test_whois_creation_date_accepts_numeric_timestamp(self):
        result = parse_whois_result(
            {"domain": "example.com", "creation_date": 1704067200}
        )

        assert result.creation_date == _try_parse_date("1704067200")

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

    def test_whois_emails_empty_list_falls_back_to_registrant_email(self):
        data = {
            "domain": "example.com",
            "emails": [],
            "registrant_email": "admin@example.com",
        }
        result = parse_whois_result(data)
        assert result.registrant_email == ["admin@example.com"]

    def test_whois_emails_empty_string_falls_back_to_registrant_email(self):
        data = {
            "domain": "example.com",
            "emails": "",
            "registrant_email": "admin@example.com",
        }
        result = parse_whois_result(data)
        assert result.registrant_email == ["admin@example.com"]

    def test_whois_emails_normalized_empty_list_falls_back_to_registrant_email(self):
        data = {
            "domain": "example.com",
            "emails": ["", "  ", None],
            "registrant_email": "admin@example.com",
        }
        result = parse_whois_result(data)
        assert result.registrant_email == ["admin@example.com"]

    def test_whois_emails_non_empty_list_takes_priority_over_registrant_email(self):
        data = {
            "domain": "example.com",
            "emails": ["primary@example.com"],
            "registrant_email": "admin@example.com",
        }
        result = parse_whois_result(data)
        assert result.registrant_email == ["primary@example.com"]

    def test_whois_statuses_filter_empty_comma_entries(self):
        data = {"domain": "example.com", "status": "active, "}
        result = parse_whois_result(data)
        assert result.status == ["active"]

    def test_whois_statuses_strip_and_filter_list_entries(self):
        data = {
            "domain": "example.com",
            "status": [" active ", " ", None, "clientHold"],
        }
        result = parse_whois_result(data)
        assert result.status == ["active", "clientHold"]

    def test_whois_empty_status_string_returns_empty_list(self):
        data = {"domain": "example.com", "status": " "}
        result = parse_whois_result(data)
        assert result.status == []

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

    def test_whois_nameservers_empty_indexed_values_fall_back_to_nameservers(self):
        data = {
            "domain": "example.com",
            "ns_1": "",
            "nameservers": ["ns1.example.com"],
        }
        result = parse_whois_result(data)
        assert result.nameservers == ["ns1.example.com"]

    def test_whois_nameservers_accept_single_host_dict(self):
        data = {
            "domain": "example.com",
            "nameservers": {"host": "ns1.example.com"},
        }
        result = parse_whois_result(data)
        assert result.nameservers == ["ns1.example.com"]

    def test_whois_nameservers_accept_list_of_host_dicts(self):
        data = {
            "domain": "example.com",
            "nameservers": [{"host": "ns1.example.com"}],
        }
        result = parse_whois_result(data)
        assert result.nameservers == ["ns1.example.com"]

    def test_whois_nameservers_strip_and_filter_empty_values(self):
        data = {
            "domain": "example.com",
            "nameservers": [
                "",
                " ns1.example.com ",
                {"host": ""},
                {"host": " ns2.example.com "},
            ],
        }
        result = parse_whois_result(data)
        assert result.nameservers == ["ns1.example.com", "ns2.example.com"]

    def test_whois_nameservers_split_comma_separated_string(self):
        data = {
            "domain": "example.com",
            "nameservers": "ns1.example.com, ns2.example.com",
        }
        result = parse_whois_result(data)
        assert result.nameservers == ["ns1.example.com", "ns2.example.com"]

    def test_whois_nameservers_whitespace_string_returns_empty_list(self):
        data = {"domain": "example.com", "nameservers": " "}
        result = parse_whois_result(data)
        assert result.nameservers == []

    def test_validate_ipv4_rejects_signed_octets(self):
        assert not validate_ipv4("-0.0.0.0")
        assert not validate_ipv4("+1.2.3.4")
        assert not validate_ipv4("1.-1.0.0")
        assert not validate_ipv4("1.+1.0.0")

    def test_validate_ipv4_rejects_empty_octet(self):
        assert not validate_ipv4("1..2.3")
        assert not validate_ipv4(".1.2.3")

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

    def test_dns_result_infers_domain_from_record_name(self):
        data = {
            "records": [
                {
                    "name": "example.com",
                    "type": "A",
                    "ip": "192.0.2.1",
                }
            ]
        }
        result = parse_dns_result(data)
        assert result.domain == "example.com"

    def test_dns_result_accepts_single_record_dict(self):
        data = {
            "domain": "example.com",
            "records": {
                "name": "example.com",
                "type": "A",
                "ip": "192.0.2.1",
            },
        }

        result = parse_dns_result(data)

        assert result.domain == "example.com"
        assert len(result.records) == 1
        assert result.records[0].type == "A"
        assert result.records[0].value == "192.0.2.1"

    def test_dns_result_prefers_soa_record_name_for_domain(self):
        data = {
            "records": [
                {
                    "name": "example.com",
                    "type": "SOA",
                    "value": "ns1.example.com",
                },
                {
                    "name": "www.example.com",
                    "type": "A",
                    "ip": "192.0.2.1",
                },
            ]
        }
        result = parse_dns_result(data)
        assert result.domain == "example.com"

    def test_dns_result_maps_soa_mname_field(self):
        data = {
            "domain": "example.com",
            "records": [
                {
                    "name": "example.com",
                    "type": "SOA",
                    "mname": "ns1.example.com",
                }
            ],
        }

        result = parse_dns_result(data)

        assert len(result.records) == 1
        assert result.records[0].type == "SOA"
        assert result.records[0].value == "ns1.example.com"

    def test_dns_result_maps_ptr_ptrdname_field(self):
        data = {
            "domain": "example.com",
            "records": [
                {
                    "name": "1.2.0.192.in-addr.arpa",
                    "type": "PTR",
                    "ptrdname": "host.example.com",
                }
            ],
        }

        result = parse_dns_result(data)

        assert len(result.records) == 1
        assert result.records[0].type == "PTR"
        assert result.records[0].value == "host.example.com"

    def test_dns_result_maps_ns_nameserver_field(self):
        data = {
            "domain": "example.com",
            "records": [
                {
                    "name": "example.com",
                    "type": "NS",
                    "nameserver": "ns1.example.com",
                }
            ],
        }

        result = parse_dns_result(data)

        assert len(result.records) == 1
        assert result.records[0].type == "NS"
        assert result.records[0].value == "ns1.example.com"

    def test_dns_result_maps_mx_exchange_field(self):
        data = {
            "domain": "example.com",
            "records": [
                {
                    "name": "example.com",
                    "type": "MX",
                    "exchange": "mail.example.com",
                    "priority": 10,
                }
            ],
        }

        result = parse_dns_result(data)

        assert len(result.records) == 1
        assert result.records[0].type == "MX"
        assert result.records[0].value == "mail.example.com"
        assert result.records[0].priority == 10

    def test_format_api_params_serializes_nested_dicts_as_json(self):
        formatted = format_api_params({"payload": [{"a": 1}, {"b": 2}]})
        assert '"' in formatted["payload"]
        assert "'" not in formatted["payload"]
        assert json.loads(formatted["payload"]) == [{"a": 1}, {"b": 2}]

    def test_cli_email_alert_default_is_true(self):
        parser = create_parser()
        args = parser.parse_args([])
        assert args.email_alert is True

    def test_cli_no_email_alert_flag_disables(self):
        parser = create_parser()
        args = parser.parse_args(["--no-email-alert"])
        assert args.email_alert is False


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
