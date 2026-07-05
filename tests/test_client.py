"""Unit and regression tests for the synchronous DomainIQ client."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import warnings
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import TypedDict, cast

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
from domainiq.http import RequestsTransport
from domainiq.parsers import try_parse_date as _try_parse_date
from domainiq.validators import (
    _is_ip_like_domain,
    _validate_label,
    ensure_positive_int,
    validate_date_string,
    validate_domain,
    validate_email,
    validate_ipv4,
)


class _ConfigKwargs(TypedDict, total=False):
    """Config keyword arguments used when unpacking test-supplied kwargs.

    Fields mirror the real ``Config`` parameter types so that ``**`` unpacking
    of a cast dict type-checks; the tests deliberately feed invalid *values*
    (never invalid keys) through the cast to exercise validation errors.
    """

    base_url: str
    timeout: float | None
    max_retries: int | None
    retry_delay: int | None
    config_file: str | Path | None
    connector_limit: int | None
    connector_limit_per_host: int | None


class TestDomainIQClientUnit:
    """Unit tests that don't require API access."""

    def test_client_initialization_with_kwargs(self) -> None:
        """Test client initialization with keyword arguments."""
        client = DomainIQClient(api_key="test_key_456", timeout=60)
        assert client.config.api_key == "test_key_456"
        assert client.config.timeout == 60
        assert client.config.base_url == "https://www.domainiq.com/api"
        client.close()

    def test_whois_lookup_missing_parameters(self) -> None:
        """Test WHOIS lookup with missing parameters."""
        client = DomainIQClient(api_key="test_key")

        with pytest.raises(DomainIQError, match="Either domain or ip") as exc_info:
            client.whois_lookup()

        assert "Either domain or ip must be provided" in str(exc_info.value)
        client.close()

    def test_context_manager(self) -> None:
        """Test client as context manager."""
        with DomainIQClient(api_key="test_key") as client:
            assert client.config.api_key == "test_key"
            assert hasattr(client, "_transport")

    def test_del_noops_without_transport(self) -> None:
        client = DomainIQClient.__new__(DomainIQClient)
        client.__del__()

    def test_del_noops_when_transport_is_closed(self) -> None:
        client = DomainIQClient.__new__(DomainIQClient)
        client._transport = RequestsTransport()
        client._transport.close()

        with warnings.catch_warnings(record=True) as caught:
            client.__del__()

        assert caught == []

    def test_del_warns_when_transport_is_still_open(self) -> None:
        client = DomainIQClient.__new__(DomainIQClient)
        client._transport = RequestsTransport()

        with pytest.warns(ResourceWarning, match="Unclosed DomainIQClient"):
            client.__del__()

        client._transport.close()

    def test_del_safe_during_interpreter_shutdown_regression(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression: __del__ raised AttributeError when warnings module was None."""
        client = DomainIQClient.__new__(DomainIQClient)
        client._transport = RequestsTransport()
        # Simulate interpreter shutdown: the warnings machinery is torn down,
        # so warnings.warn resolves to None inside __del__.
        monkeypatch.setattr(warnings, "warn", None)

        client.__del__()  # must not raise even though warnings.warn is None

        assert client._transport.is_open is False


class TestConfigUnit:
    """Unit tests for Config."""

    def test_config_initialization(self) -> None:
        config = Config(api_key="test_key", timeout=60)
        assert config.api_key == "test_key"
        assert config.timeout == 60
        assert config.base_url == "https://www.domainiq.com/api"

    def test_config_validation_invalid_timeout(self) -> None:
        with pytest.raises(DomainIQConfigurationError) as exc_info:
            Config(api_key="test_key", timeout=-1)

        assert "Timeout must be positive" in str(exc_info.value)

    @pytest.mark.parametrize("timeout", ["abc", True, float("nan"), float("inf")])
    def test_config_validation_rejects_invalid_timeout_types(
        self, timeout: object
    ) -> None:
        with pytest.raises(
            DomainIQConfigurationError, match="Timeout must be a finite number"
        ):
            Config(api_key="test_key", timeout=cast("float", timeout))

    @pytest.mark.parametrize(
        ("kwargs", "message"),
        [
            ({"max_retries": True}, "Max retries must be an integer"),
            ({"max_retries": 1.5}, "Max retries must be an integer"),
            ({"max_retries": "3"}, "Max retries must be an integer"),
            ({"retry_delay": True}, "Retry delay must be an integer"),
            ({"retry_delay": 1.5}, "Retry delay must be an integer"),
            ({"retry_delay": "3"}, "Retry delay must be an integer"),
            ({"connector_limit": True}, "Connector limit must be an integer"),
            ({"connector_limit": 1.5}, "Connector limit must be an integer"),
            ({"connector_limit": "3"}, "Connector limit must be an integer"),
            (
                {"connector_limit_per_host": True},
                "Connector limit per host must be an integer",
            ),
            (
                {"connector_limit_per_host": 1.5},
                "Connector limit per host must be an integer",
            ),
            (
                {"connector_limit_per_host": "3"},
                "Connector limit per host must be an integer",
            ),
        ],
    )
    def test_config_validation_rejects_invalid_integer_types(
        self, kwargs: dict[str, object], message: str
    ) -> None:
        with pytest.raises(DomainIQConfigurationError, match=message):
            Config(api_key="test_key", **cast("_ConfigKwargs", kwargs))

    def test_client_initialization_reports_invalid_numeric_config(self) -> None:
        with pytest.raises(
            DomainIQConfigurationError, match="Timeout must be a finite number"
        ):
            DomainIQClient(api_key="test_key", timeout=cast("float", "abc"))

    def test_config_validation_missing_api_key(self) -> None:
        config = Config(api_key="test_key")
        config.api_key = ""

        with pytest.raises(DomainIQConfigurationError) as exc_info:
            config.validate()

        assert "API key is required" in str(exc_info.value)

    def test_config_validation_rejects_whitespace_only_api_key(self) -> None:
        config = Config(api_key="test_key")
        config.api_key = "   "

        with pytest.raises(DomainIQConfigurationError) as exc_info:
            config.validate()

        assert "API key is required" in str(exc_info.value)

    def test_config_validation_rejects_whitespace_only_base_url_regression(
        self,
    ) -> None:
        """Regression: whitespace-only base_url passed validation.

        A blank base_url previously slipped through and produced malformed requests.
        """
        config = Config(api_key="test_key")
        config.base_url = "   "

        with pytest.raises(DomainIQConfigurationError) as exc_info:
            config.validate()

        assert "Base URL is required" in str(exc_info.value)

    def test_config_no_key_anywhere(self, tmp_path: Path) -> None:
        with pytest.raises(DomainIQError) as exc_info:
            Config(env={}, config_file=str(tmp_path / "missing"))

        assert "No API key found" in str(exc_info.value)

    def test_config_from_environment(self, tmp_path: Path) -> None:
        config = Config(
            env={"DOMAINIQ_API_KEY": "env_key_123"},
            config_file=str(tmp_path / "missing"),
        )
        assert config.api_key == "env_key_123"

    def test_config_from_environment_strips_whitespace_regression(
        self, tmp_path: Path
    ) -> None:
        """Regression: env var value was not stripped, causing auth failures."""
        config = Config(
            env={"DOMAINIQ_API_KEY": "  env_key_123  \n"},
            config_file=str(tmp_path / "missing"),
        )
        assert config.api_key == "env_key_123"

    def test_config_module_import_ignores_invalid_numeric_environment(self) -> None:
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
    def test_invalid_numeric_environment_values_raise_config_error(
        self, env_name: str
    ) -> None:
        with pytest.raises(DomainIQConfigurationError, match=env_name):
            Config(api_key="test_key", env={env_name: "abc"})

    def test_config_uses_numeric_environment_values(self) -> None:
        config = Config(
            api_key="test_key",
            env={
                "DOMAINIQ_TIMEOUT": "12.5",
                "DOMAINIQ_MAX_RETRIES": "5",
                "DOMAINIQ_RETRY_DELAY": "2",
                "DOMAINIQ_CONNECTOR_LIMIT": "11",
                "DOMAINIQ_CONNECTOR_LIMIT_PER_HOST": "3",
            },
        )

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
        env_name: str,
        kwarg: str,
        value: float,
    ) -> None:
        config = Config(
            api_key="test_key",
            env={env_name: "abc"},
            **cast("_ConfigKwargs", {kwarg: value}),
        )

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
    def test_config_validation_invalid_connector_limits(
        self, kwargs: dict[str, int], message: str
    ) -> None:
        with pytest.raises(DomainIQConfigurationError, match=message):
            Config(api_key="test_key", **cast("_ConfigKwargs", kwargs))

    def test_set_config_path_reloads_key_from_new_file(self, tmp_path: Path) -> None:
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

    def test_validate_domain_valid(self) -> None:
        assert validate_domain("example.com")
        assert validate_domain("subdomain.example.com")
        assert validate_domain("test-domain.co.uk")

    def test_validate_domain_invalid(self) -> None:
        assert not validate_domain("")
        assert not validate_domain("invalid")
        assert not validate_domain(".example.com")
        assert not validate_domain("example.com.")
        assert not validate_domain("example..com")
        assert not validate_domain("example\n.com")
        assert not validate_domain("example.com\n")
        assert not validate_domain("192.0.2.1")
        assert not validate_domain("a" * 64 + ".com")

    def test_validate_ipv4_valid(self) -> None:
        assert validate_ipv4("192.168.1.1")
        assert validate_ipv4("8.8.8.8")
        assert validate_ipv4("127.0.0.1")

    def test_validate_ipv4_invalid(self) -> None:
        assert not validate_ipv4("")
        assert not validate_ipv4("192.168.1")
        assert not validate_ipv4("192.168.1.256")
        assert not validate_ipv4("not.an.ip.address")

    def test_validate_email_valid(self) -> None:
        assert validate_email("user@example.com")
        assert validate_email("test.email@domain.co.uk")

    def test_validate_email_invalid(self) -> None:
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

    def test_validate_date_string_valid(self) -> None:
        assert validate_date_string("2023-01-01") == "2023-01-01"
        assert validate_date_string("2024-12-31") == "2024-12-31"

    def test_validate_date_string_invalid(self) -> None:
        with pytest.raises(DomainIQValidationError):
            validate_date_string("")
        with pytest.raises(DomainIQValidationError):
            validate_date_string("not-a-date")
        with pytest.raises(DomainIQValidationError):
            validate_date_string("2023/01/01")
        with pytest.raises(DomainIQValidationError):
            validate_date_string("23-01-01")

    def test_validate_date_string_strips_whitespace_regression(self) -> None:
        assert validate_date_string(" 2023-01-01 ") == "2023-01-01"
        assert validate_date_string("2024-12-31\t") == "2024-12-31"

    @pytest.mark.parametrize("value", [True, False, 1.5, "3"])
    def test_ensure_positive_int_rejects_non_int_values(self, value: object) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            ensure_positive_int("report_id", value)

        assert exc_info.value.param_name == "report_id"

    def test_ensure_positive_int_accepts_whole_number_float(self) -> None:
        """Regression: 10.0 was rejected because isinstance(10.0, int) is False."""
        assert ensure_positive_int("report_id", 10.0) == 10

    def test_ensure_positive_int_rejects_non_whole_float(self) -> None:
        with pytest.raises(DomainIQValidationError):
            ensure_positive_int("report_id", 10.5)

    def test_ensure_positive_int_accepts_integral_types_regression(self) -> None:
        assert ensure_positive_int("report_id", Decimal(5)) == 5
        assert ensure_positive_int("report_id", Decimal("5.0")) == 5

    def test_ensure_positive_int_rejects_decimal_nan_regression(self) -> None:
        """Regression: Decimal('NaN') crashed with unhandled ValueError."""
        with pytest.raises(DomainIQValidationError, match="must be a positive integer"):
            ensure_positive_int("report_id", Decimal("NaN"))

    def test_ensure_positive_int_rejects_decimal_infinity_regression(self) -> None:
        """Regression: Decimal('Infinity') crashed with unhandled ValueError."""
        with pytest.raises(DomainIQValidationError, match="must be a positive integer"):
            ensure_positive_int("report_id", Decimal("Infinity"))

    def test_validate_date_string_raises_for_non_string_input(self) -> None:
        """Regression: passing an int or datetime raises DomainIQValidationError."""
        with pytest.raises(DomainIQValidationError):
            validate_date_string(cast("str", 123))
        with pytest.raises(DomainIQValidationError):
            validate_date_string(cast("str", datetime.now(tz=UTC)))


class TestModelsUnit:
    """Unit tests for data models."""

    def test_parse_helpers_are_not_root_exports(self) -> None:
        assert "parse_whois_result" not in domainiq.__all__
        assert not hasattr(domainiq, "parse_whois_result")

    def test_whois_result_from_dict(self) -> None:
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

    def test_dns_result_from_dict(self) -> None:
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

    def test_try_parse_date_rejects_short_numeric_string(self) -> None:
        assert _try_parse_date("2023") is None
        assert _try_parse_date("123") is None

    def test_try_parse_date_accepts_plausible_timestamp(self) -> None:
        parsed = _try_parse_date("1700000000")
        assert isinstance(parsed, datetime)
        assert parsed.year >= 2020

    def test_try_parse_date_accepts_float_timestamp(self) -> None:
        parsed = _try_parse_date("1700000000.5")
        assert isinstance(parsed, datetime)

    def test_try_parse_date_accepts_numeric_timestamp(self) -> None:
        expected = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC).replace(tzinfo=None)

        assert _try_parse_date(1704067200) == expected
        assert _try_parse_date("1704067200") == expected

    def test_try_parse_date_accepts_numeric_float_timestamp(self) -> None:
        expected = datetime(2024, 1, 1, 0, 0, 0, 500000, tzinfo=UTC).replace(
            tzinfo=None
        )

        assert _try_parse_date(1704067200.5) == expected
        assert _try_parse_date("1704067200.5") == expected

    def test_try_parse_date_timestamp_is_timezone_independent(self) -> None:
        if not hasattr(time, "tzset"):
            pytest.skip("time.tzset is unavailable on this platform")

        expected = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC).replace(tzinfo=None)
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

    def test_try_parse_date_still_parses_iso(self) -> None:
        parsed = _try_parse_date("2023-01-01T00:00:00")
        assert isinstance(parsed, datetime)
        assert parsed.year == 2023

    def test_try_parse_date_normalizes_aware_iso_to_naive_utc(self) -> None:
        expected = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC).replace(tzinfo=None)

        zulu = _try_parse_date("2024-01-01T00:00:00Z")
        offset = _try_parse_date("2024-01-01T01:00:00+01:00")

        assert zulu == expected
        assert offset == expected
        assert zulu is not None
        assert offset is not None
        assert zulu.tzinfo is None
        assert offset.tzinfo is None

    def test_try_parse_date_strips_surrounding_whitespace(self) -> None:
        parsed = _try_parse_date(" 2024-01-01 ")
        assert isinstance(parsed, datetime)
        assert parsed.year == 2024
        assert parsed.month == 1
        assert parsed.day == 1

    def test_try_parse_date_strips_surrounding_whitespace_for_iso_datetime(
        self,
    ) -> None:
        parsed = _try_parse_date(" 2023-01-01T00:00:00 ")
        assert isinstance(parsed, datetime)
        assert parsed.year == 2023

    def test_try_parse_date_whitespace_only_returns_none(self) -> None:
        assert _try_parse_date("   ") is None

    def test_whois_creation_date_strips_surrounding_whitespace(self) -> None:
        result = parse_whois_result(
            {"domain": "example.com", "creation_date": " 2024-01-01 "}
        )
        assert result.creation_date is not None
        assert result.creation_date.year == 2024
        assert result.creation_date.month == 1
        assert result.creation_date.day == 1

    def test_whois_creation_date_accepts_numeric_timestamp(self) -> None:
        result = parse_whois_result(
            {"domain": "example.com", "creation_date": 1704067200}
        )

        assert result.creation_date == _try_parse_date("1704067200")

    @pytest.mark.parametrize("update_date", [" ", "not-a-date"])
    def test_whois_updated_date_falls_back_after_unparseable_update_date(
        self, update_date: str
    ) -> None:
        result = parse_whois_result(
            {
                "domain": "example.com",
                "update_date": update_date,
                "updated_date": "2024-01-01",
            }
        )

        assert result.updated_date == datetime(2024, 1, 1, tzinfo=UTC).replace(
            tzinfo=None
        )

    def test_whois_emails_filter_whitespace_entries(self) -> None:
        data = {
            "domain": "example.com",
            "emails": ["a@b.com", "  ", "", None, "  c@d.com "],
        }
        result = parse_whois_result(data)
        assert result.registrant_email == ["a@b.com", "c@d.com"]

    def test_whois_emails_all_empty_returns_none(self) -> None:
        data = {"domain": "example.com", "emails": ["", "  ", None]}
        result = parse_whois_result(data)
        assert result.registrant_email is None

    def test_whois_emails_empty_list_falls_back_to_registrant_email(self) -> None:
        data = {
            "domain": "example.com",
            "emails": [],
            "registrant_email": "admin@example.com",
        }
        result = parse_whois_result(data)
        assert result.registrant_email == ["admin@example.com"]

    def test_whois_emails_empty_string_falls_back_to_registrant_email(self) -> None:
        data = {
            "domain": "example.com",
            "emails": "",
            "registrant_email": "admin@example.com",
        }
        result = parse_whois_result(data)
        assert result.registrant_email == ["admin@example.com"]

    def test_whois_emails_normalized_empty_list_falls_back_to_registrant_email(
        self,
    ) -> None:
        data = {
            "domain": "example.com",
            "emails": ["", "  ", None],
            "registrant_email": "admin@example.com",
        }
        result = parse_whois_result(data)
        assert result.registrant_email == ["admin@example.com"]

    def test_whois_emails_non_empty_list_takes_priority_over_registrant_email(
        self,
    ) -> None:
        data = {
            "domain": "example.com",
            "emails": ["primary@example.com"],
            "registrant_email": "admin@example.com",
        }
        result = parse_whois_result(data)
        assert result.registrant_email == ["primary@example.com"]

    def test_whois_statuses_filter_empty_comma_entries(self) -> None:
        data = {"domain": "example.com", "status": "active, "}
        result = parse_whois_result(data)
        assert result.status == ["active"]

    def test_whois_statuses_strip_and_filter_list_entries(self) -> None:
        data = {
            "domain": "example.com",
            "status": [" active ", " ", None, "clientHold"],
        }
        result = parse_whois_result(data)
        assert result.status == ["active", "clientHold"]

    def test_whois_empty_status_string_returns_empty_list(self) -> None:
        data = {"domain": "example.com", "status": " "}
        result = parse_whois_result(data)
        assert result.status == []

    def test_whois_nameservers_tolerate_gaps(self) -> None:
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

    def test_whois_nameservers_empty_indexed_values_fall_back_to_nameservers(
        self,
    ) -> None:
        data = {
            "domain": "example.com",
            "ns_1": "",
            "nameservers": ["ns1.example.com"],
        }
        result = parse_whois_result(data)
        assert result.nameservers == ["ns1.example.com"]

    def test_whois_nameservers_accept_single_host_dict(self) -> None:
        data = {
            "domain": "example.com",
            "nameservers": {"host": "ns1.example.com"},
        }
        result = parse_whois_result(data)
        assert result.nameservers == ["ns1.example.com"]

    def test_whois_nameservers_accept_list_of_host_dicts(self) -> None:
        data = {
            "domain": "example.com",
            "nameservers": [{"host": "ns1.example.com"}],
        }
        result = parse_whois_result(data)
        assert result.nameservers == ["ns1.example.com"]

    def test_whois_nameservers_strip_and_filter_empty_values(self) -> None:
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

    def test_whois_nameservers_split_comma_separated_string(self) -> None:
        data = {
            "domain": "example.com",
            "nameservers": "ns1.example.com, ns2.example.com",
        }
        result = parse_whois_result(data)
        assert result.nameservers == ["ns1.example.com", "ns2.example.com"]

    def test_whois_nameservers_whitespace_string_returns_empty_list(self) -> None:
        data = {"domain": "example.com", "nameservers": " "}
        result = parse_whois_result(data)
        assert result.nameservers == []

    def test_validate_ipv4_rejects_signed_octets(self) -> None:
        assert not validate_ipv4("-0.0.0.0")
        assert not validate_ipv4("+1.2.3.4")
        assert not validate_ipv4("1.-1.0.0")
        assert not validate_ipv4("1.+1.0.0")

    def test_validate_ipv4_rejects_empty_octet(self) -> None:
        assert not validate_ipv4("1..2.3")
        assert not validate_ipv4(".1.2.3")

    def test_is_ip_like_domain_rejects_invalid_dotted_quad(self) -> None:
        assert not _is_ip_like_domain("999.999.999.999")
        assert not _is_ip_like_domain("256.1.2.3")

    def test_validate_label_rejects_invalid_unicode(self) -> None:
        assert not _validate_label("hello world")
        assert not _validate_label("test\x00")
        assert not _validate_label("test\n")

    def test_dns_result_maps_aaaa_from_ip_field(self) -> None:
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

    def test_dns_result_infers_domain_from_record_name(self) -> None:
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

    def test_dns_result_accepts_single_record_dict(self) -> None:
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

    def test_dns_result_skips_non_dict_record_entries(self) -> None:
        data = {
            "domain": "example.com",
            "records": [
                {
                    "name": "example.com",
                    "type": "A",
                    "ip": "192.0.2.1",
                },
                "bad-record",
                None,
            ],
        }

        result = parse_dns_result(data)

        assert result.domain == "example.com"
        assert len(result.records) == 1
        assert result.records[0].type == "A"
        assert result.records[0].value == "192.0.2.1"

    def test_dns_result_empty_results_list_falls_back_to_records(self) -> None:
        data = {
            "results": [],
            "records": [{"name": "fallback.com", "type": "A", "ip": "192.0.2.1"}],
        }

        result = parse_dns_result(data)

        assert result.domain == "fallback.com"
        assert len(result.records) == 1
        assert result.records[0].type == "A"

    def test_dns_result_prefers_soa_record_name_for_domain(self) -> None:
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

    def test_dns_result_maps_soa_mname_field(self) -> None:
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

    def test_dns_result_maps_ptr_ptrdname_field(self) -> None:
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

    def test_dns_result_maps_ns_nameserver_field(self) -> None:
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

    def test_dns_result_maps_mx_exchange_field(self) -> None:
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

    def test_format_api_params_serializes_nested_dicts_as_json(self) -> None:
        formatted = format_api_params({"payload": [{"a": 1}, {"b": 2}]})
        assert '"' in formatted["payload"]
        assert "'" not in formatted["payload"]
        assert json.loads(formatted["payload"]) == [{"a": 1}, {"b": 2}]

    def test_format_api_params_dict_with_datetime_uses_default_str(self) -> None:
        formatted = format_api_params(
            {"filter": {"date": datetime(2024, 1, 1, tzinfo=UTC)}}
        )
        assert "2024-01-01" in formatted["filter"]

    def test_cli_email_alert_default_is_true(self) -> None:
        parser = create_parser()
        args = parser.parse_args([])
        assert args.email_alert is True

    def test_cli_no_email_alert_flag_disables(self) -> None:
        parser = create_parser()
        args = parser.parse_args(["--no-email-alert"])
        assert args.email_alert is False


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
