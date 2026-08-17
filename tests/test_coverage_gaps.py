"""Targeted branch tests for otherwise-uncovered edge paths.

These exercise error/fallback branches in the pure helper functions that the
high-level client tests do not reach on their happy paths.
"""

from __future__ import annotations

import csv
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

import pytest

from domainiq._async_concurrency import _LookupFailure
from domainiq._base_client import _assert_csv_str, _assert_json_dict_or_list
from domainiq._key_sources import _ApiKeyLoader, _FileKeySource, _ParamKeySource
from domainiq._params.bulk import build_bulk_whois_ip_params
from domainiq._params.monitor import build_add_monitor_item_params
from domainiq._params.search import (
    build_reverse_ip_params,
    build_reverse_mx_params,
    build_reverse_search_params,
)
from domainiq.client import DomainIQClient
from domainiq.config import Config
from domainiq.constants import API_FORMAT_JSON
from domainiq.deserializers import (
    _normalize_string_list,
    _to_float,
    _to_int,
    parse_dns_result,
)
from domainiq.exceptions import (
    DomainIQAPIError,
    DomainIQConfigurationError,
    DomainIQError,
    DomainIQValidationError,
)
from domainiq.formatters import format_api_params, sanitize_params_for_log
from domainiq.models import (
    MonitorItemType,
    ReverseIpSearchType,
    ReverseMatchType,
    ReverseMxSearchType,
    ReverseSearchType,
)
from domainiq.parsers import (
    parse_bool,
    parse_nameservers,
    parse_statuses,
    try_parse_date,
)
from domainiq.request_policy import parse_response_body
from domainiq.utils import csv_to_dict_list, parse_retry_after, setup_logging
from domainiq.validators import validate_domain, validate_email, validate_ipv6

from .conftest import make_async_response, make_sync_response

if TYPE_CHECKING:
    from pathlib import Path


class TestParserBranches:
    def test_out_of_range_epoch_returns_none(self) -> None:
        assert try_parse_date(10**300) is None

    def test_strptime_format_is_parsed_as_naive_utc(self) -> None:
        expected = datetime(2020, 1, 15, tzinfo=UTC).replace(tzinfo=None)
        assert try_parse_date("15-Jan-2020") == expected

    def test_unsupported_type_returns_none(self) -> None:
        assert try_parse_date([1, 2]) is None

    def test_parse_bool_nonzero_int_is_true(self) -> None:
        assert parse_bool(5) is True

    def test_parse_bool_passes_through_real_bool(self) -> None:
        assert parse_bool(True) is True
        assert parse_bool(False) is False

    def test_numeric_string_overflow_falls_through_to_none(self) -> None:
        # A huge all-digit string is treated as an epoch, overflows to None,
        # then fails every strptime format.
        assert try_parse_date("9" * 400) is None

    def test_nameserver_key_with_nondigit_suffix_is_ignored(self) -> None:
        assert parse_nameservers({"ns_x": "a.example"}) == []

    def test_nameservers_none_returns_empty(self) -> None:
        assert parse_nameservers({"nameservers": None}) == []

    def test_nameservers_unexpected_type_returns_empty(self) -> None:
        assert parse_nameservers({"nameservers": 123}) == []

    def test_parse_statuses_scalar_is_wrapped(self) -> None:
        assert parse_statuses(123) == ["123"]


class TestDeserializerNumericBranches:
    def test_to_int_rejects_bool(self) -> None:
        assert _to_int(True) is None

    def test_to_int_rejects_bad_string_and_non_numeric(self) -> None:
        assert _to_int("abc") is None
        assert _to_int([]) is None

    def test_to_int_from_string_and_float(self) -> None:
        assert _to_int("42") == 42
        assert _to_int(3.9) == 3

    def test_to_float_rejects_bool(self) -> None:
        assert _to_float(True) is None

    def test_to_float_from_int_and_bad_string(self) -> None:
        assert _to_float(5) == 5.0
        assert _to_float("abc") is None
        assert _to_float([]) is None

    def test_normalize_string_list_scalar_is_wrapped(self) -> None:
        assert _normalize_string_list(123) == ["123"]

    def test_parse_dns_result_prefers_soa_for_domain(self) -> None:
        result = parse_dns_result(
            {
                "records": [
                    {"type": "A", "host": "ignored.example", "value": "1.2.3.4"},
                    {"type": "SOA", "host": "zone.example"},
                ]
            }
        )
        assert result.domain == "zone.example"


class TestUtilsBranches:
    def test_retry_after_http_date_returns_positive_seconds(self) -> None:
        seconds = parse_retry_after({"Retry-After": "Wed, 21 Oct 2099 07:28:00 GMT"})
        assert seconds is not None
        assert seconds > 0

    def test_retry_after_garbage_returns_none(self) -> None:
        assert parse_retry_after({"Retry-After": "not-a-date"}) is None

    def test_retry_after_skips_unrelated_headers(self) -> None:
        headers = {"X-Other": "ignored", "Retry-After": "7"}
        assert parse_retry_after(headers) == 7

    def test_retry_after_naive_http_date_is_treated_as_utc(self) -> None:
        seconds = parse_retry_after({"Retry-After": "Wed, 21 Oct 2099 07:28:00"})
        assert seconds is not None
        assert seconds > 0

    def test_csv_non_string_input_raises(self) -> None:
        with pytest.raises(DomainIQError, match="Expected CSV content as string"):
            csv_to_dict_list(123)

    def test_csv_parse_error_raises(self) -> None:
        old_limit = csv.field_size_limit()
        csv.field_size_limit(4)
        try:
            with pytest.raises(DomainIQError, match="Failed to parse CSV"):
                csv_to_dict_list("header\n" + "x" * 100 + "\n")
        finally:
            csv.field_size_limit(old_limit)

    def test_setup_logging_invalid_level_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid logging level"):
            setup_logging(level="BOGUS")

    def test_setup_logging_accepts_custom_format(self) -> None:
        lib_logger = logging.getLogger("domainiq")
        saved_level = lib_logger.level
        saved_handlers = lib_logger.handlers[:]
        try:
            setup_logging(level="INFO", format_string="%(message)s")
            assert lib_logger.level == logging.INFO
        finally:
            lib_logger.handlers[:] = saved_handlers
            lib_logger.setLevel(saved_level)


class TestBaseClientAssertions:
    def test_assert_json_dict_or_list_rejects_scalar(self) -> None:
        with pytest.raises(DomainIQAPIError, match="Expected JSON dict or list"):
            _assert_json_dict_or_list("scalar")

    def test_assert_csv_str_rejects_json(self) -> None:
        with pytest.raises(DomainIQAPIError, match="Expected CSV"):
            _assert_csv_str({"a": 1})

    def test_config_plus_kwargs_is_rejected(self) -> None:
        with pytest.raises(TypeError):
            DomainIQClient(config=Config(api_key="k"), api_key="other")

    def test_unsupported_output_format_is_rejected(self) -> None:
        client = DomainIQClient(api_key="test")
        with pytest.raises(
            DomainIQConfigurationError, match="Unsupported output_format"
        ):
            client._build_request_params({}, "xml")


class TestKeySourceBranches:
    def test_file_source_unreadable_path_returns_none(self, tmp_path: Path) -> None:
        # A directory exists() is True but read_text() raises OSError.
        assert _FileKeySource(tmp_path).get_key() is None

    def test_file_source_empty_file_returns_none(self, tmp_path: Path) -> None:
        empty = tmp_path / ".domainiq"
        empty.write_text("   \n")
        assert _FileKeySource(empty).get_key() is None

    def test_loader_uses_injected_sources(self, tmp_path: Path) -> None:
        loader = _ApiKeyLoader(
            tmp_path / ".domainiq", sources=[_ParamKeySource("injected-key")]
        )
        assert loader.load(None) == "injected-key"


class TestReprs:
    def test_config_repr_masks_api_key(self) -> None:
        text = repr(Config(api_key="super-secret"))
        assert "super-secret" not in text
        assert "api_key=" in text

    def test_config_repr_without_api_key_shows_none(self) -> None:
        config = Config(api_key="k")
        config.api_key = ""
        assert "api_key=None" in repr(config)

    def test_lookup_failure_repr_includes_target_and_error(self) -> None:
        failure = _LookupFailure("example.com", ValueError("boom"))
        text = repr(failure)
        assert "example.com" in text
        assert "boom" in text


class TestValidatorBranches:
    def test_validate_ipv6_rejects_non_string(self) -> None:
        assert validate_ipv6(cast("str", 123)) is False

    def test_validate_email_rejects_multiple_at_signs(self) -> None:
        assert validate_email("a@b@c.com") is False

    def test_label_over_max_length_is_rejected(self) -> None:
        assert validate_domain("a" * 64 + ".com") is False


class TestConfigValidationBranches:
    def test_negative_max_retries_is_rejected(self) -> None:
        with pytest.raises(
            DomainIQConfigurationError, match="Max retries cannot be negative"
        ):
            Config(api_key="k", max_retries=-1)

    def test_negative_retry_delay_is_rejected(self) -> None:
        with pytest.raises(
            DomainIQConfigurationError, match="Retry delay cannot be negative"
        ):
            Config(api_key="k", retry_delay=-1)


class TestRequestPolicyBodyBranches:
    def test_parse_response_body_invalid_json_raises(self) -> None:
        response = make_sync_response(200, "not-json")
        with pytest.raises(DomainIQAPIError, match="Failed to parse JSON"):
            parse_response_body(response, API_FORMAT_JSON)


class TestParamBuilderBranches:
    def test_bulk_whois_ip_rejects_invalid_entry(self) -> None:
        with pytest.raises(DomainIQValidationError, match="Invalid domain or IP"):
            build_bulk_whois_ip_params(["not a domain!!"])

    def test_reverse_search_rejects_malformed_email(self) -> None:
        with pytest.raises(DomainIQValidationError, match="Invalid email"):
            build_reverse_search_params(
                ReverseSearchType.EMAIL, "bad@", ReverseMatchType.CONTAINS
            )


class TestFormatterBranches:
    def test_sanitize_recurses_into_lists(self) -> None:
        sanitized = sanitize_params_for_log({"items": [{"key": "secret"}]})
        assert sanitized["items"] == [{"key": "********"}]

    def test_format_api_params_decodes_nested_bytes(self) -> None:
        formatted = format_api_params({"payload": {"blob": b"hi"}})
        assert formatted["payload"] == '{"blob": "hi"}'

    def test_format_list_param_sorts_mixed_set_by_str(self) -> None:
        formatted = format_api_params({"tags": {1, "a"}})
        assert set(formatted["tags"].split(",")) == {"1", "a"}


class TestReverseAndMonitorParamBranches:
    def test_reverse_search_non_email_skips_email_validation(self) -> None:
        params = build_reverse_search_params(
            ReverseSearchType.NAME, "John Doe", ReverseMatchType.CONTAINS
        )
        assert params["type"] == "name"

    def test_reverse_ip_ip_type_validates_ip(self) -> None:
        params = build_reverse_ip_params(ReverseIpSearchType.IP, "8.8.8.8")
        assert params["type"] == "ip"

    def test_reverse_ip_domain_type_validates_domain(self) -> None:
        params = build_reverse_ip_params(ReverseIpSearchType.DOMAIN, "example.com")
        assert params["type"] == "domain"

    def test_reverse_ip_subnet_type_skips_host_validation(self) -> None:
        params = build_reverse_ip_params(ReverseIpSearchType.SUBNET, "192.0.2.0/24")
        assert params["type"] == "subnet"

    def test_reverse_mx_domain_and_ip_types(self) -> None:
        domain_params = build_reverse_mx_params(
            ReverseMxSearchType.DOMAIN, "example.com", recursive=False
        )
        ip_params = build_reverse_mx_params(
            ReverseMxSearchType.IP, "8.8.8.8", recursive=True
        )
        assert domain_params["type"] == "domain"
        assert ip_params["type"] == "ip"

    def test_add_monitor_item_validates_per_type(self) -> None:
        assert (
            build_add_monitor_item_params(1, MonitorItemType.DOMAIN, ["example.com"])[
                "type"
            ]
            == "domain"
        )
        assert (
            build_add_monitor_item_params(1, MonitorItemType.IP, ["8.8.8.8"])["type"]
            == "ip"
        )
        assert (
            build_add_monitor_item_params(1, MonitorItemType.NS, ["anything"])["type"]
            == "ns"
        )


class TestResponseCaching:
    def test_sync_response_json_is_cached(self) -> None:
        response = make_sync_response(200, '{"a": 1}')
        first = response.json()
        assert response.json() is first

    def test_async_response_json_is_cached(self) -> None:
        response = make_async_response(200, '{"a": 1}')
        first = response.json()
        assert response.json() is first


class TestDnsDomainExtractionBranch:
    def test_soa_with_empty_host_falls_through_to_next_record(self) -> None:
        result = parse_dns_result(
            {
                "records": [
                    {"type": "SOA", "host": ""},
                    {"type": "NS", "host": "ns.example"},
                ]
            }
        )
        assert result.domain == "ns.example"
