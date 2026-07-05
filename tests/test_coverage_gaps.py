"""Targeted branch tests for otherwise-uncovered edge paths.

These exercise error/fallback branches in the pure helper functions that the
high-level client tests do not reach on their happy paths.
"""

from __future__ import annotations

import csv
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from domainiq._base_client import _assert_csv_str, _assert_json_dict_or_list
from domainiq._key_sources import _ApiKeyLoader, _FileKeySource, _ParamKeySource
from domainiq.client import DomainIQClient
from domainiq.config import Config
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
)
from domainiq.parsers import (
    parse_bool,
    parse_nameservers,
    parse_statuses,
    try_parse_date,
)
from domainiq.utils import csv_to_dict_list, parse_retry_after, setup_logging

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
