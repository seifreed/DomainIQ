"""Regression tests for parser edge cases and logic bugs."""

from __future__ import annotations

from datetime import datetime

import pytest

from domainiq.exceptions import DomainIQAPIError
from domainiq.parsers import (
    _normalize_email_values,
    parse_bool,
    parse_nameservers,
    parse_statuses,
    try_parse_date,
    unwrap_api_envelope,
)


class TestTryParseDateEdgeCases:
    def test_rejects_non_numeric_dot_string(self) -> None:
        """Regression: strings like '12.34' were wrongly parsed as timestamps."""
        assert try_parse_date("12.34") is None
        assert try_parse_date("abc.def") is None
        assert try_parse_date("1.2.3") is None

    def test_rejects_date_string_with_trailing_dot(self) -> None:
        """Strings that look like dates with dots should not be timestamps."""
        assert try_parse_date("2024.01.01") is None

    def test_accepts_valid_float_timestamp(self) -> None:
        parsed = try_parse_date("1704067200.5")
        assert isinstance(parsed, datetime)

    def test_rejects_short_float_timestamp_regression(self) -> None:
        """Regression: 9-digit float like '12345678.9' passed the >=10 guard."""
        assert try_parse_date("12345678.9") is None
        assert try_parse_date("123456789.0") is not None


class TestParseStatusesEdgeCases:
    def test_rejects_zero_and_false_in_list(self) -> None:
        """Regression: 0 and False were converted to '0' and 'False' strings."""
        assert parse_statuses([0, False, "active"]) == ["active"]
        assert parse_statuses([0]) == []
        assert parse_statuses([False]) == []

    def test_rejects_zero_and_false_scalar(self) -> None:
        assert parse_statuses(0) == []
        assert parse_statuses(False) == []


class TestParseEmailsEdgeCases:
    def test_rejects_zero_and_false_in_list_regression(self) -> None:
        """Regression: 0 and False in email lists produced '0' and 'False'."""
        assert _normalize_email_values([0, False, "admin@example.com"]) == [
            "admin@example.com"
        ]
        assert _normalize_email_values([0]) is None
        assert _normalize_email_values([False]) is None


class TestParseBoolEdgeCases:
    def test_string_two_uses_default(self) -> None:
        """parse_bool('2') returns default (False), parse_bool(2) returns True."""
        assert parse_bool("2") is False
        assert parse_bool(2) is True

    def test_string_zero_is_falsy_regression(self) -> None:
        """Regression: parse_bool('0') returned default instead of False."""
        assert parse_bool("0") is False
        assert parse_bool("0", default=True) is False
        assert parse_bool(0) is False


class TestUnwrapApiEnvelopeEdgeCases:
    def test_non_dict_input_raises_clean_error_regression(self) -> None:
        """Regression: list input caused AttributeError instead of clean error."""
        with pytest.raises(DomainIQAPIError, match="Expected JSON dict"):
            unwrap_api_envelope([{"result": "ok"}], ("domain",))  # type: ignore[arg-type]

    def test_scalar_input_raises_clean_error_regression(self) -> None:
        """Regression: scalar string input caused AttributeError."""
        with pytest.raises(DomainIQAPIError, match="Expected JSON dict"):
            unwrap_api_envelope("invalid", ("domain",))  # type: ignore[arg-type]


class TestParseNameserversEdgeCases:
    def test_rejects_numeric_zero(self) -> None:
        """Regression: numeric 0 was accepted as a valid nameserver '0'."""
        assert parse_nameservers({"nameservers": [0]}) == []
        assert parse_nameservers({"nameservers": [False]}) == []

    def test_rejects_numeric_zero_in_dict(self) -> None:
        assert parse_nameservers({"nameservers": [{"host": 0}]}) == []

    def test_accepts_normal_values(self) -> None:
        assert parse_nameservers({"nameservers": ["ns1.example.com"]}) == [
            "ns1.example.com"
        ]

    def test_accepts_tuple_values_regression(self) -> None:
        """Regression: tuple values were silently discarded."""
        assert parse_nameservers(
            {"nameservers": ("ns1.example.com", "ns2.example.com")}
        ) == ["ns1.example.com", "ns2.example.com"]
