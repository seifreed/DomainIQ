"""Unit tests for API parameter formatting."""

from __future__ import annotations

import json

from domainiq.constants import API_BOOL_FALSE, API_BOOL_TRUE
from domainiq.formatters import format_api_params, sanitize_params_for_log
from domainiq.models import DNSRecordType


class TestSanitizeParamsForLog:
    def test_masks_api_key_without_mutating_original(self) -> None:
        params = {"key": "secret", "service": "whois"}

        sanitized = sanitize_params_for_log(params)

        assert sanitized == {"key": "********", "service": "whois"}
        assert params == {"key": "secret", "service": "whois"}

    def test_returns_copy_when_key_absent(self) -> None:
        params = {"service": "dns"}

        sanitized = sanitize_params_for_log(params)

        assert sanitized == params
        assert sanitized is not params


class TestFormatApiParams:
    def test_formats_scalar_values(self) -> None:
        formatted = format_api_params(
            {
                "enabled": True,
                "disabled": False,
                "record": DNSRecordType.A,
                "payload": {"nested": "value"},
                "empty": None,
                "count": 3,
            }
        )

        assert formatted["enabled"] == API_BOOL_TRUE
        assert formatted["disabled"] == API_BOOL_FALSE
        assert formatted["record"] == "A"
        assert json.loads(formatted["payload"]) == {"nested": "value"}
        assert formatted["count"] == "3"
        assert "empty" not in formatted

    def test_formats_simple_lists_and_tuples(self) -> None:
        formatted = format_api_params(
            {
                "types": ["A", DNSRecordType.MX],
                "conditions": ("contains", "begins"),
            }
        )

        assert formatted["types"] == "A,MX"
        assert formatted["conditions"] == "contains,begins"

    def test_formats_bulk_domain_values_with_double_arrow_separator(self) -> None:
        formatted = format_api_params({"domains": ["example.com", "example.net"]})

        assert formatted["domains"] == "example.com>>example.net"

    def test_formats_nested_bulk_values_as_json_segments(self) -> None:
        formatted = format_api_params(
            {"domains": [{"domain": "example.com"}, "example.net"]}
        )

        assert formatted["domains"] == '{"domain": "example.com"}>>example.net'

    def test_formats_nested_lists_as_json(self) -> None:
        formatted = format_api_params({"payload": [{"a": 1}, {"b": 2}]})

        assert json.loads(formatted["payload"]) == [{"a": 1}, {"b": 2}]
