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

    def test_set_is_formatted_as_comma_separated_list_regression(self) -> None:
        formatted = format_api_params({"types": {"A", "MX"}})

        assert formatted["types"] in ("A,MX", "MX,A")

    def test_formats_bytes_as_utf8_string_regression(self) -> None:
        formatted = format_api_params({"domain": b"example.com"})

        assert formatted["domain"] == "example.com"

    def test_formats_invalid_utf8_bytes_without_crashing_regression(self) -> None:
        formatted = format_api_params({"domain": b"\xff\xfe"})

        assert "\ufffd" in formatted["domain"]

    def test_booleans_in_list_serialize_as_api_constants_regression(self) -> None:
        """Regression: bools in lists were stringified as 'True'/'False'."""
        formatted = format_api_params({"flags": [True, False]})

        assert formatted["flags"] == f"{API_BOOL_TRUE},{API_BOOL_FALSE}"

    def test_set_values_have_deterministic_ordering_regression(self) -> None:
        """Regression: set iteration produced non-deterministic parameter strings."""
        formatted = format_api_params({"types": {"A", "MX", "TXT"}})

        assert formatted["types"] == "A,MX,TXT"

    def test_bytes_in_list_are_decoded_regression(self) -> None:
        """Regression: bytes inside lists were stringified as "b'...'"."""
        formatted = format_api_params({"types": [b"A", b"MX"]})

        assert formatted["types"] == "A,MX"

    def test_bytes_in_set_are_decoded_regression(self) -> None:
        """Regression: bytes inside sets were stringified as "b'...'"."""
        formatted = format_api_params({"types": {b"A"}})

        assert formatted["types"] == "A"

    def test_empty_set_is_omitted_regression(self) -> None:
        """Regression: empty set produced empty string parameter."""
        formatted = format_api_params({"types": set(), "domain": "example.com"})

        assert "types" not in formatted
        assert formatted["domain"] == "example.com"

    def test_empty_list_is_omitted_regression(self) -> None:
        formatted = format_api_params({"types": [], "domain": "example.com"})

        assert "types" not in formatted
        assert formatted["domain"] == "example.com"

    def test_nested_dict_bool_formatted_as_api_constant_regression(self) -> None:
        """Regression: nested dicts in lists bypassed bool formatting."""
        formatted = format_api_params(
            {"payload": [{"enabled": True, "disabled": False}]}
        )
        payload = json.loads(formatted["payload"])
        assert payload == [{"enabled": API_BOOL_TRUE, "disabled": API_BOOL_FALSE}]

    def test_sanitize_masks_nested_api_key_regression(self) -> None:
        """Regression: sanitize_params_for_log only masked top-level 'key'."""
        params = {"nested": {"api_key": "secret"}, "key": "top"}
        sanitized = sanitize_params_for_log(params)
        assert sanitized["nested"]["api_key"] == "********"
        assert sanitized["key"] == "********"

    def test_dict_value_preprocessed_for_json_regression(self) -> None:
        """Regression: dict values bypassed _preprocess_for_json for raw bools/Enums."""

        formatted = format_api_params(
            {"payload": {"enabled": True, "type": DNSRecordType.A}}
        )
        payload = json.loads(formatted["payload"])
        assert payload["enabled"] == API_BOOL_TRUE
        assert payload["type"] == "A"

    def test_nested_set_in_list_preprocessed_regression(self) -> None:
        """Regression: set inside nested structures caused TypeError in json.dumps."""
        formatted = format_api_params({"payload": [{"flags": {True, False}}]})
        payload = json.loads(formatted["payload"])
        assert sorted(payload[0]["flags"]) == sorted([API_BOOL_TRUE, API_BOOL_FALSE])
