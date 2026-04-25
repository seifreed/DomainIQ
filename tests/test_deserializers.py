"""Unit tests for API response deserializers."""

from __future__ import annotations

import base64
from datetime import datetime

import pytest

from domainiq.deserializers import (
    parse_domain_category,
    parse_domain_report,
    parse_domain_snapshot,
    parse_ip_report_result,
    parse_monitor_action_result,
    parse_monitor_report,
    parse_reverse_search_result,
    parse_search_result,
)
from domainiq.exceptions import DomainIQAPIError
from domainiq.parsers import parse_bool


class TestDomainSnapshotDeserializer:
    def test_decodes_valid_raw_snapshot_data(self) -> None:
        raw = base64.b64encode(b"image-bytes").decode("ascii")

        result = parse_domain_snapshot(
            {
                "result": {
                    "domain": "example.com",
                    "screenshot_url": "https://cdn.example/s.png",
                    "raw_data": raw,
                    "timestamp": "2024-01-01",
                    "width": 640,
                    "height": 480,
                }
            }
        )

        assert result.domain == "example.com"
        assert result.raw_data == b"image-bytes"
        assert result.width == 640

    def test_invalid_raw_snapshot_data_is_ignored(self) -> None:
        result = parse_domain_snapshot(
            {"domain": "example.com", "raw": "not-valid-base64!!!"}
        )

        assert result.raw_data is None

    def test_raw_snapshot_data_with_non_base64_suffix_is_ignored(self) -> None:
        result = parse_domain_snapshot(
            {"domain": "example.com", "raw": "aGVsbG8=!!!!"}
        )

        assert result.raw_data is None

    def test_numeric_timestamp_is_parsed(self) -> None:
        result = parse_domain_snapshot(
            {"domain": "example.com", "timestamp": 1704067200}
        )

        assert isinstance(result.timestamp, datetime)


class TestDomainReportDeserializer:
    def test_parses_nested_whois_dns_and_optional_fields(self) -> None:
        result = parse_domain_report(
            {
                "result": {
                    "domain": "example.com",
                    "whois": {
                        "domain": "example.com",
                        "registrar": "Example Registrar",
                        "emails": "admin@example.com",
                    },
                    "dns": {
                        "domain": "example.com",
                        "records": [
                            {
                                "host": "example.com",
                                "type": "A",
                                "ip": "192.0.2.1",
                                "ttl": 300,
                            }
                        ],
                    },
                    "categories": ["security"],
                    "related_domains": ["example.net"],
                    "risk_score": 10,
                }
            }
        )

        assert result.domain == "example.com"
        assert result.whois_data is not None
        assert result.whois_data.registrant_email == ["admin@example.com"]
        assert result.dns_data is not None
        assert result.dns_data.records[0].value == "192.0.2.1"
        assert result.categories == ["security"]

    def test_domain_category_splits_comma_separated_categories(self) -> None:
        result = parse_domain_category(
            {"domain": "example.com", "categories": "Business,Technology"}
        )

        assert result.categories == ["Business", "Technology"]

    def test_domain_category_strips_and_filters_categories(self) -> None:
        string_result = parse_domain_category(
            {"domain": "example.com", "categories": " Business, Technology, "}
        )
        list_result = parse_domain_category(
            {
                "domain": "example.com",
                "categories": [" Business ", "", None, "Technology"],
            }
        )

        assert string_result.categories == ["Business", "Technology"]
        assert list_result.categories == ["Business", "Technology"]

    def test_domain_report_splits_comma_separated_categories(self) -> None:
        result = parse_domain_report(
            {"domain": "example.com", "categories": "Security,Malware"}
        )

        assert result.categories == ["Security", "Malware"]

    def test_domain_report_splits_comma_separated_related_domains(self) -> None:
        result = parse_domain_report(
            {
                "domain": "example.com",
                "related_domains": "example.net, example.org, ",
            }
        )

        assert result.related_domains == ["example.net", "example.org"]

    def test_domain_report_strips_and_filters_related_domains(self) -> None:
        result = parse_domain_report(
            {
                "domain": "example.com",
                "related_domains": [" example.net ", "", None, "example.org"],
            }
        )

        assert result.related_domains == ["example.net", "example.org"]

    def test_domain_report_missing_related_domains_stays_none(self) -> None:
        result = parse_domain_report({"domain": "example.com"})

        assert result.related_domains is None


class TestMonitorDeserializer:
    def test_parse_bool_strips_surrounding_whitespace(self) -> None:
        assert parse_bool(" true ") is True
        assert parse_bool(" yes ") is True
        assert parse_bool(" 1 ") is True
        assert parse_bool(" false ") is False

    def test_numeric_created_date_is_parsed(self) -> None:
        result = parse_monitor_report(
            {"name": "brand-watch", "created_date": 1704067200}
        )

        assert isinstance(result.created_date, datetime)

    def test_parses_monitor_report_with_items_and_boolean_variants(self) -> None:
        result = parse_monitor_report(
            {
                "id": 42,
                "name": "brand-watch",
                "type": "domain",
                "email_alerts": "yes",
                "items": [
                    {
                        "id": 7,
                        "type": "domain",
                        "value": "example.com",
                        "enabled": 0,
                        "typos_enabled": "true",
                        "typo_strength": 10,
                    }
                ],
            }
        )

        assert result.id == 42
        assert result.email_alerts is True
        assert result.items is not None
        assert result.items[0].enabled is False
        assert result.items[0].typos_enabled is True

    def test_parses_monitor_report_with_padded_boolean_strings(self) -> None:
        result = parse_monitor_report(
            {
                "name": "brand-watch",
                "email_alerts": " true ",
                "items": [
                    {
                        "value": "example.com",
                        "enabled": " true ",
                        "typos_enabled": " yes ",
                    }
                ],
            }
        )

        assert result.email_alerts is True
        assert result.items is not None
        assert result.items[0].enabled is True
        assert result.items[0].typos_enabled is True

    def test_parses_monitor_report_with_single_item_dict(self) -> None:
        result = parse_monitor_report(
            {
                "id": 42,
                "name": "brand-watch",
                "items": {"id": 7, "type": "domain", "value": "example.com"},
            }
        )

        assert result.items is not None
        assert len(result.items) == 1
        assert result.items[0].id == 7
        assert result.items[0].type == "domain"
        assert result.items[0].value == "example.com"

    def test_parse_monitor_report_skips_non_dict_items(self) -> None:
        result = parse_monitor_report(
            {
                "id": 42,
                "name": "brand-watch",
                "items": [
                    {"id": 7, "type": "domain", "value": "example.com"},
                    "bad-item",
                    None,
                ],
            }
        )

        assert result.items is not None
        assert len(result.items) == 1
        assert result.items[0].id == 7
        assert result.items[0].type == "domain"
        assert result.items[0].value == "example.com"

    def test_passthrough_result_casts(self) -> None:
        action = {"ok": True}
        search = {"results": []}
        reverse = {"matches": []}

        assert parse_monitor_action_result(action) is action
        assert parse_search_result(search) is search
        assert parse_reverse_search_result(reverse) is reverse


class TestIpReportDeserializer:
    def test_accepts_json_dict(self) -> None:
        raw = {"ip": "192.0.2.1"}

        assert parse_ip_report_result(raw) is raw

    def test_rejects_non_dict_response(self) -> None:
        with pytest.raises(DomainIQAPIError, match="Expected JSON dict"):
            parse_ip_report_result([{"ip": "192.0.2.1"}])
