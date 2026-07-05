"""Unit tests for API response deserializers."""

from __future__ import annotations

import base64
from datetime import datetime

import pytest

from domainiq.deserializers import (
    parse_dns_result,
    parse_domain_category,
    parse_domain_report,
    parse_domain_snapshot,
    parse_ip_report_result,
    parse_monitor_action_result,
    parse_monitor_report,
    parse_reverse_search_result,
    parse_search_result,
    parse_whois_result,
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
        result = parse_domain_snapshot({"domain": "example.com", "raw": "aGVsbG8=!!!!"})

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

    def test_null_item_id_defaults_to_zero_regression(self) -> None:
        """Regression: dict.get('id', 0) returns None when API sends 'id': null."""
        result = parse_monitor_report(
            {
                "name": "brand-watch",
                "items": [
                    {
                        "id": None,
                        "type": "domain",
                        "value": "example.com",
                    }
                ],
            }
        )

        assert result.items is not None
        assert result.items[0].id == 0

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
        action = {"success": True}
        search = {"results": []}
        reverse = {"domains": []}

        assert parse_monitor_action_result(action) is action
        assert parse_search_result(search) is search
        assert parse_reverse_search_result(reverse) is reverse

    def test_passthrough_results_reject_non_dict(self) -> None:
        with pytest.raises(DomainIQAPIError, match="Expected JSON dict"):
            parse_monitor_action_result([{"ok": True}])
        with pytest.raises(DomainIQAPIError, match="Expected JSON dict"):
            parse_search_result([{"results": []}])
        with pytest.raises(DomainIQAPIError, match="Expected JSON dict"):
            parse_reverse_search_result([{"matches": []}])

    def test_passthrough_results_reject_empty_dict(self) -> None:
        with pytest.raises(DomainIQAPIError, match="empty dict"):
            parse_monitor_action_result({})
        with pytest.raises(DomainIQAPIError, match="empty dict"):
            parse_search_result({})
        with pytest.raises(DomainIQAPIError, match="empty dict"):
            parse_reverse_search_result({})


class TestWhoisDeserializer:
    def test_empty_string_registrant_name_not_fallback_regression(self) -> None:
        """Regression: empty string registrant_name fell back to registrant."""
        result = parse_whois_result(
            {
                "domain": "example.com",
                "registrant_name": "",
                "registrant": "Fallback Name",
            }
        )
        assert result.registrant_name == ""

    def test_empty_string_registrant_org_not_fallback_regression(self) -> None:
        """Regression: empty string registrant_organization fell back to org."""
        result = parse_whois_result(
            {
                "domain": "example.com",
                "registrant_organization": "",
                "org": "Fallback Org",
            }
        )
        assert result.registrant_organization == ""


class TestDnsRecordValueExtraction:
    def test_falsy_value_zero_is_preserved_not_discarded(self) -> None:
        """Regression for truthiness bug: value=0 was discarded as falsy.

        _extract_record_value uses ``if val := record_data.get(key):`` which
        treats 0, False, and empty string as missing. DNS record values should
        be extracted even when they are falsy (e.g. a numeric 0).
        """
        result = parse_dns_result(
            {
                "domain": "example.com",
                "records": [{"host": "example.com", "type": "A", "ip": 0}],
            }
        )

        assert result.records[0].value == "0"

    def test_falsy_value_empty_string_is_preserved_not_discarded(self) -> None:
        """Regression for truthiness bug: empty string value discarded."""
        result = parse_dns_result(
            {
                "domain": "example.com",
                "records": [{"host": "example.com", "type": "TXT", "txt": ""}],
            }
        )

        assert result.records[0].value == ""

    def test_falsy_value_false_is_preserved_not_discarded(self) -> None:
        """Regression for truthiness bug: False value discarded."""
        result = parse_dns_result(
            {
                "domain": "example.com",
                "records": [{"host": "example.com", "type": "A", "ip": False}],
            }
        )

        assert result.records[0].value == "False"

    def test_null_results_falls_back_to_records_regression(self) -> None:
        """Regression for data loss when API returns null results with valid records."""
        result = parse_dns_result(
            {
                "results": None,
                "records": [
                    {"host": "example.com", "type": "A", "ip": "93.184.216.34"}
                ],
            }
        )

        assert len(result.records) == 1
        assert result.records[0].type == "A"
        assert result.records[0].value == "93.184.216.34"

    def test_prefers_soa_or_ns_for_domain_extraction_regression(self) -> None:
        """Regression: SOA/NS preference skipped; first record won regardless."""
        result = parse_dns_result(
            {
                "records": [
                    {"host": "a.example.com", "type": "A", "ip": "192.0.2.1"},
                    {"host": "ns1.example.com", "type": "NS"},
                ],
            }
        )

        assert result.domain == "ns1.example.com"

    def test_soa_preference_over_ns_for_domain_extraction(self) -> None:
        """SOA should be preferred over NS when both are present."""
        result = parse_dns_result(
            {
                "records": [
                    {"host": "ns1.example.com", "type": "NS"},
                    {"host": "soa.example.com", "type": "SOA"},
                ],
            }
        )

        assert result.domain == "ns1.example.com"

    def test_fallback_to_first_record_when_no_soa_or_ns(self) -> None:
        """When no SOA/NS records exist, fallback to first record's host."""
        result = parse_dns_result(
            {
                "records": [
                    {"host": "a.example.com", "type": "A", "ip": "192.0.2.1"},
                    {"host": "b.example.com", "type": "A", "ip": "192.0.2.2"},
                ],
            }
        )

        assert result.domain == "a.example.com"

    def test_record_name_defaults_to_empty_when_host_and_name_none_regression(
        self,
    ) -> None:
        """Regression: cast allowed None into DNSRecord.name which expects str."""
        result = parse_dns_result(
            {
                "records": [{"type": "A", "ip": "192.0.2.1"}],
            }
        )

        assert result.records[0].name == ""


class TestIpReportDeserializer:
    def test_accepts_json_dict(self) -> None:
        raw = {"ip": "192.0.2.1"}

        assert parse_ip_report_result(raw) is raw

    def test_rejects_non_dict_response(self) -> None:
        with pytest.raises(DomainIQAPIError, match="Expected JSON dict"):
            parse_ip_report_result([{"ip": "192.0.2.1"}])

    def test_rejects_empty_dict_response(self) -> None:
        with pytest.raises(DomainIQAPIError, match="empty dict"):
            parse_ip_report_result({})


class TestDeserializerTypeCoercion:
    """Regression: raw API strings were stored in int/float fields."""

    def test_dns_record_ttl_and_priority_coerced_from_string(self) -> None:
        result = parse_dns_result(
            {
                "domain": "example.com",
                "records": [
                    {
                        "host": "example.com",
                        "type": "A",
                        "ip": "192.0.2.1",
                        "ttl": "3600",
                        "pri": "10",
                    }
                ],
            }
        )
        assert result.records[0].ttl == 3600
        assert result.records[0].priority == 10

    def test_domain_snapshot_width_height_coerced_from_string(self) -> None:
        result = parse_domain_snapshot(
            {
                "domain": "example.com",
                "screenshot_url": "https://example.com/s.png",
                "width": "1024",
                "height": "768",
            }
        )
        assert result.width == 1024
        assert result.height == 768

    def test_domain_category_confidence_coerced_from_string(self) -> None:
        result = parse_domain_category(
            {"domain": "example.com", "confidence_score": "0.95"}
        )
        assert result.confidence_score == 0.95

    def test_monitor_item_id_and_typo_strength_coerced_from_string(self) -> None:
        result = parse_monitor_report(
            {
                "name": "brand-watch",
                "items": [
                    {
                        "id": "7",
                        "type": "domain",
                        "value": "example.com",
                        "typo_strength": "10",
                    }
                ],
            }
        )
        assert result.items[0].id == 7
        assert result.items[0].typo_strength == 10

    def test_monitor_report_id_coerced_from_string(self) -> None:
        result = parse_monitor_report({"id": "42", "name": "brand-watch", "items": []})
        assert result.id == 42
