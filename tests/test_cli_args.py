"""Tests for DomainIQ CLI argument parsing and validation."""

from __future__ import annotations

import argparse
from typing import Any

import pytest

from domainiq.cli._args import create_parser
from domainiq.cli._validation import validate_args as _validate_args


def _make_args(**kwargs: Any) -> argparse.Namespace:
    """Build a Namespace with all CLI attributes defaulted to None/False."""
    defaults: dict[str, Any] = {
        "api_key": None,
        "config_file": None,
        "verbose": False,
        "debug": False,
        "timeout": 30,
        "whois_lookup": None,
        "full": False,
        "current_only": False,
        "dns_lookup": None,
        "types": None,
        "domain_categorize": None,
        "domain_snapshot": None,
        "domain_snapshot_history": None,
        "snapshot_limit": None,
        "snapshot_full": False,
        "no_cache": False,
        "raw": False,
        "width": None,
        "height": None,
        "domain_report": None,
        "name_report": None,
        "organization_report": None,
        "email_report": None,
        "ip_report": None,
        "domain_search": None,
        "conditions": None,
        "match": "any",
        "count_only": False,
        "exclude_dashed": False,
        "exclude_numbers": False,
        "exclude_idn": False,
        "min_length": None,
        "max_length": None,
        "min_create_date": None,
        "max_create_date": None,
        "search_limit": None,
        "reverse_search_type": None,
        "reverse_search": None,
        "reverse_match": "contains",
        "reverse_dns": None,
        "reverse_ip_type": None,
        "reverse_ip_data": None,
        "reverse_mx_type": None,
        "reverse_mx_data": None,
        "recursive": False,
        "bulk_dns": None,
        "bulk_whois": None,
        "bulk_whois_type": "live",
        "bulk_whois_ip": None,
        "monitor_list": False,
        "monitor_report_items": None,
        "monitor_report_summary": None,
        "monitor_item": None,
        "monitor_range": None,
        "monitor_report_changes": None,
        "monitor_change": None,
        "create_monitor_report": None,
        "email_alert": True,
        "add_monitor_item": None,
        "enable_typos": None,
        "disable_typos": None,
        "modify_typo_strength": None,
        "delete_monitor_item": None,
        "delete_monitor_report": None,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


class TestArgParsing:
    def setup_method(self) -> None:
        self.parser = create_parser()

    def test_parse_whois_lookup(self) -> None:
        args = self.parser.parse_args(["--whois-lookup", "example.com"])
        assert args.whois_lookup == "example.com"
        assert args.full is False
        assert args.current_only is False

    def test_parse_whois_lookup_with_flags(self) -> None:
        args = self.parser.parse_args(
            ["--whois-lookup", "example.com", "--full", "--current-only"]
        )
        assert args.full is True
        assert args.current_only is True

    def test_parse_dns_lookup(self) -> None:
        args = self.parser.parse_args(["--dns-lookup", "example.com"])
        assert args.dns_lookup == "example.com"
        assert args.types is None

    def test_parse_dns_lookup_with_types(self) -> None:
        args = self.parser.parse_args(
            ["--dns-lookup", "example.com", "--types", "A,MX"]
        )
        assert args.types == "A,MX"

    def test_parse_domain_search(self) -> None:
        args = self.parser.parse_args(["--domain-search", "keyword1", "keyword2"])
        assert args.domain_search == ["keyword1", "keyword2"]
        assert args.match == "any"

    def test_parse_domain_search_with_filters(self) -> None:
        args = self.parser.parse_args(
            [
                "--domain-search",
                "kw",
                "--match",
                "all",
                "--exclude-dashed",
                "--min-length",
                "5",
                "--max-length",
                "20",
                "--count-only",
            ]
        )
        assert args.match == "all"
        assert args.exclude_dashed is True
        assert args.min_length == 5
        assert args.max_length == 20
        assert args.count_only is True

    def test_parse_global_flags(self) -> None:
        args = self.parser.parse_args(["--verbose", "--debug", "--timeout", "60"])
        assert args.verbose is True
        assert args.debug is True
        assert args.timeout == 60

    def test_parse_bulk_whois(self) -> None:
        args = self.parser.parse_args(
            [
                "--bulk-whois",
                "a.com",
                "b.com",
                "--bulk-whois-type",
                "cached",
            ]
        )
        assert args.bulk_whois == ["a.com", "b.com"]
        assert args.bulk_whois_type == "cached"

    def test_parse_monitor_report_items(self) -> None:
        args = self.parser.parse_args(["--monitor-report-items", "42"])
        assert args.monitor_report_items == 42

    def test_parse_monitor_list(self) -> None:
        args = self.parser.parse_args(["--monitor-list"])
        assert args.monitor_list is True

    def test_parse_api_key(self) -> None:
        args = self.parser.parse_args(["--api-key", "mykey123"])
        assert args.api_key == "mykey123"

    def test_min_length_must_be_positive(self) -> None:
        with pytest.raises(SystemExit):
            self.parser.parse_args(["--domain-search", "kw", "--min-length", "0"])

    @pytest.mark.parametrize("value", ["0", "-5"])
    def test_search_limit_must_be_positive(self, value: str) -> None:
        with pytest.raises(SystemExit):
            self.parser.parse_args(["--domain-search", "kw", "--search-limit", value])


class TestValidateArgs:
    def test_no_errors_when_args_valid(self) -> None:
        args = _make_args(whois_lookup="example.com")
        assert _validate_args(args) == []

    def test_reverse_search_requires_type(self) -> None:
        args = _make_args(reverse_search="foo")
        errors = _validate_args(args)
        assert any("reverse-search-type" in e for e in errors)

    def test_reverse_search_type_requires_term(self) -> None:
        args = _make_args(reverse_search_type="email")
        errors = _validate_args(args)
        assert any("reverse-search is required" in e for e in errors)

    def test_reverse_ip_type_requires_data(self) -> None:
        args = _make_args(reverse_ip_type="ip")
        errors = _validate_args(args)
        assert any("reverse-ip-data" in e for e in errors)

    def test_reverse_ip_data_requires_type(self) -> None:
        args = _make_args(reverse_ip_data="192.0.2.1")
        errors = _validate_args(args)
        assert any("reverse-ip-type" in e for e in errors)

    def test_reverse_mx_type_requires_data(self) -> None:
        args = _make_args(reverse_mx_type="domain")
        errors = _validate_args(args)
        assert any("reverse-mx-data" in e for e in errors)

    def test_reverse_mx_data_requires_type(self) -> None:
        args = _make_args(reverse_mx_data="example.com")
        errors = _validate_args(args)
        assert any("reverse-mx-type" in e for e in errors)

    def test_monitor_changes_requires_change_id(self) -> None:
        args = _make_args(monitor_report_changes=5)
        errors = _validate_args(args)
        assert any("monitor-change" in e for e in errors)

    def test_monitor_change_requires_report_id(self) -> None:
        args = _make_args(monitor_change=9)
        errors = _validate_args(args)
        assert any("monitor-report-changes" in e for e in errors)
