"""Tests for DomainIQ CLI argument parsing and validation."""

from __future__ import annotations

import pytest

from domainiq.cli._args import create_parser
from domainiq.cli._types import DnsArgs
from domainiq.cli._validation import validate_args as _validate_args

from .conftest import make_cli_args


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

    def test_empty_types_string_is_parsed_as_none_regression(self) -> None:
        """Regression: empty --types "" produced [''] instead of None."""
        args = self.parser.parse_args(["--dns-lookup", "example.com", "--types", ""])
        dns_args = DnsArgs.from_namespace(args)
        assert dns_args.types is None

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

    def test_search_limit_rejects_non_numeric(self) -> None:
        with pytest.raises(SystemExit):
            self.parser.parse_args(["--domain-search", "kw", "--search-limit", "abc"])

    def test_snapshot_limit_must_be_positive_regression(self) -> None:
        """Regression: --snapshot-limit accepted 0 and negative values."""
        with pytest.raises(SystemExit):
            self.parser.parse_args(["--snapshot-limit", "0"])

    def test_timeout_accepts_float_regression(self) -> None:
        """Regression: --timeout rejected float values."""
        args = self.parser.parse_args(["--timeout", "30.5"])
        assert args.timeout == 30.5

    def test_timeout_defaults_to_none_regression(self) -> None:
        """Regression: --timeout defaulted to 30, shadowing DOMAINIQ_TIMEOUT."""
        args = self.parser.parse_args([])
        assert args.timeout is None


class TestValidateArgs:
    def test_no_errors_when_args_valid(self) -> None:
        args = make_cli_args(whois_lookup="example.com")
        assert _validate_args(args) == []

    def test_reverse_search_requires_type(self) -> None:
        args = make_cli_args(reverse_search="foo")
        errors = _validate_args(args)
        assert any("reverse-search-type" in e for e in errors)

    def test_reverse_search_type_requires_term(self) -> None:
        args = make_cli_args(reverse_search_type="email")
        errors = _validate_args(args)
        assert any("reverse-search is required" in e for e in errors)

    def test_reverse_ip_type_requires_data(self) -> None:
        args = make_cli_args(reverse_ip_type="ip")
        errors = _validate_args(args)
        assert any("reverse-ip-data" in e for e in errors)

    def test_reverse_ip_data_requires_type(self) -> None:
        args = make_cli_args(reverse_ip_data="192.0.2.1")
        errors = _validate_args(args)
        assert any("reverse-ip-type" in e for e in errors)

    def test_reverse_mx_type_requires_data(self) -> None:
        args = make_cli_args(reverse_mx_type="domain")
        errors = _validate_args(args)
        assert any("reverse-mx-data" in e for e in errors)

    def test_reverse_mx_data_requires_type(self) -> None:
        args = make_cli_args(reverse_mx_data="example.com")
        errors = _validate_args(args)
        assert any("reverse-mx-type" in e for e in errors)

    def test_monitor_changes_requires_change_id(self) -> None:
        args = make_cli_args(monitor_report_changes=5)
        errors = _validate_args(args)
        assert any("monitor-change" in e for e in errors)

    def test_monitor_change_requires_report_id(self) -> None:
        args = make_cli_args(monitor_change=9)
        errors = _validate_args(args)
        assert any("monitor-report-changes" in e for e in errors)

    def test_empty_string_in_list_arg_is_caught_regression(self) -> None:
        """Regression: empty strings inside nargs='+' args bypassed validation."""
        args = make_cli_args(domain_search=["ok", ""])
        errors = _validate_args(args)
        assert any("--domain-search cannot be empty" in e for e in errors)

    def test_empty_reverse_dns_is_caught_regression(self) -> None:
        """Regression: --reverse-dns was missing from empty-string checks."""
        args = make_cli_args(reverse_dns="")
        errors = _validate_args(args)
        assert any("--reverse-dns cannot be empty" in e for e in errors)

    def test_empty_types_is_caught_regression(self) -> None:
        """Regression: --types was missing from empty-string checks."""
        args = make_cli_args(types="")
        errors = _validate_args(args)
        assert any("--types cannot be empty" in e for e in errors)

    def test_empty_min_create_date_is_caught_regression(self) -> None:
        """Regression: --min-create-date was missing from empty-string checks."""
        args = make_cli_args(min_create_date="")
        errors = _validate_args(args)
        assert any("--min-create-date cannot be empty" in e for e in errors)

    def test_empty_max_create_date_is_caught_regression(self) -> None:
        """Regression: --max-create-date was missing from empty-string checks."""
        args = make_cli_args(max_create_date="")
        errors = _validate_args(args)
        assert any("--max-create-date cannot be empty" in e for e in errors)
