"""Tests for the DomainIQ CLI (arg parsing, dispatch, handlers, main entry point)."""

from __future__ import annotations

import argparse
import base64
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from domainiq.cli import main
from domainiq.cli._args import create_parser
from domainiq.cli._credentials import _is_interactive, prompt_for_api_key
from domainiq.cli._dispatch import (
    _dispatch_command,
    _dispatch_dns,
    _dispatch_whois,
    _run_command,
)
from domainiq.cli._dispatch_bulk import _dispatch_bulk
from domainiq.cli._dispatch_monitor import (
    _dispatch_monitor,
    _dispatch_monitor_management,
)
from domainiq.cli._dispatch_search import _dispatch_search
from domainiq.cli._handlers import (
    handle_dns_lookup,
    handle_domain_search,
    handle_whois_lookup,
)
from domainiq.cli._serialization import print_result
from domainiq.cli._serialization import serialize_result as _serialize
from domainiq.cli._types import DnsArgs, DomainSearchArgs, WhoisArgs
from domainiq.cli._validation import validate_args as _validate_args
from domainiq.constants import (
    EXIT_ERROR as _EXIT_ERROR,
)
from domainiq.constants import (
    EXIT_NO_COMMAND as _EXIT_NO_COMMAND,
)
from domainiq.constants import (
    EXIT_PARTIAL as _EXIT_PARTIAL,
)
from domainiq.constants import (
    EXIT_SUCCESS as _EXIT_SUCCESS,
)
from domainiq.exceptions import DomainIQConfigurationError, DomainIQError
from domainiq.models import BulkWhoisType, KeywordMatchType, ReverseMatchType

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


def _mock_client() -> MagicMock:
    return MagicMock()


# ---------------------------------------------------------------------------
# Arg Parsing
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Validate Args
# ---------------------------------------------------------------------------


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

    def test_monitor_changes_requires_change_id(self) -> None:
        args = _make_args(monitor_report_changes=5)
        errors = _validate_args(args)
        assert any("monitor-change" in e for e in errors)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


class TestDispatch:
    def test_dispatch_whois_returns_executed_true(self) -> None:
        client = _mock_client()
        client.whois_lookup.return_value = {"domain": "example.com"}
        args = _make_args(whois_lookup="example.com")
        executed, had_errors = _dispatch_whois(client, args)
        assert executed is True
        assert had_errors is False

    def test_dispatch_whois_not_triggered_when_absent(self) -> None:
        client = _mock_client()
        args = _make_args()
        executed, had_errors = _dispatch_whois(client, args)
        assert executed is False
        assert had_errors is False

    def test_dispatch_dns_returns_executed_true(self) -> None:
        client = _mock_client()
        client.dns_lookup.return_value = []
        args = _make_args(dns_lookup="example.com")
        executed, _had_errors = _dispatch_dns(client, args)
        assert executed is True

    def test_dispatch_command_no_command_returns_exit_no_command(self) -> None:
        client = _mock_client()
        args = _make_args()
        result = _dispatch_command(client, args)
        assert result == _EXIT_NO_COMMAND

    def test_dispatch_command_success(self) -> None:
        client = _mock_client()
        client.whois_lookup.return_value = {}
        args = _make_args(whois_lookup="example.com")
        result = _dispatch_command(client, args)
        assert result == _EXIT_SUCCESS

    def test_dispatch_command_error_on_domainiq_error(self) -> None:
        client = _mock_client()
        client.whois_lookup.side_effect = DomainIQError("API failure")
        args = _make_args(whois_lookup="example.com")
        result = _dispatch_command(client, args)
        assert result == _EXIT_ERROR

    def test_dispatch_command_partial_on_mixed_results(self) -> None:
        client = _mock_client()
        client.whois_lookup.return_value = {}
        client.dns_lookup.side_effect = DomainIQError("DNS failure")
        args = _make_args(whois_lookup="example.com", dns_lookup="example.com")
        result = _dispatch_command(client, args)
        assert result == _EXIT_PARTIAL

    def test_dispatch_validation_error_returns_exit_error(self) -> None:
        client = _mock_client()
        args = _make_args(reverse_search="foo")  # missing reverse_search_type
        result = _dispatch_command(client, args)
        assert result == _EXIT_ERROR


class TestDispatchSearch:
    def test_dispatch_domain_search_forwards_namespace_args(self) -> None:
        client = _mock_client()
        client.domain_search.return_value = {}
        args = _make_args(
            domain_search=["brand"],
            match="all",
            exclude_idn=True,
            max_length=12,
        )

        result = _dispatch_search(client, args)

        assert result.executed is True
        assert result.errored is False
        call_kwargs = client.domain_search.call_args.kwargs
        assert call_kwargs["keywords"] == ["brand"]
        assert call_kwargs["match"] is KeywordMatchType.ALL
        assert call_kwargs["filters"] == {"exclude_idn": True, "max_length": 12}

    def test_dispatch_reverse_search_commands(self) -> None:
        client = _mock_client()
        client.reverse_search.return_value = {}
        client.reverse_dns.return_value = {}
        client.reverse_ip.return_value = {}
        client.reverse_mx.return_value = {}
        args = _make_args(
            reverse_search_type="email",
            reverse_search="admin@example.com",
            reverse_match="begins",
            reverse_dns="example.com",
            reverse_ip_type="ip",
            reverse_ip_data="192.0.2.1",
            reverse_mx_type="domain",
            reverse_mx_data="example.com",
            recursive=True,
        )

        result = _dispatch_search(client, args)

        assert result.executed is True
        assert result.errored is False
        client.reverse_search.assert_called_once_with(
            "email", "admin@example.com", match=ReverseMatchType.BEGINS
        )
        client.reverse_dns.assert_called_once_with("example.com")
        client.reverse_ip.assert_called_once_with("ip", "192.0.2.1")
        client.reverse_mx.assert_called_once_with(
            "domain", "example.com", recursive=True
        )


class TestDispatchBulk:
    def test_dispatch_bulk_commands(self) -> None:
        client = _mock_client()
        client.bulk_dns.return_value = {}
        client.bulk_whois.return_value = {}
        client.bulk_whois_ip.return_value = {}
        args = _make_args(
            bulk_dns=["example.com", "example.net"],
            bulk_whois=["example.org"],
            bulk_whois_type="cached",
            bulk_whois_ip=["192.0.2.1"],
        )

        result = _dispatch_bulk(client, args)

        assert result.executed is True
        assert result.errored is False
        client.bulk_dns.assert_called_once_with(["example.com", "example.net"])
        client.bulk_whois.assert_called_once_with(
            ["example.org"], BulkWhoisType.CACHED
        )
        client.bulk_whois_ip.assert_called_once_with(["192.0.2.1"])


class TestDispatchMonitor:
    def test_dispatch_monitor_read_commands(self) -> None:
        client = _mock_client()
        client.monitor_list.return_value = {}
        client.monitor_report_items.return_value = {}
        client.monitor_report_summary.return_value = {}
        client.monitor_report_changes.return_value = {}
        args = _make_args(
            monitor_list=True,
            monitor_report_items=42,
            monitor_report_summary=42,
            monitor_item=7,
            monitor_range=30,
            monitor_report_changes=42,
            monitor_change=99,
        )

        result = _dispatch_monitor(client, args)

        assert result.executed is True
        assert result.errored is False
        client.monitor_list.assert_called_once_with()
        client.monitor_report_items.assert_called_once_with(42)
        client.monitor_report_summary.assert_called_once_with(
            42, item_id=7, days_range=30
        )
        client.monitor_report_changes.assert_called_once_with(42, 99)

    def test_dispatch_monitor_management_commands(self) -> None:
        client = _mock_client()
        client.create_monitor_report.return_value = {}
        client.add_monitor_item.return_value = {}
        client.enable_typos.return_value = {}
        client.disable_typos.return_value = {}
        client.modify_typo_strength.return_value = {}
        client.delete_monitor_item.return_value = {}
        client.delete_monitor_report.return_value = {}
        args = _make_args(
            create_monitor_report=["domain", "brand-watch"],
            email_alert=False,
            add_monitor_item=["42", "domain", "example.com, example.net"],
            enable_typos=["42", "7"],
            disable_typos=["42", "7"],
            modify_typo_strength=["42", "7", "10"],
            delete_monitor_item=7,
            delete_monitor_report=42,
        )

        result = _dispatch_monitor_management(client, args)

        assert result.executed is True
        assert result.errored is False
        client.create_monitor_report.assert_called_once_with(
            "domain", "brand-watch", email_alert=False
        )
        client.add_monitor_item.assert_called_once_with(
            42, "domain", ["example.com", "example.net"]
        )
        client.enable_typos.assert_called_once_with(42, 7)
        client.disable_typos.assert_called_once_with(42, 7)
        client.modify_typo_strength.assert_called_once_with(42, 7, 10)
        client.delete_monitor_item.assert_called_once_with(7)
        client.delete_monitor_report.assert_called_once_with(42)


class TestRunCommand:
    def test_returns_executed_true_no_errors_on_success(self) -> None:
        executed, had_errors = _run_command(lambda: None)
        assert executed is True
        assert had_errors is False

    def test_returns_had_errors_on_domainiq_error(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        msg = "something went wrong"

        def _raise() -> None:
            raise DomainIQError(msg)

        executed, had_errors = _run_command(_raise)
        assert executed is True
        assert had_errors is True
        captured = capsys.readouterr()
        assert msg in captured.err


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


class TestSerialize:
    def test_datetime_to_iso(self) -> None:
        dt = datetime(2024, 1, 15, 12, 0, 0)  # noqa: DTZ001
        assert _serialize(dt) == "2024-01-15T12:00:00"

    def test_bytes_to_base64(self) -> None:
        data = b"hello"
        result = _serialize(data)
        assert result == base64.b64encode(b"hello").decode("ascii")

    def test_dict_recursion(self) -> None:
        dt = datetime(2024, 1, 1)  # noqa: DTZ001
        result = _serialize({"ts": dt, "val": 42})
        assert result == {"ts": "2024-01-01T00:00:00", "val": 42}

    def test_list_recursion(self) -> None:
        result = _serialize([1, b"x", "y"])
        assert result[0] == 1
        assert isinstance(result[1], str)
        assert result[2] == "y"

    def test_dataclass_to_dict(self) -> None:
        @dataclass
        class Simple:
            name: str
            value: int

        result = _serialize(Simple(name="test", value=99))
        assert isinstance(result, dict)
        assert result["name"] == "test"
        assert result["value"] == 99

    def test_primitive_passthrough(self) -> None:
        assert _serialize(42) == 42
        assert _serialize("hello") == "hello"
        assert _serialize(None) is None


class TestPrintResult:
    def test_prints_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        print_result({"key": "value"})
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["key"] == "value"

    def test_prints_no_data_for_none(self, capsys: pytest.CaptureFixture[str]) -> None:
        print_result(None)
        captured = capsys.readouterr()
        assert "No data returned" in captured.out

    def test_uses_2_space_indent(self, capsys: pytest.CaptureFixture[str]) -> None:
        print_result({"a": 1})
        captured = capsys.readouterr()
        assert '  "a": 1' in captured.out


class TestHandleWhoisLookup:
    def test_domain_target_calls_whois_with_domain(self) -> None:
        client = _mock_client()
        client.whois_lookup.return_value = {}
        args = WhoisArgs(query="example.com", full=False, current_only=False)
        handle_whois_lookup(client, args)
        client.whois_lookup.assert_called_once_with(
            domain="example.com", ip=None, full=False, current_only=False
        )

    def test_ip_target_calls_whois_with_ip(self) -> None:
        client = _mock_client()
        client.whois_lookup.return_value = {}
        args = WhoisArgs(query="8.8.8.8", full=False, current_only=False)
        handle_whois_lookup(client, args)
        client.whois_lookup.assert_called_once_with(
            domain=None, ip="8.8.8.8", full=False, current_only=False
        )

    def test_full_flag_forwarded(self) -> None:
        client = _mock_client()
        client.whois_lookup.return_value = {}
        args = WhoisArgs(query="example.com", full=True, current_only=False)
        handle_whois_lookup(client, args)
        call_kwargs = client.whois_lookup.call_args.kwargs
        assert call_kwargs["full"] is True


class TestHandleDnsLookup:
    def test_no_types_passes_none(self) -> None:
        client = _mock_client()
        client.dns_lookup.return_value = []
        args = DnsArgs(query="example.com", types=None)
        handle_dns_lookup(client, args)
        client.dns_lookup.assert_called_once_with("example.com", record_types=None)

    def test_types_split_by_comma(self) -> None:
        client = _mock_client()
        client.dns_lookup.return_value = []
        args = DnsArgs(query="example.com", types=["A", "MX", "TXT"])
        handle_dns_lookup(client, args)
        client.dns_lookup.assert_called_once_with(
            "example.com", record_types=["A", "MX", "TXT"]
        )


class TestHandleDomainSearch:
    def _search_args(self, **kwargs: Any) -> DomainSearchArgs:
        defaults: dict[str, Any] = {
            "keywords": ["kw"],
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
        }
        defaults.update(kwargs)
        return DomainSearchArgs(**defaults)

    def test_basic_search_no_filters(self) -> None:
        client = _mock_client()
        client.domain_search.return_value = {}
        args = self._search_args(keywords=["kw"])
        handle_domain_search(client, args)
        client.domain_search.assert_called_once()
        call_kwargs = client.domain_search.call_args.kwargs
        assert call_kwargs["keywords"] == ["kw"]
        assert call_kwargs["filters"] is None

    def test_exclude_dashed_sets_filter(self) -> None:
        client = _mock_client()
        client.domain_search.return_value = {}
        args = self._search_args(exclude_dashed=True)
        handle_domain_search(client, args)
        call_kwargs = client.domain_search.call_args.kwargs
        assert call_kwargs["filters"]["exclude_dashed"] is True

    def test_count_only_sets_filter(self) -> None:
        client = _mock_client()
        client.domain_search.return_value = {}
        args = self._search_args(count_only=True)
        handle_domain_search(client, args)
        call_kwargs = client.domain_search.call_args.kwargs
        assert call_kwargs["filters"]["count_only"] == 1

    def test_min_max_length(self) -> None:
        client = _mock_client()
        client.domain_search.return_value = {}
        args = self._search_args(min_length=5, max_length=15)
        handle_domain_search(client, args)
        call_kwargs = client.domain_search.call_args.kwargs
        assert call_kwargs["filters"]["min_length"] == 5
        assert call_kwargs["filters"]["max_length"] == 15


# ---------------------------------------------------------------------------
# Credential helpers
# ---------------------------------------------------------------------------


class TestCliCredentials:
    def test_is_interactive_requires_both_stdin_and_stdout(self) -> None:
        with patch("os.isatty") as mock_isatty:
            mock_isatty.side_effect = lambda fd: fd == 0
            assert _is_interactive() is False

        with patch("os.isatty") as mock_isatty:
            mock_isatty.return_value = True
            assert _is_interactive() is True

    def test_prompt_for_api_key_persists_value(self, tmp_path) -> None:
        target = tmp_path / "domainiq.key"

        with (
            patch("domainiq.cli._credentials._is_interactive", return_value=True),
            patch(
                "domainiq.cli._credentials._prompt_with_timeout",
                return_value="interactive_key_xyz",
            ),
        ):
            api_key = prompt_for_api_key(str(target))

        assert api_key == "interactive_key_xyz"
        assert target.exists()
        assert target.read_text() == "interactive_key_xyz"

    def test_prompt_for_api_key_raises_when_non_interactive(self) -> None:
        with (
            patch("domainiq.cli._credentials._is_interactive", return_value=False),
            pytest.raises(DomainIQError, match="No API key found"),
        ):
            prompt_for_api_key(None)


# ---------------------------------------------------------------------------
# main() entry point
# ---------------------------------------------------------------------------


class TestMain:
    def test_main_no_command_exits_no_command(self) -> None:
        with (
            patch("sys.argv", ["domainiq", "--api-key", "key"]),
            patch("domainiq.cli._args.create_parser") as mock_create,
            patch("domainiq.client.DomainIQClient.__enter__") as mock_enter,
            patch("domainiq.client.DomainIQClient.__exit__", return_value=False),
        ):
            parser = create_parser()
            mock_create.return_value = parser
            mock_enter.return_value = _mock_client()
            code = main()
        assert code == _EXIT_NO_COMMAND

    def test_main_exits_1_on_domainiq_error(self) -> None:
        with (
            patch(
                "sys.argv",
                ["domainiq", "--api-key", "key", "--whois-lookup", "example.com"],
            ),
            patch("domainiq.client.DomainIQClient") as mock_cls,
        ):
            instance = mock_cls.return_value.__enter__.return_value
            instance.whois_lookup.side_effect = DomainIQError("test error")
            code = main()
        assert code == 1

    def test_main_keyboard_interrupt_exits_130(self) -> None:
        with (
            patch("sys.argv", ["domainiq", "--api-key", "key"]),
            patch("domainiq.client.DomainIQClient") as mock_cls,
        ):
            mock_cls.return_value.__enter__.side_effect = KeyboardInterrupt
            code = main()
        assert code == 130

    def test_main_prompts_when_sdk_config_has_no_key(self) -> None:
        with (
            patch("sys.argv", ["domainiq", "--whois-lookup", "example.com"]),
            patch(
                "domainiq.cli.Config",
                side_effect=[
                    DomainIQConfigurationError("missing key"),
                    MagicMock(api_key="prompted"),
                ],
            ),
            patch("domainiq.cli.prompt_for_api_key", return_value="prompted"),
            patch("domainiq.client.DomainIQClient") as mock_cls,
        ):
            instance = mock_cls.return_value.__enter__.return_value
            instance.whois_lookup.return_value = {}
            code = main()

        assert code == _EXIT_SUCCESS
