"""Tests for DomainIQ CLI command dispatch."""

from __future__ import annotations

import argparse
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

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
from domainiq.cli._dispatch_reports import _dispatch_reports
from domainiq.cli._dispatch_search import _dispatch_search
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
from domainiq.exceptions import DomainIQError
from domainiq.models import BulkWhoisType, KeywordMatchType, ReverseMatchType

if TYPE_CHECKING:
    import pytest


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


class TestDispatchReports:
    def test_dispatch_report_commands(self, capsys: pytest.CaptureFixture[str]) -> None:
        client = _mock_client()
        client.domain_report.return_value = {"domain": "example.com"}
        client.name_report.return_value = {"name": "Alice"}
        client.organization_report.return_value = {"organization": "Example Org"}
        client.email_report.return_value = {"email": "admin@example.com"}
        client.ip_report.return_value = {"ip": "192.0.2.1"}
        args = _make_args(
            domain_report="example.com",
            name_report="Alice",
            organization_report="Example Org",
            email_report="admin@example.com",
            ip_report="192.0.2.1",
        )

        result = _dispatch_reports(client, args)

        assert result.executed is True
        assert result.errored is False
        client.domain_report.assert_called_once_with("example.com")
        client.name_report.assert_called_once_with("Alice")
        client.organization_report.assert_called_once_with("Example Org")
        client.email_report.assert_called_once_with("admin@example.com")
        client.ip_report.assert_called_once_with("192.0.2.1")
        assert "example.com" in capsys.readouterr().out

    def test_dispatch_reports_skips_when_no_report_args(self) -> None:
        client = _mock_client()
        args = _make_args()

        result = _dispatch_reports(client, args)

        assert result.executed is False
        assert result.errored is False
        client.domain_report.assert_not_called()

    def test_dispatch_reports_aggregates_partial_errors(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        client = _mock_client()
        client.domain_report.return_value = {"domain": "example.com"}
        client.name_report.side_effect = DomainIQError("report failed")
        args = _make_args(domain_report="example.com", name_report="Alice")

        result = _dispatch_reports(client, args)

        assert result.executed is True
        assert result.errored is True
        captured = capsys.readouterr()
        assert "example.com" in captured.out
        assert "report failed" in captured.err


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
