"""Tests for DomainIQ CLI command dispatch."""

from __future__ import annotations

import argparse
from typing import TYPE_CHECKING, Any, cast

import pytest

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
from domainiq.constants import TYPO_STRENGTH_MAX, TYPO_STRENGTH_MIN
from domainiq.exceptions import DomainIQError
from domainiq.models import BulkWhoisType, KeywordMatchType, ReverseMatchType
from tests.conftest import StubClient

if TYPE_CHECKING:
    from domainiq.protocols import (
        BulkProtocol,
        DNSProtocol,
        DomainIQClientProtocol,
        MonitorProtocol,
        ReportProtocol,
        SearchProtocol,
        WhoisProtocol,
    )


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


def _mock_client() -> StubClient:
    return StubClient()


class TestDispatch:
    def test_dispatch_whois_returns_executed_true(self) -> None:
        client = _mock_client()
        client.set_result("whois_lookup", {"domain": "example.com"})
        args = _make_args(whois_lookup="example.com")
        executed, had_errors = _dispatch_whois(cast("WhoisProtocol", client), args)
        assert executed is True
        assert had_errors is False

    def test_dispatch_whois_not_triggered_when_absent(self) -> None:
        client = _mock_client()
        args = _make_args()
        executed, had_errors = _dispatch_whois(cast("WhoisProtocol", client), args)
        assert executed is False
        assert had_errors is False

    def test_dispatch_dns_returns_executed_true(self) -> None:
        client = _mock_client()
        args = _make_args(dns_lookup="example.com")
        executed, _had_errors = _dispatch_dns(cast("DNSProtocol", client), args)
        assert executed is True

    def test_dispatch_command_no_command_returns_exit_no_command(self) -> None:
        client = _mock_client()
        args = _make_args()
        result = _dispatch_command(cast("DomainIQClientProtocol", client), args)
        assert result == _EXIT_NO_COMMAND

    def test_dispatch_command_success(self) -> None:
        client = _mock_client()
        args = _make_args(whois_lookup="example.com")
        result = _dispatch_command(cast("DomainIQClientProtocol", client), args)
        assert result == _EXIT_SUCCESS

    def test_dispatch_command_error_on_domainiq_error(self) -> None:
        client = _mock_client()
        client.set_error("whois_lookup", DomainIQError("API failure"))
        args = _make_args(whois_lookup="example.com")
        result = _dispatch_command(cast("DomainIQClientProtocol", client), args)
        assert result == _EXIT_ERROR

    def test_dispatch_command_partial_on_mixed_results(self) -> None:
        client = _mock_client()
        client.set_error("dns_lookup", DomainIQError("DNS failure"))
        args = _make_args(whois_lookup="example.com", dns_lookup="example.com")
        result = _dispatch_command(cast("DomainIQClientProtocol", client), args)
        assert result == _EXIT_PARTIAL

    def test_dispatch_validation_error_returns_exit_error(self) -> None:
        client = _mock_client()
        args = _make_args(reverse_search="foo")  # missing reverse_search_type
        result = _dispatch_command(cast("DomainIQClientProtocol", client), args)
        assert result == _EXIT_ERROR

    def test_dispatch_validation_catches_whitespace_only_strings_regression(
        self,
    ) -> None:
        """Regression: whitespace-only values bypassed empty-string check."""
        client = _mock_client()
        args = _make_args(whois_lookup="   ")
        result = _dispatch_command(cast("DomainIQClientProtocol", client), args)
        assert result == _EXIT_ERROR


class TestDispatchSearch:
    def test_dispatch_domain_search_forwards_namespace_args(self) -> None:
        client = _mock_client()
        args = _make_args(
            domain_search=["brand"],
            match="all",
            exclude_idn=True,
            max_length=12,
        )

        result = _dispatch_search(cast("SearchProtocol", client), args)

        assert result.executed is True
        assert result.errored is False
        call_kwargs = client.calls_to("domain_search")[-1].kwargs
        assert call_kwargs["keywords"] == ["brand"]
        assert call_kwargs["match"] is KeywordMatchType.ALL
        assert call_kwargs["filters"] == {"exclude_idn": True, "max_length": 12}

    def test_dispatch_reverse_search_commands(self) -> None:
        client = _mock_client()
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

        result = _dispatch_search(cast("SearchProtocol", client), args)

        assert result.executed is True
        assert result.errored is False
        search_calls = client.calls_to("reverse_search")
        assert len(search_calls) == 1
        assert search_calls[0].args == ("email", "admin@example.com")
        assert search_calls[0].kwargs == {"match": ReverseMatchType.BEGINS}
        dns_calls = client.calls_to("reverse_dns")
        assert len(dns_calls) == 1
        assert dns_calls[0].args == ("example.com",)
        assert dns_calls[0].kwargs == {}
        ip_calls = client.calls_to("reverse_ip")
        assert len(ip_calls) == 1
        assert ip_calls[0].args == ("ip", "192.0.2.1")
        assert ip_calls[0].kwargs == {}
        mx_calls = client.calls_to("reverse_mx")
        assert len(mx_calls) == 1
        assert mx_calls[0].args == ("domain", "example.com")
        assert mx_calls[0].kwargs == {"recursive": True}


class TestDispatchBulk:
    def test_dispatch_bulk_commands(self) -> None:
        client = _mock_client()
        args = _make_args(
            bulk_dns=["example.com", "example.net"],
            bulk_whois=["example.org"],
            bulk_whois_type="cached",
            bulk_whois_ip=["192.0.2.1"],
        )

        result = _dispatch_bulk(cast("BulkProtocol", client), args)

        assert result.executed is True
        assert result.errored is False
        dns_calls = client.calls_to("bulk_dns")
        assert len(dns_calls) == 1
        assert dns_calls[0].args == (["example.com", "example.net"],)
        assert dns_calls[0].kwargs == {}
        whois_calls = client.calls_to("bulk_whois")
        assert len(whois_calls) == 1
        assert whois_calls[0].args == (["example.org"], BulkWhoisType.CACHED)
        assert whois_calls[0].kwargs == {}
        whois_ip_calls = client.calls_to("bulk_whois_ip")
        assert len(whois_ip_calls) == 1
        assert whois_ip_calls[0].args == (["192.0.2.1"],)
        assert whois_ip_calls[0].kwargs == {}


class TestDispatchReports:
    def test_dispatch_report_commands(self, capsys: pytest.CaptureFixture[str]) -> None:
        client = _mock_client()
        client.set_result("domain_report", {"domain": "example.com"})
        client.set_result("name_report", {"name": "Alice"})
        client.set_result("organization_report", {"organization": "Example Org"})
        client.set_result("email_report", {"email": "admin@example.com"})
        client.set_result("ip_report", {"ip": "192.0.2.1"})
        args = _make_args(
            domain_report="example.com",
            name_report="Alice",
            organization_report="Example Org",
            email_report="admin@example.com",
            ip_report="192.0.2.1",
        )

        result = _dispatch_reports(cast("ReportProtocol", client), args)

        assert result.executed is True
        assert result.errored is False
        domain_calls = client.calls_to("domain_report")
        assert len(domain_calls) == 1
        assert domain_calls[0].args == ("example.com",)
        assert domain_calls[0].kwargs == {}
        name_calls = client.calls_to("name_report")
        assert len(name_calls) == 1
        assert name_calls[0].args == ("Alice",)
        assert name_calls[0].kwargs == {}
        org_calls = client.calls_to("organization_report")
        assert len(org_calls) == 1
        assert org_calls[0].args == ("Example Org",)
        assert org_calls[0].kwargs == {}
        email_calls = client.calls_to("email_report")
        assert len(email_calls) == 1
        assert email_calls[0].args == ("admin@example.com",)
        assert email_calls[0].kwargs == {}
        ip_calls = client.calls_to("ip_report")
        assert len(ip_calls) == 1
        assert ip_calls[0].args == ("192.0.2.1",)
        assert ip_calls[0].kwargs == {}
        assert "example.com" in capsys.readouterr().out

    def test_dispatch_reports_skips_when_no_report_args(self) -> None:
        client = _mock_client()
        args = _make_args()

        result = _dispatch_reports(cast("ReportProtocol", client), args)

        assert result.executed is False
        assert result.errored is False
        assert client.calls_to("domain_report") == []

    def test_dispatch_reports_aggregates_partial_errors(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        client = _mock_client()
        client.set_result("domain_report", {"domain": "example.com"})
        client.set_error("name_report", DomainIQError("report failed"))
        args = _make_args(domain_report="example.com", name_report="Alice")

        result = _dispatch_reports(cast("ReportProtocol", client), args)

        assert result.executed is True
        assert result.errored is True
        captured = capsys.readouterr()
        assert "example.com" in captured.out
        assert "report failed" in captured.err


class TestDispatchMonitor:
    def test_dispatch_monitor_read_commands(self) -> None:
        client = _mock_client()
        args = _make_args(
            monitor_list=True,
            monitor_report_items=42,
            monitor_report_summary=42,
            monitor_item=7,
            monitor_range=30,
            monitor_report_changes=42,
            monitor_change=99,
        )

        result = _dispatch_monitor(cast("MonitorProtocol", client), args)

        assert result.executed is True
        assert result.errored is False
        list_calls = client.calls_to("monitor_list")
        assert len(list_calls) == 1
        assert list_calls[0].args == ()
        assert list_calls[0].kwargs == {}
        items_calls = client.calls_to("monitor_report_items")
        assert len(items_calls) == 1
        assert items_calls[0].args == (42,)
        assert items_calls[0].kwargs == {}
        summary_calls = client.calls_to("monitor_report_summary")
        assert len(summary_calls) == 1
        assert summary_calls[0].args == (42,)
        assert summary_calls[0].kwargs == {"item_id": 7, "days_range": 30}
        changes_calls = client.calls_to("monitor_report_changes")
        assert len(changes_calls) == 1
        assert changes_calls[0].args == (42, 99)
        assert changes_calls[0].kwargs == {}

    def test_dispatch_monitor_management_commands(self) -> None:
        client = _mock_client()
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

        result = _dispatch_monitor_management(cast("MonitorProtocol", client), args)

        assert result.executed is True
        assert result.errored is False
        create_calls = client.calls_to("create_monitor_report")
        assert len(create_calls) == 1
        assert create_calls[0].args == ("domain", "brand-watch")
        assert create_calls[0].kwargs == {"email_alert": False}
        add_calls = client.calls_to("add_monitor_item")
        assert len(add_calls) == 1
        assert add_calls[0].args == (42, "domain", ["example.com", "example.net"])
        assert add_calls[0].kwargs == {}
        enable_calls = client.calls_to("enable_typos")
        assert len(enable_calls) == 1
        assert enable_calls[0].args == (42, 7)
        assert enable_calls[0].kwargs == {}
        disable_calls = client.calls_to("disable_typos")
        assert len(disable_calls) == 1
        assert disable_calls[0].args == (42, 7)
        assert disable_calls[0].kwargs == {}
        modify_calls = client.calls_to("modify_typo_strength")
        assert len(modify_calls) == 1
        assert modify_calls[0].args == (42, 7, 10)
        assert modify_calls[0].kwargs == {}
        del_item_calls = client.calls_to("delete_monitor_item")
        assert len(del_item_calls) == 1
        assert del_item_calls[0].args == (7,)
        assert del_item_calls[0].kwargs == {}
        del_report_calls = client.calls_to("delete_monitor_report")
        assert len(del_report_calls) == 1
        assert del_report_calls[0].args == (42,)
        assert del_report_calls[0].kwargs == {}

    def test_dispatch_monitor_management_filters_empty_add_item_values(
        self,
    ) -> None:
        client = _mock_client()
        args = _make_args(add_monitor_item=["42", "domain", "example.com,"])

        result = _dispatch_monitor_management(cast("MonitorProtocol", client), args)

        assert result.executed is True
        assert result.errored is False
        add_calls = client.calls_to("add_monitor_item")
        assert len(add_calls) == 1
        assert add_calls[0].args == (42, "domain", ["example.com"])
        assert add_calls[0].kwargs == {}

    def test_dispatch_command_reports_invalid_add_monitor_item_report_id(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        client = _mock_client()
        args = _make_args(add_monitor_item=["abc", "domain", "example.com"])

        result = _dispatch_command(cast("DomainIQClientProtocol", client), args)

        assert result == _EXIT_ERROR
        assert client.calls_to("add_monitor_item") == []
        captured = capsys.readouterr()
        assert "report_id" in captured.err

    def test_dispatch_command_reports_invalid_enable_typos_report_id(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        client = _mock_client()
        args = _make_args(enable_typos=["abc", "7"])

        result = _dispatch_command(cast("DomainIQClientProtocol", client), args)

        assert result == _EXIT_ERROR
        assert client.calls_to("enable_typos") == []
        captured = capsys.readouterr()
        assert "report_id" in captured.err

    def test_dispatch_command_reports_invalid_modify_typo_strength_item_id(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        client = _mock_client()
        args = _make_args(modify_typo_strength=["42", "x", "10"])

        result = _dispatch_command(cast("DomainIQClientProtocol", client), args)

        assert result == _EXIT_ERROR
        assert client.calls_to("modify_typo_strength") == []
        captured = capsys.readouterr()
        assert "item_id" in captured.err

    def test_modify_typo_strength_uses_constants_regression(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Regression: typo strength bounds were hardcoded, not read from constants."""
        client = _mock_client()
        args = _make_args(modify_typo_strength=["42", "7", str(TYPO_STRENGTH_MIN - 1)])

        result = _dispatch_command(cast("DomainIQClientProtocol", client), args)

        assert result == _EXIT_ERROR
        assert client.calls_to("modify_typo_strength") == []
        captured = capsys.readouterr()
        assert f"{TYPO_STRENGTH_MIN} and {TYPO_STRENGTH_MAX}" in captured.err


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

    def test_value_error_propagates_instead_of_being_caught(self) -> None:
        msg = "bad value"

        def _raise() -> None:
            raise ValueError(msg)

        with pytest.raises(ValueError, match=msg):
            _run_command(_raise)

    def test_returns_had_errors_on_oserror(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        msg = "network down"

        def _raise() -> None:
            raise OSError(msg)

        executed, had_errors = _run_command(_raise)
        assert executed is True
        assert had_errors is True
        captured = capsys.readouterr()
        assert msg in captured.err

    def test_type_error_propagates(self) -> None:
        msg = "unexpected type mismatch"

        def _raise() -> None:
            raise TypeError(msg)

        with pytest.raises(TypeError, match=msg):
            _run_command(_raise)

    def test_runtime_error_propagates(self) -> None:
        msg = "internal failure"

        def _raise() -> None:
            raise RuntimeError(msg)

        with pytest.raises(RuntimeError, match=msg):
            _run_command(_raise)

    def test_attribute_error_propagates(self) -> None:
        msg = "missing attribute"

        def _raise() -> None:
            raise AttributeError(msg)

        with pytest.raises(AttributeError, match=msg):
            _run_command(_raise)

    def test_key_error_propagates(self) -> None:
        msg = "missing key"

        def _raise() -> None:
            raise KeyError(msg)

        with pytest.raises(KeyError, match=msg):
            _run_command(_raise)

    def test_index_error_propagates(self) -> None:
        msg = "index out of range"

        def _raise() -> None:
            raise IndexError(msg)

        with pytest.raises(IndexError, match=msg):
            _run_command(_raise)

    def test_broken_stderr_does_not_crash_regression(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression: broken stderr caused unhandled OSError crash."""

        class BrokenStderr:
            def write(self, _msg: str) -> None:
                error = "broken pipe"
                raise OSError(error)

        monkeypatch.setattr("sys.stderr", BrokenStderr())
        executed, had_errors = _run_command(
            lambda: (_ for _ in ()).throw(DomainIQError("fail"))
        )
        assert executed is True
        assert had_errors is True
