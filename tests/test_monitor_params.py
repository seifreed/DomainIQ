"""Unit tests for monitor request-parameter builders."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from domainiq._params.monitor import (
    build_add_monitor_item_params,
    build_create_monitor_report_params,
    build_delete_monitor_item_params,
    build_delete_monitor_report_params,
    build_disable_typos_params,
    build_enable_typos_params,
    build_modify_typo_strength_params,
    build_monitor_list_params,
    build_monitor_report_changes_params,
    build_monitor_report_items_params,
    build_monitor_report_summary_params,
)
from domainiq.constants import API_BOOL_FALSE, API_BOOL_TRUE, TYPO_STRENGTH_MAX
from domainiq.exceptions import DomainIQValidationError
from domainiq.models import MonitorItemType, MonitorReportType

if TYPE_CHECKING:
    from collections.abc import Callable


class TestMonitorReadParams:
    def test_list_params(self) -> None:
        assert build_monitor_list_params() == {
            "service": "monitor",
            "action": "list",
        }

    def test_report_items_params(self) -> None:
        assert build_monitor_report_items_params(42) == {
            "service": "monitor",
            "action": "report_items",
            "report": 42,
        }

    def test_summary_omits_optional_fields_when_absent(self) -> None:
        assert build_monitor_report_summary_params(42, None, None) == {
            "service": "monitor",
            "action": "report_summary",
            "report": 42,
        }

    def test_summary_includes_optional_fields_when_present(self) -> None:
        assert build_monitor_report_summary_params(42, 7, 30) == {
            "service": "monitor",
            "action": "report_summary",
            "report": 42,
            "item": 7,
            "range": 30,
        }

    def test_changes_params(self) -> None:
        assert build_monitor_report_changes_params(42, 99) == {
            "service": "monitor",
            "action": "report_changes",
            "report": 42,
            "change": 99,
        }

    @pytest.mark.parametrize(
        ("build_params", "param_name"),
        [
            (lambda: build_monitor_report_items_params(0), "report_id"),
            (lambda: build_monitor_report_summary_params(-1, None, None), "report_id"),
            (lambda: build_monitor_report_summary_params(42, 0, None), "item_id"),
            (lambda: build_monitor_report_summary_params(42, None, 0), "days_range"),
            (lambda: build_monitor_report_changes_params(0, 99), "report_id"),
            (lambda: build_monitor_report_changes_params(42, 0), "change_id"),
        ],
    )
    def test_read_params_reject_non_positive_identifiers(
        self, build_params: Callable[[], object], param_name: str
    ) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            build_params()

        assert exc_info.value.param_name == param_name


class TestMonitorMutationParams:
    def test_create_report_uses_api_boolean_flags(self) -> None:
        enabled = build_create_monitor_report_params(
            MonitorReportType.DOMAIN,
            "brand-watch",
            True,
        )
        disabled = build_create_monitor_report_params(
            "domain",
            "quiet-watch",
            False,
        )

        assert enabled["email_alert"] == API_BOOL_TRUE
        assert enabled["type"] == MonitorReportType.DOMAIN
        assert disabled["email_alert"] == API_BOOL_FALSE

    def test_add_monitor_item_omits_enabled_when_unspecified(self) -> None:
        params = build_add_monitor_item_params(
            42,
            MonitorItemType.DOMAIN,
            ["example.com", "example.net"],
        )

        assert params == {
            "service": "monitor",
            "action": "report_item_add",
            "report_id": 42,
            "type": MonitorItemType.DOMAIN,
            "items": ["example.com", "example.net"],
        }

    def test_add_monitor_item_includes_enabled_when_specified(self) -> None:
        params = build_add_monitor_item_params(42, "domain", ["example.com"], False)

        assert params["enabled"] is False

    @pytest.mark.parametrize(
        ("item_type", "items"),
        [
            (MonitorItemType.DOMAIN, ["example..com"]),
            (MonitorItemType.IP, ["999.999.999.999"]),
        ],
    )
    def test_add_monitor_item_rejects_invalid_typed_items(
        self,
        item_type: MonitorItemType,
        items: list[str],
    ) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            build_add_monitor_item_params(42, item_type, items)

        assert exc_info.value.param_name == "items"

    @pytest.mark.parametrize("items", [[], [""], ["  "], ["example.com", ""]])
    def test_add_monitor_item_rejects_empty_items(self, items: list[str]) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            build_add_monitor_item_params(42, "domain", items)

        assert exc_info.value.param_name == "items"

    def test_typo_actions_validate_strength(self) -> None:
        assert build_enable_typos_params(42, 7, TYPO_STRENGTH_MAX)["strength"] == 41
        assert build_modify_typo_strength_params(42, 7, 5)["strength"] == 5

        with pytest.raises(DomainIQValidationError) as exc_info:
            build_enable_typos_params(42, 7, 4)

        assert exc_info.value.param_name == "strength"

    def test_disable_and_delete_params(self) -> None:
        assert build_disable_typos_params(42, 7) == {
            "service": "monitor",
            "action": "disable_typos",
            "report_id": 42,
            "item_id": 7,
        }
        assert build_delete_monitor_item_params(7) == {
            "service": "monitor",
            "action": "report_item_delete",
            "item_id": 7,
        }
        assert build_delete_monitor_report_params(42) == {
            "service": "monitor",
            "action": "report_delete",
            "report_id": 42,
        }

    @pytest.mark.parametrize(
        ("build_params", "param_name"),
        [
            (
                lambda: build_add_monitor_item_params(
                    0, "domain", ["example.com"]
                ),
                "report_id",
            ),
            (lambda: build_enable_typos_params(0, 7, 5), "report_id"),
            (lambda: build_enable_typos_params(42, 0, 5), "item_id"),
            (lambda: build_disable_typos_params(0, 7), "report_id"),
            (lambda: build_disable_typos_params(42, 0), "item_id"),
            (lambda: build_modify_typo_strength_params(0, 7, 5), "report_id"),
            (lambda: build_modify_typo_strength_params(42, 0, 5), "item_id"),
            (lambda: build_delete_monitor_item_params(0), "item_id"),
            (lambda: build_delete_monitor_report_params(0), "report_id"),
        ],
    )
    def test_mutation_params_reject_non_positive_identifiers(
        self, build_params: Callable[[], object], param_name: str
    ) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            build_params()

        assert exc_info.value.param_name == param_name
