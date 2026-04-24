"""Monitor endpoint mixins (sync and async).

_MonitorMixin and _AsyncMonitorMixin are intentionally near-identical.
Python requires 'await' inside 'async def'; the two classes cannot share
implementation while maintaining correct coroutine semantics, mypy strict
compliance, and IDE support. All extractable logic lives in parameter-builder
modules and deserializers.py; what remains is structural boilerplate.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ._base_client import _AsyncRequestable, _SyncRequestable
from ._params.monitor import (
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
from .constants import TYPO_STRENGTH_MAX
from .deserializers import parse_monitor_action_result, parse_monitor_report
from .utils import ensure_list_of_models

if TYPE_CHECKING:
    from ._models import (
        MonitorActionResult,
        MonitorItemType,
        MonitorReport,
        MonitorReportType,
    )


class _MonitorMixin(_SyncRequestable):
    def monitor_list(self) -> list[MonitorReport]:
        """Get list of active monitors."""
        result = self._make_json_request_maybe_list(build_monitor_list_params())
        return ensure_list_of_models(result, parse_monitor_report)

    def monitor_report_items(self, report_id: int) -> MonitorActionResult:
        """Get items in a monitor report."""
        return parse_monitor_action_result(
            self._make_json_request(build_monitor_report_items_params(report_id))
        )

    def monitor_report_summary(
        self, report_id: int, item_id: int | None = None, days_range: int | None = None
    ) -> MonitorActionResult:
        """Get monitor report summary."""
        return parse_monitor_action_result(
            self._make_json_request(
                build_monitor_report_summary_params(report_id, item_id, days_range)
            )
        )

    def monitor_report_changes(
        self, report_id: int, change_id: int
    ) -> MonitorActionResult:
        """Get monitor report changes."""
        return parse_monitor_action_result(
            self._make_json_request(
                build_monitor_report_changes_params(report_id, change_id)
            )
        )

    def create_monitor_report(
        self, report_type: MonitorReportType | str, name: str, email_alert: bool = True
    ) -> MonitorReport:
        """Create a new monitor report."""
        result = self._make_json_request(
            build_create_monitor_report_params(report_type, name, email_alert)
        )
        return parse_monitor_report(result)

    def add_monitor_item(
        self,
        report_id: int,
        item_type: MonitorItemType | str,
        items: list[str],
        enabled: bool | None = None,
    ) -> MonitorActionResult:
        """Add items to a monitor report."""
        return parse_monitor_action_result(
            self._make_json_request(
                build_add_monitor_item_params(
                    report_id, item_type, items, enabled=enabled
                )
            )
        )

    def enable_typos(
        self, report_id: int, item_id: int, strength: int = TYPO_STRENGTH_MAX
    ) -> MonitorActionResult:
        """Enable typo monitoring for a keyword monitor item."""
        return parse_monitor_action_result(
            self._make_json_request(
                build_enable_typos_params(report_id, item_id, strength)
            )
        )

    def disable_typos(self, report_id: int, item_id: int) -> MonitorActionResult:
        """Disable typo monitoring for a keyword monitor item."""
        return parse_monitor_action_result(
            self._make_json_request(build_disable_typos_params(report_id, item_id))
        )

    def modify_typo_strength(
        self, report_id: int, item_id: int, strength: int
    ) -> MonitorActionResult:
        """Modify typo monitoring strength for a keyword monitor item."""
        return parse_monitor_action_result(
            self._make_json_request(
                build_modify_typo_strength_params(report_id, item_id, strength)
            )
        )

    def delete_monitor_item(self, item_id: int) -> MonitorActionResult:
        """Delete a monitor item."""
        return parse_monitor_action_result(
            self._make_json_request(build_delete_monitor_item_params(item_id))
        )

    def delete_monitor_report(self, report_id: int) -> MonitorActionResult:
        """Delete a monitor report."""
        return parse_monitor_action_result(
            self._make_json_request(build_delete_monitor_report_params(report_id))
        )


# --- BEGIN GENERATED ---
# Async counterpart of the sync class above — generated by scripts/generate_mixins.py
# Edit the sync class, then run `make gen-mixins` to regenerate.
class _AsyncMonitorMixin(_AsyncRequestable):
    async def monitor_list(self) -> list[MonitorReport]:
        """Get list of active monitors asynchronously."""
        result = await self._make_json_request_maybe_list(build_monitor_list_params())
        return ensure_list_of_models(result, parse_monitor_report)

    async def monitor_report_items(self, report_id: int) -> MonitorActionResult:
        """Get items in a monitor report asynchronously."""
        return parse_monitor_action_result(
            await self._make_json_request(build_monitor_report_items_params(report_id))
        )

    async def monitor_report_summary(
        self, report_id: int, item_id: int | None = None, days_range: int | None = None
    ) -> MonitorActionResult:
        """Get monitor report summary asynchronously."""
        return parse_monitor_action_result(
            await self._make_json_request(
                build_monitor_report_summary_params(report_id, item_id, days_range)
            )
        )

    async def monitor_report_changes(
        self, report_id: int, change_id: int
    ) -> MonitorActionResult:
        """Get monitor report changes asynchronously."""
        return parse_monitor_action_result(
            await self._make_json_request(
                build_monitor_report_changes_params(report_id, change_id)
            )
        )

    async def create_monitor_report(
        self, report_type: MonitorReportType | str, name: str, email_alert: bool = True
    ) -> MonitorReport:
        """Create a new monitor report asynchronously."""
        result = await self._make_json_request(
            build_create_monitor_report_params(report_type, name, email_alert)
        )
        return parse_monitor_report(result)

    async def add_monitor_item(
        self,
        report_id: int,
        item_type: MonitorItemType | str,
        items: list[str],
        enabled: bool | None = None,
    ) -> MonitorActionResult:
        """Add items to a monitor report asynchronously."""
        return parse_monitor_action_result(
            await self._make_json_request(
                build_add_monitor_item_params(
                    report_id, item_type, items, enabled=enabled
                )
            )
        )

    async def enable_typos(
        self, report_id: int, item_id: int, strength: int = TYPO_STRENGTH_MAX
    ) -> MonitorActionResult:
        """Enable typo monitoring for a keyword monitor item asynchronously."""
        return parse_monitor_action_result(
            await self._make_json_request(
                build_enable_typos_params(report_id, item_id, strength)
            )
        )

    async def disable_typos(self, report_id: int, item_id: int) -> MonitorActionResult:
        """Disable typo monitoring for a keyword monitor item asynchronously."""
        return parse_monitor_action_result(
            await self._make_json_request(
                build_disable_typos_params(report_id, item_id)
            )
        )

    async def modify_typo_strength(
        self, report_id: int, item_id: int, strength: int
    ) -> MonitorActionResult:
        """Modify typo monitoring strength for a keyword monitor item asynchronously."""
        return parse_monitor_action_result(
            await self._make_json_request(
                build_modify_typo_strength_params(report_id, item_id, strength)
            )
        )

    async def delete_monitor_item(self, item_id: int) -> MonitorActionResult:
        """Delete a monitor item asynchronously."""
        return parse_monitor_action_result(
            await self._make_json_request(build_delete_monitor_item_params(item_id))
        )

    async def delete_monitor_report(self, report_id: int) -> MonitorActionResult:
        """Delete a monitor report asynchronously."""
        return parse_monitor_action_result(
            await self._make_json_request(build_delete_monitor_report_params(report_id))
        )


# --- END GENERATED ---
