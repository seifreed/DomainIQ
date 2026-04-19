"""Monitor endpoint mixins (sync and async).

_MonitorMixin and _AsyncMonitorMixin are intentionally near-identical.
Python requires 'await' inside 'async def'; the two classes cannot share
implementation while maintaining correct coroutine semantics, mypy strict
compliance, and IDE support. All extractable logic lives in params.py and
deserializers.py; what remains is structural boilerplate.
"""

from __future__ import annotations

from typing import Any

from . import params as _params
from ._base_client import _AsyncRequestable, _SyncRequestable
from .deserializers import parse_monitor_report
from .models import MonitorItemType, MonitorReport, MonitorReportType
from .utils import ensure_list_of_models


class _MonitorMixin(_SyncRequestable):
    def monitor_list(self) -> list[MonitorReport]:
        """Get list of active monitors."""
        result = self._make_json_request_maybe_list(_params.build_monitor_list_params())
        return ensure_list_of_models(result, parse_monitor_report)

    def monitor_report_items(self, report_id: int) -> dict[str, Any]:
        """Get items in a monitor report."""
        return self._make_json_request(_params.build_monitor_report_items_params(report_id))

    def monitor_report_summary(self, report_id: int, item_id: int | None = None, days_range: int | None = None) -> dict[str, Any]:
        """Get monitor report summary."""
        return self._make_json_request(_params.build_monitor_report_summary_params(report_id, item_id, days_range))

    def monitor_report_changes(self, report_id: int, change_id: int) -> dict[str, Any]:
        """Get monitor report changes."""
        return self._make_json_request(_params.build_monitor_report_changes_params(report_id, change_id))

    def create_monitor_report(self, report_type: MonitorReportType | str, name: str, email_alert: bool = True) -> dict[str, Any]:
        """Create a new monitor report."""
        return self._make_json_request(_params.build_create_monitor_report_params(report_type, name, email_alert))

    def add_monitor_item(
        self, report_id: int, item_type: MonitorItemType | str, items: list[str], enabled: bool | None = None
    ) -> dict[str, Any]:
        """Add items to a monitor report."""
        return self._make_json_request(
            _params.build_add_monitor_item_params(report_id, item_type, items, enabled=enabled)
        )

    def enable_typos(self, report_id: int, item_id: int, strength: int = _params.TYPO_STRENGTH_MAX) -> dict[str, Any]:
        """Enable typo monitoring for a keyword monitor item."""
        return self._make_json_request(_params.build_enable_typos_params(report_id, item_id, strength))

    def disable_typos(self, report_id: int, item_id: int) -> dict[str, Any]:
        """Disable typo monitoring for a keyword monitor item."""
        return self._make_json_request(_params.build_disable_typos_params(report_id, item_id))

    def modify_typo_strength(self, report_id: int, item_id: int, strength: int) -> dict[str, Any]:
        """Modify typo monitoring strength for a keyword monitor item."""
        return self._make_json_request(_params.build_modify_typo_strength_params(report_id, item_id, strength))

    def delete_monitor_item(self, item_id: int) -> dict[str, Any]:
        """Delete a monitor item."""
        return self._make_json_request(_params.build_delete_monitor_item_params(item_id))

    def delete_monitor_report(self, report_id: int) -> dict[str, Any]:
        """Delete a monitor report."""
        return self._make_json_request(_params.build_delete_monitor_report_params(report_id))


# Async version mirrors sync; only await calls differ.
class _AsyncMonitorMixin(_AsyncRequestable):
    async def monitor_list(self) -> list[MonitorReport]:
        """Get list of active monitors asynchronously."""
        params = _params.build_monitor_list_params()
        result = await self._make_json_request_maybe_list(params)
        return ensure_list_of_models(result, parse_monitor_report)

    async def monitor_report_items(self, report_id: int) -> dict[str, Any]:
        """Get items in a monitor report asynchronously."""
        return await self._make_json_request(_params.build_monitor_report_items_params(report_id))

    async def monitor_report_summary(self, report_id: int, item_id: int | None = None, days_range: int | None = None) -> dict[str, Any]:
        """Get monitor report summary asynchronously."""
        return await self._make_json_request(_params.build_monitor_report_summary_params(report_id, item_id, days_range))

    async def monitor_report_changes(self, report_id: int, change_id: int) -> dict[str, Any]:
        """Get monitor report changes asynchronously."""
        return await self._make_json_request(_params.build_monitor_report_changes_params(report_id, change_id))

    async def create_monitor_report(self, report_type: MonitorReportType | str, name: str, email_alert: bool = True) -> dict[str, Any]:
        """Create a new monitor report asynchronously."""
        return await self._make_json_request(_params.build_create_monitor_report_params(report_type, name, email_alert))

    async def add_monitor_item(
        self, report_id: int, item_type: MonitorItemType | str, items: list[str], enabled: bool | None = None
    ) -> dict[str, Any]:
        """Add items to a monitor report asynchronously."""
        return await self._make_json_request(
            _params.build_add_monitor_item_params(report_id, item_type, items, enabled=enabled)
        )

    async def enable_typos(self, report_id: int, item_id: int, strength: int = _params.TYPO_STRENGTH_MAX) -> dict[str, Any]:
        """Enable typo monitoring asynchronously."""
        return await self._make_json_request(_params.build_enable_typos_params(report_id, item_id, strength))

    async def disable_typos(self, report_id: int, item_id: int) -> dict[str, Any]:
        """Disable typo monitoring asynchronously."""
        return await self._make_json_request(_params.build_disable_typos_params(report_id, item_id))

    async def modify_typo_strength(self, report_id: int, item_id: int, strength: int) -> dict[str, Any]:
        """Modify typo monitoring strength asynchronously."""
        return await self._make_json_request(_params.build_modify_typo_strength_params(report_id, item_id, strength))

    async def delete_monitor_item(self, item_id: int) -> dict[str, Any]:
        """Delete a monitor item asynchronously."""
        return await self._make_json_request(_params.build_delete_monitor_item_params(item_id))

    async def delete_monitor_report(self, report_id: int) -> dict[str, Any]:
        """Delete a monitor report asynchronously."""
        return await self._make_json_request(_params.build_delete_monitor_report_params(report_id))
