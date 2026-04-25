"""Monitor request-parameter builders."""

from __future__ import annotations

from typing import Any

from domainiq._models import MonitorItemType, MonitorReportType
from domainiq.constants import (
    API_BOOL_FALSE,
    API_BOOL_TRUE,
    TYPO_STRENGTH_MAX,
    TYPO_STRENGTH_MIN,
)
from domainiq.exceptions import DomainIQValidationError
from domainiq.utils import enum_value
from domainiq.validators import ensure_positive_int, is_ip_address, validate_domain

from ._shared import require_non_empty

_MONITOR_REPORT_TYPES = {member.value for member in MonitorReportType}
_MONITOR_ITEM_TYPES = {member.value for member in MonitorItemType}


def _validate_typo_strength(strength: int) -> None:
    if not (TYPO_STRENGTH_MIN <= strength <= TYPO_STRENGTH_MAX):
        msg = f"strength must be between {TYPO_STRENGTH_MIN} and {TYPO_STRENGTH_MAX}"
        raise DomainIQValidationError(msg, param_name="strength")


def _validate_positive_ids(**ids: int | None) -> None:
    for field_name, value in ids.items():
        if value is not None:
            ensure_positive_int(field_name, value)


def _validate_type_value(
    value: MonitorReportType | MonitorItemType | str,
    valid_values: set[str],
    param_name: str,
) -> str:
    wire_value = enum_value(value)
    if not isinstance(wire_value, str) or wire_value not in valid_values:
        msg = f"Invalid {param_name}: {wire_value}"
        raise DomainIQValidationError(msg, param_name=param_name)
    return wire_value


def _validate_required_string(value: str, param_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        msg = f"{param_name} must not be empty or whitespace-only"
        raise DomainIQValidationError(msg, param_name=param_name)


def _validate_monitor_item_values(
    item_type: MonitorItemType | str,
    items: list[str],
) -> str:
    item_type_value = _validate_type_value(
        item_type,
        _MONITOR_ITEM_TYPES,
        "item_type",
    )
    if item_type_value == "domain":
        for item in items:
            if not validate_domain(item):
                msg = f"Invalid domain: {item}"
                raise DomainIQValidationError(msg, param_name="items")
    elif item_type_value == "ip":
        for item in items:
            if not is_ip_address(item):
                msg = f"Invalid IP address: {item}"
                raise DomainIQValidationError(msg, param_name="items")
    return item_type_value


def build_monitor_list_params() -> dict[str, Any]:
    return {"service": "monitor", "action": "list"}


def build_monitor_report_items_params(report_id: int) -> dict[str, Any]:
    _validate_positive_ids(report_id=report_id)
    return {"service": "monitor", "action": "report_items", "report": report_id}


def build_monitor_report_summary_params(
    report_id: int,
    item_id: int | None,
    days_range: int | None,
) -> dict[str, Any]:
    _validate_positive_ids(
        report_id=report_id,
        item_id=item_id,
        days_range=days_range,
    )
    params: dict[str, Any] = {
        "service": "monitor",
        "action": "report_summary",
        "report": report_id,
    }
    if item_id is not None:
        params["item"] = item_id
    if days_range is not None:
        params["range"] = days_range
    return params


def build_monitor_report_changes_params(
    report_id: int,
    change_id: int,
) -> dict[str, Any]:
    _validate_positive_ids(report_id=report_id, change_id=change_id)
    return {
        "service": "monitor",
        "action": "report_changes",
        "report": report_id,
        "change": change_id,
    }


def build_create_monitor_report_params(
    report_type: MonitorReportType | str,
    name: str,
    email_alert: bool,
) -> dict[str, Any]:
    report_type_value = _validate_type_value(
        report_type,
        _MONITOR_REPORT_TYPES,
        "report_type",
    )
    _validate_required_string(name, "name")
    return {
        "service": "monitor",
        "action": "report_create",
        "type": report_type_value,
        "name": name,
        "email_alert": API_BOOL_TRUE if email_alert else API_BOOL_FALSE,
    }


def build_add_monitor_item_params(
    report_id: int,
    item_type: MonitorItemType | str,
    items: list[str],
    enabled: bool | None = None,
) -> dict[str, Any]:
    _validate_positive_ids(report_id=report_id)
    require_non_empty("items", items)
    item_type_value = _validate_monitor_item_values(item_type, items)
    params: dict[str, Any] = {
        "service": "monitor",
        "action": "report_item_add",
        "report_id": report_id,
        "type": item_type_value,
        "items": items,
    }
    if enabled is not None:
        params["enabled"] = enabled
    return params


def build_enable_typos_params(
    report_id: int,
    item_id: int,
    strength: int,
) -> dict[str, Any]:
    _validate_positive_ids(report_id=report_id, item_id=item_id)
    _validate_typo_strength(strength)
    return {
        "service": "monitor",
        "action": "enable_typos",
        "report_id": report_id,
        "item_id": item_id,
        "strength": strength,
    }


def build_disable_typos_params(report_id: int, item_id: int) -> dict[str, Any]:
    _validate_positive_ids(report_id=report_id, item_id=item_id)
    return {
        "service": "monitor",
        "action": "disable_typos",
        "report_id": report_id,
        "item_id": item_id,
    }


def build_modify_typo_strength_params(
    report_id: int,
    item_id: int,
    strength: int,
) -> dict[str, Any]:
    _validate_positive_ids(report_id=report_id, item_id=item_id)
    _validate_typo_strength(strength)
    return {
        "service": "monitor",
        "action": "modify_typo_strength",
        "report_id": report_id,
        "item_id": item_id,
        "strength": strength,
    }


def build_delete_monitor_item_params(item_id: int) -> dict[str, Any]:
    _validate_positive_ids(item_id=item_id)
    return {
        "service": "monitor",
        "action": "report_item_delete",
        "item_id": item_id,
    }


def build_delete_monitor_report_params(report_id: int) -> dict[str, Any]:
    _validate_positive_ids(report_id=report_id)
    return {
        "service": "monitor",
        "action": "report_delete",
        "report_id": report_id,
    }
