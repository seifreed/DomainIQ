"""Helpers shared across internal parameter-builder modules."""

from __future__ import annotations

from typing import Any

from domainiq.exceptions import DomainIQValidationError
from domainiq.utils import enum_value
from domainiq.validators import is_ip_address, validate_domain


def validate_type_value(
    value: object,
    valid_values: set[str] | frozenset[str],
    param_name: str = "type",
) -> str:
    """Validate an enum-or-string choice against its allowed wire values."""
    wire_value = enum_value(value)
    if not isinstance(wire_value, str) or wire_value not in valid_values:
        msg = f"Invalid {param_name}: {wire_value}"
        raise DomainIQValidationError(msg, param_name=param_name)
    return wire_value


def require_valid_domain(value: str, param_name: str = "domain") -> None:
    """Raise when a value is not a valid registrable domain name."""
    if not validate_domain(value):
        msg = f"Invalid domain: {value}"
        raise DomainIQValidationError(msg, param_name=param_name)


def require_valid_ip(value: str, param_name: str = "ip") -> None:
    """Raise when a value is not a valid IPv4 or IPv6 address."""
    if not is_ip_address(value):
        msg = f"Invalid IP address: {value}"
        raise DomainIQValidationError(msg, param_name=param_name)


def require_valid_domains(items: list[str], param_name: str) -> None:
    """Raise when any list item is not a valid registrable domain name."""
    for item in items:
        require_valid_domain(item, param_name)


def require_non_empty(name: str, items: list[Any]) -> None:
    """Raise when a list-like request argument is empty or has empty entries."""
    if not items:
        msg = f"{name} must not be empty"
        raise DomainIQValidationError(msg, param_name=name)
    if any(
        item is None or (isinstance(item, str) and not item.strip()) for item in items
    ):
        msg = f"{name} must not contain empty values"
        raise DomainIQValidationError(msg, param_name=name)


def require_non_empty_string(value: str, name: str) -> None:
    """Raise when a required string argument is empty or whitespace-only."""
    if not isinstance(value, str) or not value.strip():
        msg = f"{name} must not be empty or whitespace-only"
        raise DomainIQValidationError(msg, param_name=name)


def simple_service_params(service: str, key: str, value: str) -> dict[str, Any]:
    """Build a trivial {'service': ..., key: value} payload."""
    return {"service": service, key: value}
