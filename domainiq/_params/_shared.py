"""Helpers shared across internal parameter-builder modules."""

from __future__ import annotations

from typing import Any

from domainiq.exceptions import DomainIQValidationError


def require_non_empty(name: str, items: list[Any]) -> None:
    """Raise when a list-like request argument is empty."""
    if not items:
        msg = f"{name} must not be empty"
        raise DomainIQValidationError(msg, param_name=name)


def simple_service_params(service: str, key: str, value: str) -> dict[str, Any]:
    """Build a trivial {'service': ..., key: value} payload."""
    return {"service": service, key: value}
