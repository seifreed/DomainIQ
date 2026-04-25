"""Report request-parameter builders."""

from __future__ import annotations

from typing import Any

from domainiq.exceptions import DomainIQValidationError
from domainiq.validators import is_ip_address, validate_domain, validate_email

from ._shared import simple_service_params


def _validate_required_string(value: str, param_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        msg = f"{param_name} must not be empty or whitespace-only"
        raise DomainIQValidationError(msg, param_name=param_name)


def build_domain_report_params(domain: str) -> dict[str, Any]:
    if not validate_domain(domain):
        msg = f"Invalid domain: {domain}"
        raise DomainIQValidationError(msg, param_name="domain")
    return simple_service_params("domain_report", "domain", domain)


def build_name_report_params(name: str) -> dict[str, Any]:
    _validate_required_string(name, "name")
    return simple_service_params("name_report", "name", name)


def build_organization_report_params(organization: str) -> dict[str, Any]:
    _validate_required_string(organization, "organization")
    return simple_service_params("organization_report", "organization", organization)


def build_email_report_params(email: str) -> dict[str, Any]:
    if not validate_email(email):
        msg = f"Invalid email: {email}"
        raise DomainIQValidationError(msg, param_name="email")
    return simple_service_params("email_report", "email", email)


def build_ip_report_params(ip: str) -> dict[str, Any]:
    if not is_ip_address(ip):
        msg = f"Invalid IP address: {ip}"
        raise DomainIQValidationError(msg, param_name="ip")
    return simple_service_params("ip_report", "ip", ip)
