"""Report request-parameter builders."""

from __future__ import annotations

from typing import Any

from domainiq.exceptions import DomainIQValidationError
from domainiq.validators import validate_email

from ._shared import (
    require_non_empty_string,
    require_valid_domain,
    require_valid_ip,
    simple_service_params,
)


def build_domain_report_params(domain: str, *, cached: bool = False) -> dict[str, Any]:
    domain = domain.strip()
    require_valid_domain(domain)
    params = simple_service_params("domain_report", "domain", domain)
    if cached:
        params["cached"] = 1
    return params


def build_name_report_params(name: str) -> dict[str, Any]:
    require_non_empty_string(name, "name")
    return simple_service_params("name_report", "name", name.strip())


def build_organization_report_params(organization: str) -> dict[str, Any]:
    require_non_empty_string(organization, "organization")
    return simple_service_params(
        "organization_report", "organization", organization.strip()
    )


def build_email_report_params(email: str) -> dict[str, Any]:
    email = email.strip()
    if not validate_email(email):
        msg = f"Invalid email: {email}"
        raise DomainIQValidationError(msg, param_name="email")
    return simple_service_params("email_report", "email", email)


def build_ip_report_params(ip: str) -> dict[str, Any]:
    ip = ip.strip()
    require_valid_ip(ip)
    return simple_service_params("ip_report", "ip", ip)
