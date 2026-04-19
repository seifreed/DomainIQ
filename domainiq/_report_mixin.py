"""Report endpoint mixins (sync and async).

_ReportMixin and _AsyncReportMixin are intentionally near-identical.
Python requires 'await' inside 'async def'; the two classes cannot share
implementation while maintaining correct coroutine semantics, mypy strict
compliance, and IDE support. All extractable logic lives in params.py and
deserializers.py; what remains is structural boilerplate.
"""

from __future__ import annotations

from typing import cast

from . import params as _params
from ._base_client import _AsyncRequestable, _SyncRequestable
from .deserializers import parse_domain_report, parse_ip_report_result
from .models import (
    DomainReport,
    EmailReportResult,
    IpReportResult,
    NameReportResult,
    OrganizationReportResult,
)


class _ReportMixin(_SyncRequestable):
    def domain_report(self, domain: str) -> DomainReport:
        """Get comprehensive domain report."""
        return parse_domain_report(self._make_json_request(_params.build_domain_report_params(domain)))

    def name_report(self, name: str) -> NameReportResult:
        """Get registrant name report."""
        return cast(NameReportResult, self._make_json_request(_params.build_name_report_params(name)))

    def organization_report(self, organization: str) -> OrganizationReportResult:
        """Get registrant organization report."""
        return cast(OrganizationReportResult, self._make_json_request(_params.build_organization_report_params(organization)))

    def email_report(self, email: str) -> EmailReportResult:
        """Get registrant email report."""
        return cast(EmailReportResult, self._make_json_request(_params.build_email_report_params(email)))

    def ip_report(self, ip: str) -> IpReportResult:
        """Get IP address summary report."""
        return parse_ip_report_result(self._make_json_request(_params.build_ip_report_params(ip)))


# Async version mirrors sync; only await calls differ.
class _AsyncReportMixin(_AsyncRequestable):
    async def domain_report(self, domain: str) -> DomainReport:
        """Get comprehensive domain report asynchronously."""
        return parse_domain_report(
            await self._make_json_request(_params.build_domain_report_params(domain))
        )

    async def name_report(self, name: str) -> NameReportResult:
        """Get registrant name report asynchronously."""
        return cast(NameReportResult, await self._make_json_request(_params.build_name_report_params(name)))

    async def organization_report(self, organization: str) -> OrganizationReportResult:
        """Get registrant organization report asynchronously."""
        return cast(OrganizationReportResult, await self._make_json_request(_params.build_organization_report_params(organization)))

    async def email_report(self, email: str) -> EmailReportResult:
        """Get registrant email report asynchronously."""
        return cast(EmailReportResult, await self._make_json_request(_params.build_email_report_params(email)))

    async def ip_report(self, ip: str) -> IpReportResult:
        """Get IP address summary report asynchronously."""
        return parse_ip_report_result(await self._make_json_request(_params.build_ip_report_params(ip)))
