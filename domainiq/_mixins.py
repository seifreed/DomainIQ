"""API endpoint mixins — re-exports from domain-specific modules.

Each API domain has its own module (e.g. _whois_mixin.py, _dns_mixin.py).
This file aggregates them so existing imports remain unchanged.
"""

from ._base_client import _AsyncRequestable, _SyncRequestable
from ._bulk_mixin import _AsyncBulkMixin, _BulkMixin
from ._dns_mixin import _AsyncDNSMixin, _DNSMixin
from ._domain_analysis_mixin import _AsyncDomainAnalysisMixin, _DomainAnalysisMixin
from ._monitor_mixin import _AsyncMonitorMixin, _MonitorMixin
from ._report_mixin import _AsyncReportMixin, _ReportMixin
from ._search_mixin import _AsyncSearchMixin, _SearchMixin
from ._whois_mixin import _AsyncWhoisMixin, _WhoisMixin

__all__ = [
    "_AsyncBulkMixin",
    "_AsyncDNSMixin",
    "_AsyncDomainAnalysisMixin",
    "_AsyncMonitorMixin",
    "_AsyncReportMixin",
    "_AsyncRequestable",
    "_AsyncSearchMixin",
    "_AsyncWhoisMixin",
    "_BulkMixin",
    "_DNSMixin",
    "_DomainAnalysisMixin",
    "_MonitorMixin",
    "_ReportMixin",
    "_SearchMixin",
    "_SyncRequestable",
    "_WhoisMixin",
]
