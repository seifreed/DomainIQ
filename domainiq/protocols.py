"""Backward-compatible protocol exports.

Concrete protocol definitions live in ``domainiq._protocols`` so sync and
async capability contracts can evolve independently without breaking existing
``domainiq.protocols`` imports.
"""

from ._protocols import (
    AsyncBulkProtocol,
    AsyncDNSProtocol,
    AsyncDomainAnalysisProtocol,
    AsyncDomainIQClientProtocol,
    AsyncLimitsProtocol,
    AsyncMonitorProtocol,
    AsyncQueueProtocol,
    AsyncReportProtocol,
    AsyncSearchProtocol,
    AsyncWhoisProtocol,
    BulkProtocol,
    DNSProtocol,
    DomainAnalysisProtocol,
    DomainIQClientProtocol,
    LimitsProtocol,
    MonitorProtocol,
    QueueProtocol,
    ReportProtocol,
    SearchProtocol,
    WhoisProtocol,
)

__all__ = [
    "AsyncBulkProtocol",
    "AsyncDNSProtocol",
    "AsyncDomainAnalysisProtocol",
    "AsyncDomainIQClientProtocol",
    "AsyncLimitsProtocol",
    "AsyncMonitorProtocol",
    "AsyncQueueProtocol",
    "AsyncReportProtocol",
    "AsyncSearchProtocol",
    "AsyncWhoisProtocol",
    "BulkProtocol",
    "DNSProtocol",
    "DomainAnalysisProtocol",
    "DomainIQClientProtocol",
    "LimitsProtocol",
    "MonitorProtocol",
    "QueueProtocol",
    "ReportProtocol",
    "SearchProtocol",
    "WhoisProtocol",
]
