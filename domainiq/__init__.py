"""DomainIQ Python Library - A modern Python client for the DomainIQ API.

This library provides both synchronous and asynchronous clients for interacting
with the DomainIQ API, enabling domain intelligence gathering, WHOIS lookups,
DNS queries, and monitoring capabilities.
"""

from .client import DomainIQClient
from .exceptions import (
    DomainIQAPIError,
    DomainIQAuthenticationError,
    DomainIQError,
    DomainIQRateLimitError,
    DomainIQTimeoutError,
)
from .models import (
    DNSResult,
    DomainReport,
    MonitorReport,
    WhoisResult,
)

__version__ = "2.0.0"
__author__ = "seifreed"
__email__ = "contact@example.com"
__license__ = "MIT"

__all__ = [
    "DNSResult",
    "DomainIQAPIError",
    "DomainIQAuthenticationError",
    "DomainIQClient",
    "DomainIQError",
    "DomainIQRateLimitError",
    "DomainIQTimeoutError",
    "DomainReport",
    "MonitorReport",
    "WhoisResult",
]
