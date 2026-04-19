"""Bulk operation endpoint mixins (sync and async).

_BulkMixin and _AsyncBulkMixin are intentionally near-identical.
Python requires 'await' inside 'async def'; the two classes cannot share
implementation while maintaining correct coroutine semantics, mypy strict
compliance, and IDE support. All extractable logic lives in params.py and
deserializers.py; what remains is structural boilerplate.
"""

from __future__ import annotations

from typing import Any

from . import params as _params
from ._base_client import _AsyncRequestable, _SyncRequestable
from .models import BulkWhoisType
from .utils import csv_to_dict_list


class _BulkMixin(_SyncRequestable):
    def bulk_dns(self, domains: list[str]) -> list[dict[str, Any]]:
        """Perform bulk DNS lookups."""
        csv_response = self._make_csv_request(_params.build_bulk_dns_params(domains))
        return csv_to_dict_list(csv_response) if csv_response else []

    def bulk_whois(self, items: list[str], lookup_type: BulkWhoisType = BulkWhoisType.LIVE) -> list[dict[str, Any]]:
        """Perform bulk WHOIS lookups."""
        csv_response = self._make_csv_request(_params.build_bulk_whois_params(items, lookup_type))
        return csv_to_dict_list(csv_response) if csv_response else []

    def bulk_whois_ip(self, domains: list[str]) -> list[dict[str, Any]]:
        """Perform bulk domain IP WHOIS lookups."""
        csv_response = self._make_csv_request(_params.build_bulk_whois_ip_params(domains))
        return csv_to_dict_list(csv_response) if csv_response else []


# Async version mirrors sync; only await calls differ.
class _AsyncBulkMixin(_AsyncRequestable):
    async def bulk_dns(self, domains: list[str]) -> list[dict[str, Any]]:
        """Perform bulk DNS lookups asynchronously."""
        csv_response = await self._make_csv_request(_params.build_bulk_dns_params(domains))
        return csv_to_dict_list(csv_response) if csv_response else []

    async def bulk_whois(self, items: list[str], lookup_type: BulkWhoisType = BulkWhoisType.LIVE) -> list[dict[str, Any]]:
        """Perform bulk WHOIS lookups asynchronously."""
        csv_response = await self._make_csv_request(_params.build_bulk_whois_params(items, lookup_type))
        return csv_to_dict_list(csv_response) if csv_response else []

    async def bulk_whois_ip(self, domains: list[str]) -> list[dict[str, Any]]:
        """Perform bulk domain IP WHOIS lookups asynchronously."""
        csv_response = await self._make_csv_request(_params.build_bulk_whois_ip_params(domains))
        return csv_to_dict_list(csv_response) if csv_response else []
