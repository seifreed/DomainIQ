"""DNS endpoint mixins (sync and async).

_DNSMixin and _AsyncDNSMixin are intentionally near-identical.
Python requires 'await' inside 'async def'; the two classes cannot share
implementation while maintaining correct coroutine semantics, mypy strict
compliance, and IDE support. All extractable logic lives in params.py and
deserializers.py; what remains is structural boilerplate.
"""

from __future__ import annotations

from . import params as _params
from ._base_client import _AsyncRequestable, _SyncRequestable
from .deserializers import parse_dns_result
from .models import DNSRecordType, DNSResult


class _DNSMixin(_SyncRequestable):
    def dns_lookup(
        self,
        query: str,
        record_types: list[str | DNSRecordType] | None = None,
    ) -> DNSResult:
        """Perform DNS lookup for a domain or hostname."""
        params = _params.build_dns_params(query, record_types)
        return parse_dns_result(self._make_json_request(params))


# Async version mirrors sync; only await calls differ.
class _AsyncDNSMixin(_AsyncRequestable):
    async def dns_lookup(
        self,
        query: str,
        record_types: list[str | DNSRecordType] | None = None,
    ) -> DNSResult:
        """Perform async DNS lookup for a domain or hostname."""
        params = _params.build_dns_params(query, record_types)
        return parse_dns_result(await self._make_json_request(params))
