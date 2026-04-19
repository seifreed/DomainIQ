"""WHOIS endpoint mixins (sync and async).

_WhoisMixin and _AsyncWhoisMixin are intentionally near-identical.
Python requires 'await' inside 'async def'; the two classes cannot share
implementation while maintaining correct coroutine semantics, mypy strict
compliance, and IDE support. All extractable logic lives in params.py and
deserializers.py; what remains is structural boilerplate.
"""

from __future__ import annotations

from typing import Any

from . import params as _params
from ._base_client import _AsyncRequestable, _SyncRequestable
from .deserializers import parse_whois_result
from .models import WhoisResult


class _WhoisMixin(_SyncRequestable):
    def whois_lookup(
        self,
        domain: str | None = None,
        ip: str | None = None,
        full: bool = False,
        current_only: bool = False,
    ) -> WhoisResult:
        """Perform WHOIS lookup for a domain or IP address."""
        params = _params.build_whois_params(domain, ip, full, current_only)
        return parse_whois_result(self._make_json_request(params))


# Async version mirrors sync; only await calls differ.
class _AsyncWhoisMixin(_AsyncRequestable):
    async def whois_lookup(
        self,
        domain: str | None = None,
        ip: str | None = None,
        full: bool = False,
        current_only: bool = False,
    ) -> WhoisResult:
        """Perform async WHOIS lookup for a domain or IP address."""
        params = _params.build_whois_params(domain, ip, full, current_only)
        return parse_whois_result(await self._make_json_request(params))
