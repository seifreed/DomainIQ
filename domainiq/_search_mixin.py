"""Search endpoint mixins (sync and async).

_SearchMixin and _AsyncSearchMixin are intentionally near-identical.
Python requires 'await' inside 'async def'; the two classes cannot share
implementation while maintaining correct coroutine semantics, mypy strict
compliance, and IDE support. All extractable logic lives in params.py and
deserializers.py; what remains is structural boilerplate.
"""

from __future__ import annotations

from typing import Any, Unpack

from . import params as _params
from ._base_client import _AsyncRequestable, _SyncRequestable
from .deserializers import parse_reverse_search_result, parse_search_result
from .models import (
    DomainSearchFilters,
    KeywordMatchType,
    ReverseIpSearchType,
    ReverseMxSearchType,
    ReverseMatchType,
    ReverseSearchResult,
    ReverseSearchType,
    SearchResult,
)


class _SearchMixin(_SyncRequestable):
    def domain_search(
        self,
        keywords: list[str],
        conditions: list[str] | None = None,
        match: KeywordMatchType = KeywordMatchType.ANY,
        filters: DomainSearchFilters | None = None,
        **kwargs: Unpack[DomainSearchFilters],
    ) -> SearchResult:
        """Search for domains matching keywords."""
        merged: DomainSearchFilters = {**(filters or {}), **kwargs}
        params = _params.build_domain_search_params(keywords, conditions, match, merged if merged else None)
        return parse_search_result(self._make_json_request(params))

    def reverse_search(
        self,
        search_type: str | ReverseSearchType,
        search_term: str,
        match: ReverseMatchType = ReverseMatchType.CONTAINS,
    ) -> ReverseSearchResult:
        """Perform reverse search by email, name, or organization."""
        return parse_reverse_search_result(
            self._make_json_request(
                _params.build_reverse_search_params(search_type, search_term, match)
            )
        )

    def reverse_dns(self, domain: str) -> ReverseSearchResult:
        """Perform reverse DNS search."""
        return parse_reverse_search_result(
            self._make_json_request(_params.build_reverse_dns_params(domain))
        )

    def reverse_ip(self, search_type: ReverseIpSearchType | str, data: str) -> ReverseSearchResult:
        """Perform reverse IP search."""
        return parse_reverse_search_result(
            self._make_json_request(_params.build_reverse_ip_params(search_type, data))
        )

    def reverse_mx(
        self, search_type: ReverseMxSearchType | str, data: str, recursive: bool = False
    ) -> ReverseSearchResult:
        """Perform reverse MX search."""
        return parse_reverse_search_result(
            self._make_json_request(_params.build_reverse_mx_params(search_type, data, recursive))
        )


# Async version mirrors sync; only await calls differ.
class _AsyncSearchMixin(_AsyncRequestable):
    async def domain_search(
        self,
        keywords: list[str],
        conditions: list[str] | None = None,
        match: KeywordMatchType = KeywordMatchType.ANY,
        filters: DomainSearchFilters | None = None,
        **kwargs: Unpack[DomainSearchFilters],
    ) -> SearchResult:
        """Search for domains matching keywords asynchronously."""
        merged: DomainSearchFilters = {**(filters or {}), **kwargs}
        params = _params.build_domain_search_params(keywords, conditions, match, merged if merged else None)
        return parse_search_result(await self._make_json_request(params))

    async def reverse_search(
        self,
        search_type: str | ReverseSearchType,
        search_term: str,
        match: ReverseMatchType = ReverseMatchType.CONTAINS,
    ) -> ReverseSearchResult:
        """Perform async reverse search."""
        return parse_reverse_search_result(
            await self._make_json_request(
                _params.build_reverse_search_params(search_type, search_term, match)
            )
        )

    async def reverse_dns(self, domain: str) -> ReverseSearchResult:
        """Perform async reverse DNS search."""
        return parse_reverse_search_result(
            await self._make_json_request(_params.build_reverse_dns_params(domain))
        )

    async def reverse_ip(self, search_type: ReverseIpSearchType | str, data: str) -> ReverseSearchResult:
        """Perform async reverse IP search."""
        return parse_reverse_search_result(
            await self._make_json_request(_params.build_reverse_ip_params(search_type, data))
        )

    async def reverse_mx(
        self, search_type: ReverseMxSearchType | str, data: str, recursive: bool = False
    ) -> ReverseSearchResult:
        """Perform async reverse MX search."""
        return parse_reverse_search_result(
            await self._make_json_request(
                _params.build_reverse_mx_params(search_type, data, recursive)
            )
        )
