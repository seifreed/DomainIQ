"""Domain analysis endpoint mixins (sync and async).

_DomainAnalysisMixin and _AsyncDomainAnalysisMixin are intentionally near-identical.
Python requires 'await' inside 'async def'; the two classes cannot share
implementation while maintaining correct coroutine semantics, mypy strict
compliance, and IDE support. All extractable logic lives in params.py and
deserializers.py; what remains is structural boilerplate.
"""

from __future__ import annotations

from . import params as _params
from ._base_client import _AsyncRequestable, _SyncRequestable
from .constants import SNAPSHOT_DEFAULT_HEIGHT, SNAPSHOT_DEFAULT_LIMIT, SNAPSHOT_DEFAULT_WIDTH
from .deserializers import parse_domain_category, parse_domain_snapshot
from .models import DomainCategory, DomainSnapshot, SnapshotOptions
from .utils import ensure_list_of_models


class _DomainAnalysisMixin(_SyncRequestable):
    def domain_categorize(self, domains: list[str]) -> list[DomainCategory]:
        """Categorize domain names."""
        params = _params.build_domain_categorize_params(domains)
        return ensure_list_of_models(self._make_json_request_maybe_list(params), parse_domain_category)

    def domain_snapshot(
        self,
        domain: str,
        options: SnapshotOptions | None = None,
    ) -> DomainSnapshot:
        """Get a snapshot of a domain."""
        params = _params.build_domain_snapshot_params(domain, options or SnapshotOptions())
        return parse_domain_snapshot(self._make_json_request(params))

    def domain_snapshot_history(
        self,
        domain: str,
        width: int = SNAPSHOT_DEFAULT_WIDTH,
        height: int = SNAPSHOT_DEFAULT_HEIGHT,
        limit: int = SNAPSHOT_DEFAULT_LIMIT,
    ) -> list[DomainSnapshot]:
        """Get snapshot history for a domain."""
        params = _params.build_domain_snapshot_history_params(domain, width, height, limit)
        return ensure_list_of_models(self._make_json_request_maybe_list(params), parse_domain_snapshot)


# Async version mirrors sync; only await calls differ.
class _AsyncDomainAnalysisMixin(_AsyncRequestable):
    async def domain_categorize(self, domains: list[str]) -> list[DomainCategory]:
        """Categorize domain names asynchronously."""
        params = _params.build_domain_categorize_params(domains)
        return ensure_list_of_models(
            await self._make_json_request_maybe_list(params), parse_domain_category
        )

    async def domain_snapshot(
        self,
        domain: str,
        options: SnapshotOptions | None = None,
    ) -> DomainSnapshot:
        """Get a snapshot of a domain asynchronously."""
        params = _params.build_domain_snapshot_params(domain, options or SnapshotOptions())
        return parse_domain_snapshot(await self._make_json_request(params))

    async def domain_snapshot_history(
        self,
        domain: str,
        width: int = SNAPSHOT_DEFAULT_WIDTH,
        height: int = SNAPSHOT_DEFAULT_HEIGHT,
        limit: int = SNAPSHOT_DEFAULT_LIMIT,
    ) -> list[DomainSnapshot]:
        """Get snapshot history for a domain asynchronously."""
        params = _params.build_domain_snapshot_history_params(domain, width, height, limit)
        return ensure_list_of_models(
            await self._make_json_request_maybe_list(params), parse_domain_snapshot
        )
