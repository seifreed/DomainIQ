"""Shared fixtures for transport-based unit tests."""

from __future__ import annotations

import argparse
from typing import Any, NamedTuple, Self

import pytest

from domainiq import DomainIQClient
from domainiq.async_client import AsyncDomainIQClient
from domainiq.config import Config
from domainiq.http_transport import AsyncResponse, SyncResponse


def make_cli_args(**kwargs: Any) -> argparse.Namespace:
    """Build a Namespace with all CLI attributes defaulted to None/False."""
    defaults: dict[str, Any] = {
        "api_key": None,
        "config_file": None,
        "verbose": False,
        "debug": False,
        "timeout": 30,
        "whois_lookup": None,
        "full": False,
        "current_only": False,
        "dns_lookup": None,
        "types": None,
        "domain_categorize": None,
        "domain_snapshot": None,
        "domain_snapshot_history": None,
        "snapshot_limit": None,
        "snapshot_full": False,
        "no_cache": False,
        "raw": False,
        "width": None,
        "height": None,
        "domain_report": None,
        "cached": False,
        "name_report": None,
        "organization_report": None,
        "email_report": None,
        "ip_report": None,
        "domain_search": None,
        "conditions": None,
        "match": "any",
        "count_only": False,
        "exclude_dashed": False,
        "exclude_numbers": False,
        "exclude_idn": False,
        "min_length": None,
        "max_length": None,
        "min_create_date": None,
        "max_create_date": None,
        "search_limit": None,
        "reverse_search_type": None,
        "reverse_search": None,
        "reverse_match": "contains",
        "reverse_dns": None,
        "reverse_ip_type": None,
        "reverse_ip_data": None,
        "reverse_mx_type": None,
        "reverse_mx_data": None,
        "recursive": False,
        "bulk_dns": None,
        "bulk_dns_type": None,
        "bulk_whois": None,
        "bulk_whois_type": "live",
        "bulk_whois_ip": None,
        "monitor_list": False,
        "monitor_report_items": None,
        "monitor_report_summary": None,
        "monitor_item": None,
        "monitor_range": None,
        "monitor_report_changes": None,
        "monitor_change": None,
        "queue_hash": None,
        "queue_action": None,
        "submit_queued": None,
        "queued_param": None,
        "limits": False,
        "create_monitor_report": None,
        "email_alert": True,
        "add_monitor_item": None,
        "monitor_domain_alert": None,
        "monitor_match_types": None,
        "monitor_join_types": None,
        "monitor_use_typos": None,
        "monitor_typo_strength": None,
        "enable_typos": None,
        "disable_typos": None,
        "modify_typo_strength": None,
        "delete_monitor_item": None,
        "delete_monitor_report": None,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


class RecordedCall(NamedTuple):
    """A single recorded call to a StubClient method."""

    args: tuple[object, ...]
    kwargs: dict[str, object]


class StubClient:
    """In-memory DomainIQ client double for CLI dispatch/handler tests.

    A real, explicit class (no mock library): every method records its
    call and returns a per-method configured value (default ``None``, which
    ``print_result`` serialises harmlessly) or raises a configured exception.
    """

    def __init__(self) -> None:
        self.calls: dict[str, list[RecordedCall]] = {}
        self._results: dict[str, object] = {}
        self._errors: dict[str, BaseException] = {}

    def set_result(self, method: str, value: object) -> None:
        self._results[method] = value

    def set_error(self, method: str, exc: BaseException) -> None:
        self._errors[method] = exc

    def calls_to(self, method: str) -> list[RecordedCall]:
        return self.calls.get(method, [])

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _record(
        self, method: str, args: tuple[object, ...], kwargs: dict[str, object]
    ) -> object:
        self.calls.setdefault(method, []).append(RecordedCall(args, kwargs))
        if method in self._errors:
            raise self._errors[method]
        return self._results.get(method)

    def whois_lookup(self, *args: object, **kwargs: object) -> object:
        return self._record("whois_lookup", args, kwargs)

    def dns_lookup(self, *args: object, **kwargs: object) -> object:
        return self._record("dns_lookup", args, kwargs)

    def domain_categorize(self, *args: object, **kwargs: object) -> object:
        return self._record("domain_categorize", args, kwargs)

    def domain_snapshot(self, *args: object, **kwargs: object) -> object:
        return self._record("domain_snapshot", args, kwargs)

    def domain_snapshot_history(self, *args: object, **kwargs: object) -> object:
        return self._record("domain_snapshot_history", args, kwargs)

    def domain_search(self, *args: object, **kwargs: object) -> object:
        return self._record("domain_search", args, kwargs)

    def reverse_search(self, *args: object, **kwargs: object) -> object:
        return self._record("reverse_search", args, kwargs)

    def reverse_dns(self, *args: object, **kwargs: object) -> object:
        return self._record("reverse_dns", args, kwargs)

    def reverse_ip(self, *args: object, **kwargs: object) -> object:
        return self._record("reverse_ip", args, kwargs)

    def reverse_mx(self, *args: object, **kwargs: object) -> object:
        return self._record("reverse_mx", args, kwargs)

    def bulk_dns(self, *args: object, **kwargs: object) -> object:
        return self._record("bulk_dns", args, kwargs)

    def bulk_whois(self, *args: object, **kwargs: object) -> object:
        return self._record("bulk_whois", args, kwargs)

    def bulk_whois_ip(self, *args: object, **kwargs: object) -> object:
        return self._record("bulk_whois_ip", args, kwargs)

    def domain_report(self, *args: object, **kwargs: object) -> object:
        return self._record("domain_report", args, kwargs)

    def name_report(self, *args: object, **kwargs: object) -> object:
        return self._record("name_report", args, kwargs)

    def organization_report(self, *args: object, **kwargs: object) -> object:
        return self._record("organization_report", args, kwargs)

    def email_report(self, *args: object, **kwargs: object) -> object:
        return self._record("email_report", args, kwargs)

    def ip_report(self, *args: object, **kwargs: object) -> object:
        return self._record("ip_report", args, kwargs)

    def monitor_list(self, *args: object, **kwargs: object) -> object:
        return self._record("monitor_list", args, kwargs)

    def monitor_report_items(self, *args: object, **kwargs: object) -> object:
        return self._record("monitor_report_items", args, kwargs)

    def monitor_report_summary(self, *args: object, **kwargs: object) -> object:
        return self._record("monitor_report_summary", args, kwargs)

    def monitor_report_changes(self, *args: object, **kwargs: object) -> object:
        return self._record("monitor_report_changes", args, kwargs)

    def create_monitor_report(self, *args: object, **kwargs: object) -> object:
        return self._record("create_monitor_report", args, kwargs)

    def add_monitor_item(self, *args: object, **kwargs: object) -> object:
        return self._record("add_monitor_item", args, kwargs)

    def enable_typos(self, *args: object, **kwargs: object) -> object:
        return self._record("enable_typos", args, kwargs)

    def disable_typos(self, *args: object, **kwargs: object) -> object:
        return self._record("disable_typos", args, kwargs)

    def modify_typo_strength(self, *args: object, **kwargs: object) -> object:
        return self._record("modify_typo_strength", args, kwargs)

    def delete_monitor_item(self, *args: object, **kwargs: object) -> object:
        return self._record("delete_monitor_item", args, kwargs)

    def delete_monitor_report(self, *args: object, **kwargs: object) -> object:
        return self._record("delete_monitor_report", args, kwargs)

    def check_queue(self, *args: object, **kwargs: object) -> object:
        return self._record("check_queue", args, kwargs)

    def submit_queued(self, *args: object, **kwargs: object) -> object:
        return self._record("submit_queued", args, kwargs)

    def account_limits(self, *args: object, **kwargs: object) -> object:
        return self._record("account_limits", args, kwargs)

    def close(self) -> None:
        self._record("close", (), {})


# ---------------------------------------------------------------------------
# Sync mock transport
# ---------------------------------------------------------------------------


class MockSyncTransport:
    """Enqueues responses or exceptions; records all calls."""

    def __init__(self) -> None:
        self._queue: list[SyncResponse | BaseException] = []
        self.calls: list[dict[str, Any]] = []

    def enqueue(self, item: SyncResponse | BaseException) -> None:
        self._queue.append(item)

    def get(self, url: str, params: dict[str, str], timeout: float) -> SyncResponse:
        self.calls.append({"url": url, "params": params, "timeout": timeout})
        if not self._queue:
            msg = (
                "MockSyncTransport: no more enqueued responses "
                f"(call #{len(self.calls)})"
            )
            raise AssertionError(msg)
        item = self._queue.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    @property
    def is_open(self) -> bool:
        return True

    def close(self) -> None:
        pass


def make_sync_response(
    status_code: int = 200,
    body: str = "{}",
    headers: dict[str, str] | None = None,
) -> SyncResponse:
    return SyncResponse(
        status_code=status_code,
        headers=headers or {},
        text=body,
    )


# ---------------------------------------------------------------------------
# Async mock transport
# ---------------------------------------------------------------------------


class MockAsyncTransport:
    """Async version of MockSyncTransport."""

    def __init__(self) -> None:
        self._queue: list[AsyncResponse | BaseException] = []
        self.calls: list[dict[str, Any]] = []

    def enqueue(self, item: AsyncResponse | BaseException) -> None:
        self._queue.append(item)

    async def get(
        self, url: str, params: dict[str, str], request_timeout: float
    ) -> AsyncResponse:
        self.calls.append({"url": url, "params": params, "timeout": request_timeout})
        if not self._queue:
            msg = (
                "MockAsyncTransport: no more enqueued responses "
                f"(call #{len(self.calls)})"
            )
            raise AssertionError(msg)
        item = self._queue.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    @property
    def is_open(self) -> bool:
        return True

    async def close(self) -> None:
        pass


def make_async_response(
    status: int = 200,
    body: str = "{}",
    headers: dict[str, str] | None = None,
) -> AsyncResponse:
    return AsyncResponse(
        status=status,
        headers=headers or {},
        _body=body,
    )


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------
#
# Retry tests stay fast without patching stdlib sleep: the clients accept an
# injectable ``sleeper``, so fixtures pass real no-op sleep functions instead
# of monkeypatching ``time.sleep`` / ``asyncio.sleep``.


def _noop_sleep(_: float) -> None:
    return None


async def _async_noop_sleep(_: float) -> None:
    return None


@pytest.fixture
def mock_transport() -> MockSyncTransport:
    return MockSyncTransport()


@pytest.fixture
def mock_client(mock_transport: MockSyncTransport) -> DomainIQClient:
    config = Config(api_key="test-key-fixture", timeout=5, max_retries=3, retry_delay=0)
    return DomainIQClient(config=config, transport=mock_transport, sleeper=_noop_sleep)


@pytest.fixture
def mock_async_transport() -> MockAsyncTransport:
    return MockAsyncTransport()


@pytest.fixture
def mock_async_client(mock_async_transport: MockAsyncTransport) -> AsyncDomainIQClient:
    config = Config(api_key="test-key-fixture", timeout=5, max_retries=3, retry_delay=0)
    return AsyncDomainIQClient(
        config=config, transport=mock_async_transport, sleeper=_async_noop_sleep
    )
