"""Async concurrency helpers for bulk lookup operations."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from .exceptions import DomainIQPartialResultsError

if TYPE_CHECKING:
    from collections.abc import Coroutine, Iterable

logger = logging.getLogger(__name__)


class _LookupFailure:
    """Internal sentinel for a non-critical concurrent lookup failure."""

    def __init__(self, target: str, error: Exception) -> None:
        self.target = target
        self.error = error

    def __repr__(self) -> str:
        return f"_LookupFailure(target={self.target!r}, error={self.error!r})"


def _collect_task_results[T](
    tasks: list[asyncio.Task[Any]],
    expected_type: type[T],
) -> list[T | None]:
    """Collect task results aligned by submission order."""
    partials: list[T | None] = []
    for task in tasks:
        if task.done() and not task.cancelled() and task.exception() is None:
            result = task.result()
            partials.append(result if isinstance(result, expected_type) else None)
        else:
            partials.append(None)
    return partials


def _find_critical_exception(
    tasks: list[asyncio.Task[Any]],
) -> BaseException | None:
    """Return the first non-cancelled exception from done tasks, if any."""
    for task in tasks:
        if task.done() and not task.cancelled() and task.exception() is not None:
            return task.exception()
    return None


async def _cancel_and_settle(tasks: list[asyncio.Task[Any]]) -> None:
    """Cancel all unfinished tasks and await their termination."""
    for task in tasks:
        if not task.done():
            task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


async def _run_with_critical_cancel[T](
    coros: Iterable[Coroutine[Any, Any, Any]],
    expected_type: type[T],
) -> list[T | None]:
    """Run lookup awaitables, cancelling pending work on first exception.

    Non-critical failures are represented by sentinel values returned by the
    awaitables. Escaped exceptions are treated as critical and re-raised as
    DomainIQPartialResultsError with aligned partial results.
    """
    tasks: list[asyncio.Task[Any]] = [asyncio.create_task(coro) for coro in coros]

    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
    except (Exception, asyncio.CancelledError):
        await _cancel_and_settle(tasks)
        raise

    critical = _find_critical_exception(tasks)
    if critical is not None:
        for task in tasks:
            if task.done() and not task.cancelled():
                exc = task.exception()
                if exc is not None and exc is not critical:
                    logger.warning("Additional critical exception discarded: %s", exc)
        await _cancel_and_settle(tasks)
        partials = _collect_task_results(tasks, expected_type)
        raise DomainIQPartialResultsError(critical, partials) from critical

    return _collect_task_results(tasks, expected_type)


__all__ = ["_LookupFailure", "_run_with_critical_cancel"]
