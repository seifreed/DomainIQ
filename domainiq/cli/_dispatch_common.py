"""Shared helpers for CLI command dispatchers."""

import argparse
import contextlib
import sys
from collections.abc import Callable
from typing import Any, NamedTuple, Protocol

from domainiq.exceptions import DomainIQError


class _SupportsWrite(Protocol):
    def write(self, s: str, /) -> object: ...


class _CommandResult(NamedTuple):
    executed: bool
    errored: bool


_DispatchFn = Callable[[Any, argparse.Namespace], _CommandResult]


def _run_command(
    fn: Callable[[], None],
    *,
    stderr: _SupportsWrite | None = None,
) -> _CommandResult:
    """Run fn and return (executed=True, had_errors). Catches all expected errors."""
    stream = sys.stderr if stderr is None else stderr
    try:
        fn()
        return _CommandResult(executed=True, errored=False)
    except (DomainIQError, OSError) as e:
        with contextlib.suppress(OSError):
            stream.write(f"Error: {e}\n")
        return _CommandResult(executed=True, errored=True)


def _aggregate(results: list[_CommandResult]) -> _CommandResult:
    """Aggregate (executed, errored) results from multiple commands."""
    if not results:
        return _CommandResult(executed=False, errored=False)
    return _CommandResult(
        executed=any(r.executed for r in results),
        errored=any(r.errored for r in results),
    )


__all__ = ["_CommandResult", "_DispatchFn", "_aggregate", "_run_command"]
