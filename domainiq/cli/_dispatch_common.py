"""Shared helpers for CLI command dispatchers."""

import argparse
import sys
from collections.abc import Callable
from typing import Any, NamedTuple

from domainiq.exceptions import DomainIQError


class _CommandResult(NamedTuple):
    executed: bool
    errored: bool


_DispatchFn = Callable[[Any, argparse.Namespace], _CommandResult]


def _run_command(fn: Callable[[], None]) -> _CommandResult:
    """Run fn and return (executed=True, had_errors). Catches DomainIQError."""
    try:
        fn()
        return _CommandResult(executed=True, errored=False)
    except DomainIQError as e:
        sys.stderr.write(f"Error: {e}\n")
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
