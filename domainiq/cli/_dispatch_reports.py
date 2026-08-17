"""CLI dispatchers for report commands."""

from typing import TYPE_CHECKING

from ._dispatch_common import _aggregate, _CommandResult, _run_command
from ._serialization import print_result

if TYPE_CHECKING:
    import argparse

    from domainiq.protocols import ReportProtocol

_REPORT_COMMANDS: tuple[str, ...] = (
    "domain_report",
    "name_report",
    "organization_report",
    "email_report",
    "ip_report",
)

# Per-command keyword options sourced from extra CLI flags.
_REPORT_OPTION_FLAGS: dict[str, tuple[str, ...]] = {
    "domain_report": ("cached",),
}


def _run_report_command(
    client: ReportProtocol,
    args: argparse.Namespace,
    command: str,
) -> _CommandResult:
    method = getattr(client, command)
    value = getattr(args, command)
    options = {
        flag: getattr(args, flag) for flag in _REPORT_OPTION_FLAGS.get(command, ())
    }
    return _run_command(lambda: print_result(method(value, **options)))


def _dispatch_reports(
    client: ReportProtocol, args: argparse.Namespace
) -> _CommandResult:
    """Dispatch report commands. Returns (executed, had_errors)."""
    results = [
        _run_report_command(client, args, command)
        for command in _REPORT_COMMANDS
        if getattr(args, command) is not None
    ]
    return _aggregate(results)


__all__ = ["_dispatch_reports"]
