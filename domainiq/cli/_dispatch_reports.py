"""CLI dispatchers for report commands."""

import argparse

from domainiq.protocols import ReportProtocol

from ._dispatch_common import _aggregate, _CommandResult, _run_command
from ._serialization import print_result

_REPORT_COMMANDS: tuple[str, ...] = (
    "domain_report",
    "name_report",
    "organization_report",
    "email_report",
    "ip_report",
)


def _run_report_command(
    client: ReportProtocol,
    args: argparse.Namespace,
    command: str,
) -> _CommandResult:
    method = getattr(client, command)
    value = getattr(args, command)
    return _run_command(lambda: print_result(method(value)))


def _dispatch_reports(
    client: ReportProtocol, args: argparse.Namespace
) -> _CommandResult:
    """Dispatch report commands. Returns (executed, had_errors)."""
    results = [
        _run_report_command(client, args, command)
        for command in _REPORT_COMMANDS
        if getattr(args, command)
    ]
    return _aggregate(results)


__all__ = ["_dispatch_reports"]
