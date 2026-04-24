"""Dispatcher registry and command routing for the DomainIQ CLI."""

import argparse
import sys
from collections.abc import Callable
from functools import partial
from typing import Any, NamedTuple

from ..constants import (
    EXIT_ERROR,
    EXIT_NO_COMMAND,
    EXIT_PARTIAL,
    EXIT_SUCCESS,
    SNAPSHOT_DEFAULT_LIMIT,
)
from ..exceptions import DomainIQError
from ..models import BulkWhoisType, ReverseMatchType
from ..protocols import (
    BulkProtocol,
    DNSProtocol,
    DomainAnalysisProtocol,
    DomainIQClientProtocol,
    MonitorProtocol,
    ReportProtocol,
    SearchProtocol,
    WhoisProtocol,
)
from ._handlers import (
    build_snapshot_options,
    handle_dns_lookup,
    handle_domain_search,
    handle_whois_lookup,
    print_result,
)
from ._types import DnsArgs, DomainSearchArgs, WhoisArgs


class _CommandResult(NamedTuple):
    executed: bool
    errored: bool


_DispatchFn = Callable[[Any, "argparse.Namespace"], _CommandResult]
_DISPATCHERS: list[_DispatchFn] = []


def _dispatcher(fn: _DispatchFn) -> _DispatchFn:
    """Register fn as a CLI command dispatcher."""
    _DISPATCHERS.append(fn)
    return fn


def _run_command(fn: Callable[[], None]) -> _CommandResult:
    """Run fn and return (executed=True, had_errors). Catches DomainIQError."""
    try:
        fn()
        return _CommandResult(executed=True, errored=False)
    except DomainIQError as e:
        print(f"Error: {e}", file=sys.stderr)
        return _CommandResult(executed=True, errored=True)


def _aggregate(results: list[_CommandResult]) -> _CommandResult:
    """Aggregate (executed, errored) results from multiple commands."""
    if not results:
        return _CommandResult(executed=False, errored=False)
    return _CommandResult(
        executed=any(r.executed for r in results),
        errored=any(r.errored for r in results),
    )


@_dispatcher
def _dispatch_whois(client: WhoisProtocol, args: argparse.Namespace) -> _CommandResult:
    """Dispatch WHOIS commands. Returns (executed, had_errors)."""
    if args.whois_lookup:
        return _run_command(partial(handle_whois_lookup, client, WhoisArgs.from_namespace(args)))
    return _CommandResult(executed=False, errored=False)


@_dispatcher
def _dispatch_dns(client: DNSProtocol, args: argparse.Namespace) -> _CommandResult:
    """Dispatch DNS commands. Returns (executed, had_errors)."""
    if args.dns_lookup:
        return _run_command(partial(handle_dns_lookup, client, DnsArgs.from_namespace(args)))
    return _CommandResult(executed=False, errored=False)


@_dispatcher
def _dispatch_domain_analysis(
    client: DomainAnalysisProtocol, args: argparse.Namespace
) -> _CommandResult:
    """Dispatch domain analysis commands. Returns (executed, had_errors)."""
    results = []
    if args.domain_categorize:
        results.append(_run_command(
            lambda: print_result(client.domain_categorize(args.domain_categorize))
        ))
    if args.domain_snapshot:
        opts = build_snapshot_options(args)
        results.append(_run_command(lambda: print_result(
            client.domain_snapshot(args.domain_snapshot, options=opts)
        )))
    if args.domain_snapshot_history:
        opts = build_snapshot_options(args)
        results.append(_run_command(lambda: print_result(
            client.domain_snapshot_history(
                args.domain_snapshot_history,
                width=opts.width,
                height=opts.height,
                limit=args.snapshot_limit if args.snapshot_limit is not None else SNAPSHOT_DEFAULT_LIMIT,
            )
        )))
    return _aggregate(results)


_REPORT_COMMANDS: tuple[str, ...] = (
    "domain_report", "name_report", "organization_report", "email_report", "ip_report"
)


@_dispatcher
def _dispatch_reports(
    client: ReportProtocol, args: argparse.Namespace
) -> _CommandResult:
    """Dispatch report commands. Returns (executed, had_errors)."""
    results = [
        _run_command(lambda cmd=cmd: print_result(getattr(client, cmd)(getattr(args, cmd))))
        for cmd in _REPORT_COMMANDS
        if getattr(args, cmd)
    ]
    return _aggregate(results)


@_dispatcher
def _dispatch_search(
    client: SearchProtocol, args: argparse.Namespace
) -> _CommandResult:
    """Dispatch search commands. Returns (executed, had_errors)."""
    results = []
    if args.domain_search:
        results.append(_run_command(partial(handle_domain_search, client, DomainSearchArgs.from_namespace(args))))
    if args.reverse_search_type and args.reverse_search:
        results.append(_run_command(lambda: print_result(
            client.reverse_search(
                args.reverse_search_type,
                args.reverse_search,
                match=ReverseMatchType(args.reverse_match),
            )
        )))
    if args.reverse_dns:
        results.append(_run_command(lambda: print_result(client.reverse_dns(args.reverse_dns))))
    if args.reverse_ip_type and args.reverse_ip_data:
        results.append(_run_command(
            lambda: print_result(client.reverse_ip(args.reverse_ip_type, args.reverse_ip_data))
        ))
    if args.reverse_mx_type and args.reverse_mx_data:
        results.append(_run_command(lambda: print_result(
            client.reverse_mx(
                args.reverse_mx_type, args.reverse_mx_data, recursive=args.recursive
            )
        )))
    return _aggregate(results)


@_dispatcher
def _dispatch_bulk(
    client: BulkProtocol, args: argparse.Namespace
) -> _CommandResult:
    """Dispatch bulk operation commands. Returns (executed, had_errors)."""
    results = []
    if args.bulk_dns:
        results.append(_run_command(lambda: print_result(client.bulk_dns(args.bulk_dns))))
    if args.bulk_whois:
        results.append(_run_command(
            lambda: print_result(client.bulk_whois(args.bulk_whois, BulkWhoisType(args.bulk_whois_type)))
        ))
    if args.bulk_whois_ip:
        results.append(_run_command(lambda: print_result(client.bulk_whois_ip(args.bulk_whois_ip))))
    return _aggregate(results)


@_dispatcher
def _dispatch_monitor(
    client: MonitorProtocol, args: argparse.Namespace
) -> _CommandResult:
    """Dispatch monitoring commands. Returns (executed, had_errors)."""
    results = []
    if args.monitor_list:
        results.append(_run_command(lambda: print_result(client.monitor_list())))
    if args.monitor_report_items is not None:
        results.append(_run_command(
            lambda: print_result(client.monitor_report_items(args.monitor_report_items))
        ))
    if args.monitor_report_summary is not None:
        results.append(_run_command(lambda: print_result(
            client.monitor_report_summary(
                args.monitor_report_summary,
                item_id=args.monitor_item,
                days_range=args.monitor_range,
            )
        )))
    if args.monitor_report_changes is not None and args.monitor_change is not None:
        results.append(_run_command(lambda: print_result(
            client.monitor_report_changes(args.monitor_report_changes, args.monitor_change)
        )))
    return _aggregate(results)


_MONITOR_MANAGEMENT_COMMANDS: list[tuple[str, Callable[[MonitorProtocol, argparse.Namespace], Any]]] = [
    (
        "create_monitor_report",
        lambda c, a: c.create_monitor_report(*a.create_monitor_report, email_alert=a.email_alert),
    ),
    (
        "add_monitor_item",
        lambda c, a: c.add_monitor_item(
            int(a.add_monitor_item[0]),
            a.add_monitor_item[1],
            [x.strip() for x in a.add_monitor_item[2].split(",")],
        ),
    ),
    ("enable_typos",          lambda c, a: c.enable_typos(*map(int, a.enable_typos))),
    ("disable_typos",         lambda c, a: c.disable_typos(*map(int, a.disable_typos))),
    ("modify_typo_strength",  lambda c, a: c.modify_typo_strength(*map(int, a.modify_typo_strength))),
    ("delete_monitor_item",   lambda c, a: c.delete_monitor_item(a.delete_monitor_item)),
    ("delete_monitor_report", lambda c, a: c.delete_monitor_report(a.delete_monitor_report)),
]


@_dispatcher
def _dispatch_monitor_management(
    client: MonitorProtocol, args: argparse.Namespace
) -> _CommandResult:
    """Dispatch monitor management commands."""
    results = [
        _run_command(lambda handler=handler: print_result(handler(client, args)))
        for attr, handler in _MONITOR_MANAGEMENT_COMMANDS
        if getattr(args, attr) is not None
    ]
    return _aggregate(results)


def _validate_args(args: argparse.Namespace) -> list[str]:
    """Validate paired/dependent arguments before dispatching.

    Returns:
        List of error messages. Empty if all valid.
    """
    errors: list[str] = []
    if args.reverse_search and not args.reverse_search_type:
        errors.append("--reverse-search-type is required with --reverse-search")
    if args.reverse_search_type and not args.reverse_search:
        errors.append("--reverse-search is required with --reverse-search-type")
    if args.reverse_ip_type and not args.reverse_ip_data:
        errors.append("--reverse-ip-data is required with --reverse-ip-type")
    if args.reverse_ip_data and not args.reverse_ip_type:
        errors.append("--reverse-ip-type is required with --reverse-ip-data")
    if args.reverse_mx_type and not args.reverse_mx_data:
        errors.append("--reverse-mx-data is required with --reverse-mx-type")
    if args.reverse_mx_data and not args.reverse_mx_type:
        errors.append("--reverse-mx-type is required with --reverse-mx-data")
    if args.monitor_report_changes is not None and args.monitor_change is None:
        errors.append("--monitor-change is required with --monitor-report-changes")
    if args.monitor_change is not None and args.monitor_report_changes is None:
        errors.append("--monitor-report-changes is required with --monitor-change")
    return errors


def _dispatch_command(client: DomainIQClientProtocol, args: argparse.Namespace) -> int:
    """Dispatch to the appropriate command handler.

    Returns:
        EXIT_SUCCESS (0): all commands succeeded,
        EXIT_ERROR (1): validation errors or all commands failed,
        EXIT_PARTIAL (2): some commands succeeded and some failed,
        EXIT_NO_COMMAND (3): no command matched (show help).
    """
    errors = _validate_args(args)
    if errors:
        for error in errors:
            print(f"Error: {error}", file=sys.stderr)
        return EXIT_ERROR

    # Intentionally runs ALL matching dispatchers so the user can combine
    # multiple operations in a single invocation (e.g. --whois-lookup + --dns-lookup).
    executed = False
    has_errors = False
    has_success = False
    for dispatcher in _DISPATCHERS:
        result = dispatcher(client, args)
        if result.executed:
            executed = True
        if result.errored:
            has_errors = True
        if result.executed and not result.errored:
            has_success = True
    if not executed and not has_errors:
        return EXIT_NO_COMMAND
    if has_errors and has_success:
        return EXIT_PARTIAL
    if has_errors:
        return EXIT_ERROR
    return EXIT_SUCCESS
