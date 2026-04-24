"""Dispatcher registry and command routing for the DomainIQ CLI."""

import argparse
import sys
from collections.abc import Callable
from functools import partial
from typing import Any, NamedTuple

from domainiq.constants import (
    EXIT_ERROR,
    EXIT_NO_COMMAND,
    EXIT_PARTIAL,
    EXIT_SUCCESS,
    SNAPSHOT_DEFAULT_LIMIT,
)
from domainiq.exceptions import DomainIQError
from domainiq.models import BulkWhoisType, ReverseMatchType
from domainiq.protocols import (
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
)
from ._serialization import print_result
from ._types import DnsArgs, DomainSearchArgs, WhoisArgs
from ._validation import validate_args


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


@_dispatcher
def _dispatch_whois(client: WhoisProtocol, args: argparse.Namespace) -> _CommandResult:
    """Dispatch WHOIS commands. Returns (executed, had_errors)."""
    if args.whois_lookup:
        return _run_command(
            partial(handle_whois_lookup, client, WhoisArgs.from_namespace(args))
        )
    return _CommandResult(executed=False, errored=False)


@_dispatcher
def _dispatch_dns(client: DNSProtocol, args: argparse.Namespace) -> _CommandResult:
    """Dispatch DNS commands. Returns (executed, had_errors)."""
    if args.dns_lookup:
        return _run_command(
            partial(handle_dns_lookup, client, DnsArgs.from_namespace(args))
        )
    return _CommandResult(executed=False, errored=False)


@_dispatcher
def _dispatch_domain_analysis(
    client: DomainAnalysisProtocol, args: argparse.Namespace
) -> _CommandResult:
    """Dispatch domain analysis commands. Returns (executed, had_errors)."""
    results = []
    if args.domain_categorize:
        results.append(
            _run_command(
                lambda: print_result(client.domain_categorize(args.domain_categorize))
            )
        )
    if args.domain_snapshot:
        opts = build_snapshot_options(args)
        results.append(
            _run_command(
                lambda: print_result(
                    client.domain_snapshot(args.domain_snapshot, options=opts)
                )
            )
        )
    if args.domain_snapshot_history:
        opts = build_snapshot_options(args)
        results.append(
            _run_command(
                lambda: print_result(
                    client.domain_snapshot_history(
                        args.domain_snapshot_history,
                        width=opts.width,
                        height=opts.height,
                        limit=args.snapshot_limit
                        if args.snapshot_limit is not None
                        else SNAPSHOT_DEFAULT_LIMIT,
                    )
                )
            )
        )
    return _aggregate(results)


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


@_dispatcher
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


@_dispatcher
def _dispatch_search(
    client: SearchProtocol, args: argparse.Namespace
) -> _CommandResult:
    """Dispatch search commands. Returns (executed, had_errors)."""
    results = []
    if args.domain_search:
        results.append(
            _run_command(
                partial(
                    handle_domain_search, client, DomainSearchArgs.from_namespace(args)
                )
            )
        )
    if args.reverse_search_type and args.reverse_search:
        results.append(
            _run_command(
                lambda: print_result(
                    client.reverse_search(
                        args.reverse_search_type,
                        args.reverse_search,
                        match=ReverseMatchType(args.reverse_match),
                    )
                )
            )
        )
    if args.reverse_dns:
        results.append(
            _run_command(lambda: print_result(client.reverse_dns(args.reverse_dns)))
        )
    if args.reverse_ip_type and args.reverse_ip_data:
        results.append(
            _run_command(
                lambda: print_result(
                    client.reverse_ip(args.reverse_ip_type, args.reverse_ip_data)
                )
            )
        )
    if args.reverse_mx_type and args.reverse_mx_data:
        results.append(
            _run_command(
                lambda: print_result(
                    client.reverse_mx(
                        args.reverse_mx_type,
                        args.reverse_mx_data,
                        recursive=args.recursive,
                    )
                )
            )
        )
    return _aggregate(results)


@_dispatcher
def _dispatch_bulk(client: BulkProtocol, args: argparse.Namespace) -> _CommandResult:
    """Dispatch bulk operation commands. Returns (executed, had_errors)."""
    results = []
    if args.bulk_dns:
        results.append(
            _run_command(lambda: print_result(client.bulk_dns(args.bulk_dns)))
        )
    if args.bulk_whois:
        results.append(
            _run_command(
                lambda: print_result(
                    client.bulk_whois(
                        args.bulk_whois, BulkWhoisType(args.bulk_whois_type)
                    )
                )
            )
        )
    if args.bulk_whois_ip:
        results.append(
            _run_command(lambda: print_result(client.bulk_whois_ip(args.bulk_whois_ip)))
        )
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
        results.append(
            _run_command(
                lambda: print_result(
                    client.monitor_report_items(args.monitor_report_items)
                )
            )
        )
    if args.monitor_report_summary is not None:
        results.append(
            _run_command(
                lambda: print_result(
                    client.monitor_report_summary(
                        args.monitor_report_summary,
                        item_id=args.monitor_item,
                        days_range=args.monitor_range,
                    )
                )
            )
        )
    if args.monitor_report_changes is not None and args.monitor_change is not None:
        results.append(
            _run_command(
                lambda: print_result(
                    client.monitor_report_changes(
                        args.monitor_report_changes, args.monitor_change
                    )
                )
            )
        )
    return _aggregate(results)


def _create_monitor_report(
    client: MonitorProtocol,
    args: argparse.Namespace,
) -> object:
    report_type, name = args.create_monitor_report
    return client.create_monitor_report(report_type, name, email_alert=args.email_alert)


def _add_monitor_item(client: MonitorProtocol, args: argparse.Namespace) -> object:
    report_id, item_type, raw_items = args.add_monitor_item
    items = [item.strip() for item in raw_items.split(",")]
    return client.add_monitor_item(int(report_id), item_type, items)


def _enable_typos(client: MonitorProtocol, args: argparse.Namespace) -> object:
    report_id, item_id = (int(value) for value in args.enable_typos)
    return client.enable_typos(report_id, item_id)


def _disable_typos(client: MonitorProtocol, args: argparse.Namespace) -> object:
    report_id, item_id = (int(value) for value in args.disable_typos)
    return client.disable_typos(report_id, item_id)


def _modify_typo_strength(
    client: MonitorProtocol,
    args: argparse.Namespace,
) -> object:
    report_id, item_id, strength = (int(value) for value in args.modify_typo_strength)
    return client.modify_typo_strength(report_id, item_id, strength)


def _delete_monitor_item(client: MonitorProtocol, args: argparse.Namespace) -> object:
    return client.delete_monitor_item(args.delete_monitor_item)


def _delete_monitor_report(client: MonitorProtocol, args: argparse.Namespace) -> object:
    return client.delete_monitor_report(args.delete_monitor_report)


def _print_monitor_management_result(
    handler: Callable[[MonitorProtocol, argparse.Namespace], object],
    client: MonitorProtocol,
    args: argparse.Namespace,
) -> None:
    print_result(handler(client, args))


_MONITOR_MANAGEMENT_COMMANDS: list[
    tuple[str, Callable[[MonitorProtocol, argparse.Namespace], object]]
] = [
    (
        "create_monitor_report",
        _create_monitor_report,
    ),
    (
        "add_monitor_item",
        _add_monitor_item,
    ),
    ("enable_typos", _enable_typos),
    ("disable_typos", _disable_typos),
    ("modify_typo_strength", _modify_typo_strength),
    ("delete_monitor_item", _delete_monitor_item),
    ("delete_monitor_report", _delete_monitor_report),
]


@_dispatcher
def _dispatch_monitor_management(
    client: MonitorProtocol, args: argparse.Namespace
) -> _CommandResult:
    """Dispatch monitor management commands."""
    results = []
    for attr, handler in _MONITOR_MANAGEMENT_COMMANDS:
        if getattr(args, attr) is not None:
            results.append(
                _run_command(
                    partial(_print_monitor_management_result, handler, client, args)
                )
            )
    return _aggregate(results)


def _dispatch_command(client: DomainIQClientProtocol, args: argparse.Namespace) -> int:
    """Dispatch to the appropriate command handler.

    Returns:
        EXIT_SUCCESS (0): all commands succeeded,
        EXIT_ERROR (1): validation errors or all commands failed,
        EXIT_PARTIAL (2): some commands succeeded and some failed,
        EXIT_NO_COMMAND (3): no command matched (show help).
    """
    errors = validate_args(args)
    if errors:
        for error in errors:
            sys.stderr.write(f"Error: {error}\n")
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
