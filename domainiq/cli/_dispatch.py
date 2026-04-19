"""Dispatcher registry and command routing for the DomainIQ CLI."""

import argparse
import sys
from collections.abc import Callable
from functools import partial
from typing import Any

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
from ..constants import SNAPSHOT_DEFAULT_LIMIT
from ._handlers import (
    build_snapshot_options,
    handle_dns_lookup,
    handle_domain_search,
    handle_whois_lookup,
    print_result,
)

_DispatchFn = Callable[[Any, "argparse.Namespace"], tuple[bool, bool]]
_DISPATCHERS: list[_DispatchFn] = []


def _dispatcher(fn: _DispatchFn) -> _DispatchFn:
    """Register fn as a CLI command dispatcher."""
    _DISPATCHERS.append(fn)
    return fn


def _run_command(fn: Callable[[], None]) -> tuple[bool, bool]:
    """Run fn and return (executed=True, had_errors). Catches DomainIQError."""
    try:
        fn()
        return True, False
    except DomainIQError as e:
        print(f"Error: {e}", file=sys.stderr)
        return True, True


def _aggregate(results: list[tuple[bool, bool]]) -> tuple[bool, bool]:
    """Aggregate (executed, had_errors) pairs from multiple commands."""
    if not results:
        return False, False
    return any(r[0] for r in results), any(r[1] for r in results)


@_dispatcher
def _dispatch_whois(client: WhoisProtocol, args: argparse.Namespace) -> tuple[bool, bool]:
    """Dispatch WHOIS commands. Returns (executed, had_errors)."""
    if args.whois_lookup:
        return _run_command(partial(handle_whois_lookup, client, args))
    return False, False


@_dispatcher
def _dispatch_dns(client: DNSProtocol, args: argparse.Namespace) -> tuple[bool, bool]:
    """Dispatch DNS commands. Returns (executed, had_errors)."""
    if args.dns_lookup:
        return _run_command(partial(handle_dns_lookup, client, args))
    return False, False


@_dispatcher
def _dispatch_domain_analysis(
    client: DomainAnalysisProtocol, args: argparse.Namespace
) -> tuple[bool, bool]:
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
) -> tuple[bool, bool]:
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
) -> tuple[bool, bool]:
    """Dispatch search commands. Returns (executed, had_errors)."""
    results = []
    if args.domain_search:
        results.append(_run_command(partial(handle_domain_search, client, args)))
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
) -> tuple[bool, bool]:
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
) -> tuple[bool, bool]:
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


@_dispatcher
def _dispatch_monitor_management(
    client: MonitorProtocol, args: argparse.Namespace
) -> tuple[bool, bool]:
    """Dispatch monitor management commands. Returns (executed, had_errors)."""
    results = []
    if args.create_monitor_report:
        report_type, name = args.create_monitor_report
        results.append(_run_command(lambda rt=report_type, n=name, ea=args.email_alert: print_result(
            client.create_monitor_report(rt, n, email_alert=ea)
        )))
    if args.add_monitor_item:
        report_id, item_type, items = args.add_monitor_item
        results.append(_run_command(lambda rid=report_id, it=item_type, its=items: print_result(
            client.add_monitor_item(
                int(rid), it, [i.strip() for i in its.split(",")]
            )
        )))
    if args.enable_typos:
        report_id, item_id = map(int, args.enable_typos)
        results.append(_run_command(
            lambda rid=report_id, iid=item_id: print_result(client.enable_typos(rid, iid))
        ))
    if args.disable_typos:
        report_id, item_id = map(int, args.disable_typos)
        results.append(_run_command(
            lambda rid=report_id, iid=item_id: print_result(client.disable_typos(rid, iid))
        ))
    if args.modify_typo_strength:
        report_id, item_id, strength = map(int, args.modify_typo_strength)
        results.append(_run_command(
            lambda rid=report_id, iid=item_id, s=strength: print_result(client.modify_typo_strength(rid, iid, s))
        ))
    if args.delete_monitor_item is not None:
        results.append(_run_command(
            lambda item=args.delete_monitor_item: print_result(client.delete_monitor_item(item))
        ))
    if args.delete_monitor_report is not None:
        results.append(_run_command(
            lambda rep=args.delete_monitor_report: print_result(client.delete_monitor_report(rep))
        ))
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


_EXIT_SUCCESS = 0
_EXIT_ERROR = 1
_EXIT_PARTIAL = 2
_EXIT_NO_COMMAND = 3


def _dispatch_command(client: DomainIQClientProtocol, args: argparse.Namespace) -> int:
    """Dispatch to the appropriate command handler.

    Returns:
        _EXIT_SUCCESS (0): all commands succeeded,
        _EXIT_ERROR (1): validation errors or all commands failed,
        _EXIT_PARTIAL (2): some commands succeeded and some failed,
        _EXIT_NO_COMMAND (3): no command matched (show help).
    """
    errors = _validate_args(args)
    if errors:
        for error in errors:
            print(f"Error: {error}", file=sys.stderr)
        return _EXIT_ERROR

    # Intentionally runs ALL matching dispatchers so the user can combine
    # multiple operations in a single invocation (e.g. --whois-lookup + --dns-lookup).
    executed = False
    has_errors = False
    has_success = False
    for dispatcher in _DISPATCHERS:
        ran, errored = dispatcher(client, args)
        if ran:
            executed = True
        if errored:
            has_errors = True
        if ran and not errored:
            has_success = True
    if not executed and not has_errors:
        return _EXIT_NO_COMMAND
    if has_errors and has_success:
        return _EXIT_PARTIAL
    if has_errors:
        return _EXIT_ERROR
    return _EXIT_SUCCESS
