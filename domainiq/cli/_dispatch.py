"""Dispatcher registry and command routing for the DomainIQ CLI."""

import argparse
import sys
from functools import partial

from domainiq._protocols import (
    DNSProtocol,
    DomainAnalysisProtocol,
    DomainIQClientProtocol,
    WhoisProtocol,
)
from domainiq.constants import (
    EXIT_ERROR,
    EXIT_NO_COMMAND,
    EXIT_PARTIAL,
    EXIT_SUCCESS,
    SNAPSHOT_DEFAULT_LIMIT,
)

from ._dispatch_bulk import _dispatch_bulk
from ._dispatch_common import _aggregate, _CommandResult, _DispatchFn, _run_command
from ._dispatch_monitor import _dispatch_monitor, _dispatch_monitor_management
from ._dispatch_reports import _dispatch_reports
from ._dispatch_search import _dispatch_search
from ._handlers import build_snapshot_options, handle_dns_lookup, handle_whois_lookup
from ._serialization import print_result
from ._types import DnsArgs, WhoisArgs
from ._validation import validate_args


def _dispatch_whois(client: WhoisProtocol, args: argparse.Namespace) -> _CommandResult:
    """Dispatch WHOIS commands. Returns (executed, had_errors)."""
    if args.whois_lookup:
        return _run_command(
            partial(handle_whois_lookup, client, WhoisArgs.from_namespace(args))
        )
    return _CommandResult(executed=False, errored=False)


def _dispatch_dns(client: DNSProtocol, args: argparse.Namespace) -> _CommandResult:
    """Dispatch DNS commands. Returns (executed, had_errors)."""
    if args.dns_lookup:
        return _run_command(
            partial(handle_dns_lookup, client, DnsArgs.from_namespace(args))
        )
    return _CommandResult(executed=False, errored=False)


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


_DISPATCHERS: tuple[_DispatchFn, ...] = (
    _dispatch_whois,
    _dispatch_dns,
    _dispatch_domain_analysis,
    _dispatch_reports,
    _dispatch_search,
    _dispatch_bulk,
    _dispatch_monitor,
    _dispatch_monitor_management,
)


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


__all__ = [
    "_CommandResult",
    "_dispatch_bulk",
    "_dispatch_command",
    "_dispatch_dns",
    "_dispatch_monitor",
    "_dispatch_monitor_management",
    "_dispatch_reports",
    "_dispatch_search",
    "_dispatch_whois",
    "_run_command",
]
