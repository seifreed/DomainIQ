"""CLI dispatchers for search commands."""

import argparse
from functools import partial

from domainiq._models import ReverseMatchType
from domainiq._protocols import SearchProtocol

from ._dispatch_common import _aggregate, _CommandResult, _run_command
from ._handlers import handle_domain_search
from ._serialization import print_result
from ._types import DomainSearchArgs


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


__all__ = ["_dispatch_search"]
