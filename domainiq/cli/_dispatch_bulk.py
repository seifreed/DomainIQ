"""CLI dispatchers for bulk commands."""

import argparse

from domainiq._models import BulkWhoisType
from domainiq._protocols import BulkProtocol

from ._dispatch_common import _aggregate, _CommandResult, _run_command
from ._serialization import print_result


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


__all__ = ["_dispatch_bulk"]
