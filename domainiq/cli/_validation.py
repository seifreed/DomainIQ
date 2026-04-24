"""CLI argument validation helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import argparse


def validate_args(args: argparse.Namespace) -> list[str]:
    """Validate paired and dependent arguments before dispatching."""
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


__all__ = ["validate_args"]
