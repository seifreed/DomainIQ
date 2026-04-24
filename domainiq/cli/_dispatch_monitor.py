"""CLI dispatchers for monitor commands."""

import argparse
from collections.abc import Callable
from functools import partial

from domainiq.protocols import MonitorProtocol

from ._dispatch_common import _aggregate, _CommandResult, _run_command
from ._serialization import print_result


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
    ("create_monitor_report", _create_monitor_report),
    ("add_monitor_item", _add_monitor_item),
    ("enable_typos", _enable_typos),
    ("disable_typos", _disable_typos),
    ("modify_typo_strength", _modify_typo_strength),
    ("delete_monitor_item", _delete_monitor_item),
    ("delete_monitor_report", _delete_monitor_report),
]


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


__all__ = ["_dispatch_monitor", "_dispatch_monitor_management"]
