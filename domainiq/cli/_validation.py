"""CLI argument validation helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import argparse

# (namespace attribute, CLI flag name)
_EMPTY_STRING_FLAGS: tuple[tuple[str, str], ...] = (
    ("whois_lookup", "--whois-lookup"),
    ("dns_lookup", "--dns-lookup"),
    ("types", "--types"),
    ("domain_snapshot", "--domain-snapshot"),
    ("domain_snapshot_history", "--domain-snapshot-history"),
    ("domain_report", "--domain-report"),
    ("name_report", "--name-report"),
    ("organization_report", "--organization-report"),
    ("email_report", "--email-report"),
    ("ip_report", "--ip-report"),
    ("reverse_search", "--reverse-search"),
    ("reverse_dns", "--reverse-dns"),
    ("reverse_ip_data", "--reverse-ip-data"),
    ("reverse_mx_data", "--reverse-mx-data"),
    ("domain_categorize", "--domain-categorize"),
    ("domain_search", "--domain-search"),
    ("conditions", "--conditions"),
    ("bulk_dns", "--bulk-dns"),
    ("bulk_whois", "--bulk-whois"),
    ("bulk_whois_ip", "--bulk-whois-ip"),
    ("create_monitor_report", "--create-monitor-report"),
    ("add_monitor_item", "--add-monitor-item"),
    ("enable_typos", "--enable-typos"),
    ("disable_typos", "--disable-typos"),
    ("min_create_date", "--min-create-date"),
    ("max_create_date", "--max-create-date"),
    ("modify_typo_strength", "--modify-typo-strength"),
)


def _check_empty_strings(args: argparse.Namespace) -> list[str]:
    """Collect errors for arguments that were explicitly set to empty strings."""
    errors: list[str] = []
    for attr, flag in _EMPTY_STRING_FLAGS:
        val = getattr(args, attr)
        if val is None:
            continue
        if isinstance(val, list):
            errors.extend(
                f"{flag} cannot be empty" for item in val if str(item).strip() == ""
            )
        elif str(val).strip() == "":
            errors.append(f"{flag} cannot be empty")
    return errors


def validate_args(args: argparse.Namespace) -> list[str]:
    """Validate paired and dependent arguments before dispatching."""
    errors = _check_empty_strings(args)

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
