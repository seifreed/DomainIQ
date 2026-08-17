"""CLI argument validation helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import argparse
    from collections.abc import Callable

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
    ("queue_hash", "--queue-hash"),
    ("queue_action", "--queue-action"),
    ("submit_queued", "--submit-queued"),
)


def _check_queued_params(args: argparse.Namespace) -> list[str]:
    """Collect errors for malformed --queued-param values."""
    errors: list[str] = []
    for pair in args.queued_param or []:
        key, sep, _value = pair.partition("=")
        if not sep or not key.strip():
            errors.append(f"--queued-param must be KEY=VALUE, got: {pair!r}")
    return errors


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


def _provided_truthy(value: object) -> bool:
    return bool(value)


def _provided_not_none(value: object) -> bool:
    return value is not None


# Flag pairs that must be provided together. Each entry holds the two
# (namespace attribute, CLI flag) sides and the predicate deciding whether
# a value counts as provided (empty strings differ from explicit None here).
_MUTUAL_FLAG_PAIRS: tuple[
    tuple[tuple[str, str], tuple[str, str], Callable[[object], bool]], ...
] = (
    (
        ("reverse_search", "--reverse-search"),
        ("reverse_search_type", "--reverse-search-type"),
        _provided_truthy,
    ),
    (
        ("reverse_ip_type", "--reverse-ip-type"),
        ("reverse_ip_data", "--reverse-ip-data"),
        _provided_truthy,
    ),
    (
        ("reverse_mx_type", "--reverse-mx-type"),
        ("reverse_mx_data", "--reverse-mx-data"),
        _provided_truthy,
    ),
    (
        ("monitor_report_changes", "--monitor-report-changes"),
        ("monitor_change", "--monitor-change"),
        _provided_not_none,
    ),
    (
        ("queue_hash", "--queue-hash"),
        ("queue_action", "--queue-action"),
        _provided_not_none,
    ),
)


def _check_mutual_flag_pairs(args: argparse.Namespace) -> list[str]:
    """Collect errors for flags that require their counterpart flag."""
    errors: list[str] = []
    for (attr_a, flag_a), (attr_b, flag_b), provided in _MUTUAL_FLAG_PAIRS:
        has_a = provided(getattr(args, attr_a))
        has_b = provided(getattr(args, attr_b))
        if has_a and not has_b:
            errors.append(f"{flag_b} is required with {flag_a}")
        if has_b and not has_a:
            errors.append(f"{flag_a} is required with {flag_b}")
    return errors


def validate_args(args: argparse.Namespace) -> list[str]:
    """Validate paired and dependent arguments before dispatching."""
    errors = _check_empty_strings(args)
    errors.extend(_check_mutual_flag_pairs(args))
    if args.queued_param and args.submit_queued is None:
        errors.append("--submit-queued is required with --queued-param")
    errors.extend(_check_queued_params(args))
    return errors


__all__ = ["validate_args"]
