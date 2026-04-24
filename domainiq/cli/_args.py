"""Argument parsing for the DomainIQ CLI."""

import argparse

from domainiq.models import ReverseMxSearchType


def _positive_int(value: str) -> int:
    n = int(value)
    if n <= 0:
        msg = f"must be a positive integer, got {n}"
        raise argparse.ArgumentTypeError(msg)
    return n


def _add_global_args(parser: argparse.ArgumentParser) -> None:
    """Add global options to the parser."""
    parser.add_argument("--api-key", help="DomainIQ API key")
    parser.add_argument("--config-file", help="Path to configuration file")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--timeout", type=int, default=30, help="Request timeout in seconds"
    )


def _add_whois_args(parser: argparse.ArgumentParser) -> None:
    """Add WHOIS operation arguments."""
    parser.add_argument("--whois-lookup", help="Get WHOIS data for domain or IP")
    parser.add_argument(
        "--full", action="store_true", help="Retrieve full WHOIS record"
    )
    parser.add_argument(
        "--current-only", action="store_true", help="Use only current WHOIS record"
    )


def _add_dns_args(parser: argparse.ArgumentParser) -> None:
    """Add DNS operation arguments."""
    parser.add_argument("--dns-lookup", help="Get DNS records for domain")
    parser.add_argument("--types", help="DNS record types (comma-separated)")


def _add_domain_analysis_args(parser: argparse.ArgumentParser) -> None:
    """Add domain analysis arguments."""
    parser.add_argument("--domain-categorize", nargs="+", help="Categorize domains")
    parser.add_argument("--domain-snapshot", help="Get domain snapshot")
    parser.add_argument("--domain-snapshot-history", help="Get snapshot history")
    parser.add_argument("--snapshot-limit", type=int, help="Limit snapshots returned")
    parser.add_argument(
        "--snapshot-full", action="store_true", help="Capture full page screenshot"
    )
    parser.add_argument(
        "--no-cache", action="store_true", help="Don't use cached snapshot"
    )
    parser.add_argument("--raw", action="store_true", help="Return raw image data")
    parser.add_argument("--width", type=int, help="Snapshot width")
    parser.add_argument("--height", type=int, help="Snapshot height")


def _add_report_args(parser: argparse.ArgumentParser) -> None:
    """Add report arguments."""
    parser.add_argument("--domain-report", help="Get comprehensive domain report")
    parser.add_argument("--name-report", help="Get registrant name report")
    parser.add_argument("--organization-report", help="Get organization report")
    parser.add_argument("--email-report", help="Get email report")
    parser.add_argument("--ip-report", help="Get IP report")


def _add_search_args(parser: argparse.ArgumentParser) -> None:
    """Add search operation arguments."""
    parser.add_argument("--domain-search", nargs="+", help="Search domains by keywords")
    parser.add_argument("--conditions", nargs="+", help="Conditions for domain search")
    parser.add_argument(
        "--match",
        choices=["any", "all"],
        default="any",
        help="Match type for multiple keywords",
    )
    parser.add_argument("--count-only", action="store_true", help="Return only count")
    parser.add_argument(
        "--exclude-dashed", action="store_true", help="Exclude dashed domains"
    )
    parser.add_argument(
        "--exclude-numbers", action="store_true", help="Exclude domains with numbers"
    )
    parser.add_argument(
        "--exclude-idn", action="store_true", help="Exclude IDN domains"
    )
    parser.add_argument(
        "--min-length", type=_positive_int, help="Minimum domain length"
    )
    parser.add_argument(
        "--max-length", type=_positive_int, help="Maximum domain length"
    )
    parser.add_argument("--min-create-date", help="Minimum creation date (YYYY-MM-DD)")
    parser.add_argument("--max-create-date", help="Maximum creation date (YYYY-MM-DD)")
    parser.add_argument(
        "--search-limit", type=_positive_int, help="Limit search results"
    )


def _add_reverse_search_args(parser: argparse.ArgumentParser) -> None:
    """Add reverse search operation arguments."""
    parser.add_argument(
        "--reverse-search-type",
        choices=["email", "name", "org"],
        help="Type of reverse search",
    )
    parser.add_argument("--reverse-search", help="Term to reverse search")
    parser.add_argument(
        "--reverse-match",
        choices=["contains", "begins", "ends"],
        default="contains",
        help="Reverse search match type",
    )
    parser.add_argument("--reverse-dns", help="Perform reverse DNS search")
    parser.add_argument(
        "--reverse-ip-type",
        choices=["ip", "subnet", "block", "range", "domain"],
        help="Type of reverse IP search",
    )
    parser.add_argument("--reverse-ip-data", help="Data for reverse IP search")
    parser.add_argument(
        "--reverse-mx-type",
        choices=[e.value for e in ReverseMxSearchType],
        help="Type of reverse MX search",
    )
    parser.add_argument("--reverse-mx-data", help="Data for reverse MX search")
    parser.add_argument(
        "--recursive", action="store_true", help="Recursively check MX hostnames"
    )


def _add_bulk_args(parser: argparse.ArgumentParser) -> None:
    """Add bulk operation arguments."""
    parser.add_argument("--bulk-dns", nargs="+", help="Bulk DNS lookup for domains")
    parser.add_argument("--bulk-whois", nargs="+", help="Bulk WHOIS lookup")
    parser.add_argument(
        "--bulk-whois-type",
        choices=["live", "registry", "cached"],
        default="live",
        help="Type of bulk WHOIS lookup",
    )
    parser.add_argument(
        "--bulk-whois-ip", nargs="+", help="Bulk domain IP WHOIS lookup"
    )


def _add_monitor_args(parser: argparse.ArgumentParser) -> None:
    """Add monitoring operation arguments."""
    parser.add_argument(
        "--monitor-list", action="store_true", help="List active monitors"
    )
    parser.add_argument(
        "--monitor-report-items", type=int, help="Get monitor report items"
    )
    parser.add_argument(
        "--monitor-report-summary", type=int, help="Get monitor report summary"
    )
    parser.add_argument("--monitor-item", type=int, help="Monitor item ID for summary")
    parser.add_argument(
        "--monitor-range", type=int, help="Days range for monitor summary"
    )
    parser.add_argument(
        "--monitor-report-changes", type=int, help="Get monitor report changes"
    )
    parser.add_argument(
        "--monitor-change", type=int, help="Change ID for monitor changes"
    )


def _add_monitor_management_args(parser: argparse.ArgumentParser) -> None:
    """Add monitor management arguments."""
    parser.add_argument(
        "--create-monitor-report",
        nargs=2,
        metavar=("TYPE", "NAME"),
        help="Create monitor report (type name)",
    )
    parser.add_argument(
        "--email-alert",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Enable email alerts for monitor "
            "(default: enabled; use --no-email-alert to disable)"
        ),
    )
    parser.add_argument(
        "--add-monitor-item",
        nargs=3,
        metavar=("REPORT_ID", "TYPE", "ITEMS"),
        help="Add items to monitor (report_id type items)",
    )
    parser.add_argument(
        "--enable-typos",
        nargs=2,
        metavar=("REPORT_ID", "ITEM_ID"),
        help="Enable typos for monitor item",
    )
    parser.add_argument(
        "--disable-typos",
        nargs=2,
        metavar=("REPORT_ID", "ITEM_ID"),
        help="Disable typos for monitor item",
    )
    parser.add_argument(
        "--modify-typo-strength",
        nargs=3,
        metavar=("REPORT_ID", "ITEM_ID", "STRENGTH"),
        help="Modify typo strength (5-41)",
    )
    parser.add_argument("--delete-monitor-item", type=int, help="Delete monitor item")
    parser.add_argument(
        "--delete-monitor-report", type=int, help="Delete monitor report"
    )


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        description=(
            "DomainIQ API Client - Domain Intelligence and Security Research Tool"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  domainiq --whois-lookup example.com
  domainiq --dns-lookup example.com --types A,MX
  domainiq --domain-search keyword1 keyword2 --match any
  domainiq --bulk-dns example1.com example2.com
  domainiq --monitor-list
        """,
    )

    _add_global_args(parser)
    _add_whois_args(parser)
    _add_dns_args(parser)
    _add_domain_analysis_args(parser)
    _add_report_args(parser)
    _add_search_args(parser)
    _add_reverse_search_args(parser)
    _add_bulk_args(parser)
    _add_monitor_args(parser)
    _add_monitor_management_args(parser)

    return parser
