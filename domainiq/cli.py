"""Command-line interface for the DomainIQ library."""

import argparse
import sys
from typing import Any

from .client import DomainIQClient
from .config import Config
from .exceptions import DomainIQError
from .utils import setup_logging


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        description=(
            "DomainIQ API Client - Domain Intelligence and "
            "Security Research Tool"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  domainiq --whois-lookup example.com
  domainiq --dns-lookup example.com --types A,MX
  domainiq --domain-search keyword1 keyword2 --match any
  domainiq --bulk-dns example1.com example2.com
  domainiq --monitor-list
        """
    )

    # Global options
    parser.add_argument("--api-key", help="DomainIQ API key")
    parser.add_argument("--config-file", help="Path to configuration file")
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")

    # WHOIS operations
    parser.add_argument("--whois-lookup", help="Get WHOIS data for domain or IP")
    parser.add_argument("--full", action="store_true", help="Retrieve full WHOIS record")
    parser.add_argument("--current-only", action="store_true", help="Use only current WHOIS record")

    # DNS operations
    parser.add_argument("--dns-lookup", help="Get DNS records for domain")
    parser.add_argument("--types", help="DNS record types (comma-separated)")

    # Domain analysis
    parser.add_argument("--domain-categorize", nargs="+", help="Categorize domains")
    parser.add_argument("--domain-snapshot", help="Get domain snapshot")
    parser.add_argument("--domain-snapshot-history", help="Get snapshot history")
    parser.add_argument("--snapshot-limit", type=int, help="Limit snapshots returned")
    parser.add_argument("--no-cache", action="store_true", help="Don't use cached snapshot")
    parser.add_argument("--raw", action="store_true", help="Return raw image data")
    parser.add_argument("--width", type=int, help="Snapshot width")
    parser.add_argument("--height", type=int, help="Snapshot height")

    # Reports
    parser.add_argument("--domain-report", help="Get comprehensive domain report")
    parser.add_argument("--name-report", help="Get registrant name report")
    parser.add_argument("--organization-report", help="Get organization report")
    parser.add_argument("--email-report", help="Get email report")
    parser.add_argument("--ip-report", help="Get IP report")

    # Search operations
    parser.add_argument("--domain-search", nargs="+", help="Search domains by keywords")
    parser.add_argument("--conditions", nargs="+", help="Conditions for domain search")
    parser.add_argument("--match", choices=["any", "all"], default="any",
                       help="Match type for multiple keywords")
    parser.add_argument("--count-only", action="store_true", help="Return only count")
    parser.add_argument("--exclude-dashed", action="store_true", help="Exclude dashed domains")
    parser.add_argument("--exclude-numbers", action="store_true", help="Exclude domains with numbers")
    parser.add_argument("--exclude-idn", action="store_true", help="Exclude IDN domains")
    parser.add_argument("--min-length", type=int, help="Minimum domain length")
    parser.add_argument("--max-length", type=int, help="Maximum domain length")
    parser.add_argument("--min-create-date", help="Minimum creation date (YYYY-MM-DD)")
    parser.add_argument("--max-create-date", help="Maximum creation date (YYYY-MM-DD)")
    parser.add_argument("--search-limit", type=int, help="Limit search results")

    # Reverse search operations
    parser.add_argument("--reverse-search-type", choices=["email", "name", "org"],
                       help="Type of reverse search")
    parser.add_argument("--reverse-search", help="Term to reverse search")
    parser.add_argument("--reverse-match", choices=["contains", "begins", "ends"],
                       default="contains", help="Reverse search match type")
    parser.add_argument("--reverse-dns", help="Perform reverse DNS search")
    parser.add_argument("--reverse-ip-type",
                       choices=["ip", "subnet", "block", "range", "domain"],
                       help="Type of reverse IP search")
    parser.add_argument("--reverse-ip-data", help="Data for reverse IP search")
    parser.add_argument("--reverse-mx-type",
                       choices=["hostname", "ip", "subnet", "block", "range"],
                       help="Type of reverse MX search")
    parser.add_argument("--reverse-mx-data", help="Data for reverse MX search")
    parser.add_argument("--recursive", action="store_true",
                       help="Recursively check MX hostnames")

    # Bulk operations
    parser.add_argument("--bulk-dns", nargs="+", help="Bulk DNS lookup for domains")
    parser.add_argument("--bulk-whois", nargs="+", help="Bulk WHOIS lookup")
    parser.add_argument("--bulk-whois-type", choices=["live", "registry", "cached"],
                       default="live", help="Type of bulk WHOIS lookup")
    parser.add_argument("--bulk-whois-ip", nargs="+", help="Bulk domain IP WHOIS lookup")

    # Monitoring operations
    parser.add_argument("--monitor-list", action="store_true", help="List active monitors")
    parser.add_argument("--monitor-report-items", type=int, help="Get monitor report items")
    parser.add_argument("--monitor-report-summary", type=int, help="Get monitor report summary")
    parser.add_argument("--monitor-item", type=int, help="Monitor item ID for summary")
    parser.add_argument("--monitor-range", type=int, help="Days range for monitor summary")
    parser.add_argument("--monitor-report-changes", type=int, help="Get monitor report changes")
    parser.add_argument("--monitor-change", type=int, help="Change ID for monitor changes")

    # Monitor management
    parser.add_argument("--create-monitor-report", nargs=2, metavar=("TYPE", "NAME"),
                       help="Create monitor report (type name)")
    parser.add_argument("--email-alert", action="store_true",
                       help="Enable email alerts for monitor")
    parser.add_argument("--add-monitor-item", nargs=3, metavar=("REPORT_ID", "TYPE", "ITEMS"),
                       help="Add items to monitor (report_id type items)")
    parser.add_argument("--enable-typos", nargs=2, metavar=("REPORT_ID", "ITEM_ID"),
                       help="Enable typos for monitor item")
    parser.add_argument("--disable-typos", nargs=2, metavar=("REPORT_ID", "ITEM_ID"),
                       help="Disable typos for monitor item")
    parser.add_argument("--modify-typo-strength", nargs=3,
                       metavar=("REPORT_ID", "ITEM_ID", "STRENGTH"),
                       help="Modify typo strength (5-41)")
    parser.add_argument("--delete-monitor-item", type=int, help="Delete monitor item")
    parser.add_argument("--delete-monitor-report", type=int, help="Delete monitor report")

    return parser


def print_result(result: Any, indent: int = 2) -> None:
    """Print API result in formatted JSON."""
    if result is None:
        print("No data returned")
        return

    import json

    try:
        if hasattr(result, "__dict__"):
            # Convert dataclass/object to dict
            result_dict = vars(result)
            # Convert datetime objects to strings for JSON serialization
            for key, value in result_dict.items():
                if hasattr(value, 'isoformat'):
                    result_dict[key] = value.isoformat()
                elif isinstance(value, list) and value and hasattr(value[0], '__dict__'):
                    result_dict[key] = [vars(item) for item in value]
            print(json.dumps(result_dict, indent=indent, default=str))
        elif isinstance(result, list):
            # Handle list of results
            result_list = []
            for item in result:
                if hasattr(item, "__dict__"):
                    item_dict = vars(item)
                    for key, value in item_dict.items():
                        if hasattr(value, 'isoformat'):
                            item_dict[key] = value.isoformat()
                    result_list.append(item_dict)
                else:
                    result_list.append(item)
            print(json.dumps(result_list, indent=indent, default=str))
        else:
            # Simple dict or other JSON-serializable data
            print(json.dumps(result, indent=indent, default=str))
    except (TypeError, ValueError) as e:
        print(f"Result (couldn't format as JSON): {result}")
        print(f"Error: {e}")


def handle_whois_lookup(client: DomainIQClient, args: argparse.Namespace) -> None:
    """Handle WHOIS lookup command."""
    # Determine if it's a domain or IP
    domain = None
    ip = None

    query = args.whois_lookup
    if query.replace(".", "").isdigit():  # Simple IP check
        ip = query
    else:
        domain = query

    result = client.whois_lookup(
        domain=domain,
        ip=ip,
        full=args.full,
        current_only=args.current_only
    )
    print_result(result)


def handle_dns_lookup(client: DomainIQClient, args: argparse.Namespace) -> None:
    """Handle DNS lookup command."""
    types = args.types.split(",") if args.types else None
    result = client.dns_lookup(args.dns_lookup, record_types=types)
    print_result(result)


def handle_domain_search(client: DomainIQClient, args: argparse.Namespace) -> None:
    """Handle domain search command."""
    additional_params = {}

    if args.count_only:
        additional_params["count_only"] = 1
    if args.exclude_dashed:
        additional_params["exclude_dashed"] = True
    if args.exclude_numbers:
        additional_params["exclude_numbers"] = True
    if args.exclude_idn:
        additional_params["exclude_idn"] = True
    if args.min_length:
        additional_params["min_length"] = args.min_length
    if args.max_length:
        additional_params["max_length"] = args.max_length
    if args.min_create_date:
        additional_params["min_create_date"] = args.min_create_date
    if args.max_create_date:
        additional_params["max_create_date"] = args.max_create_date
    if args.search_limit:
        additional_params["limit"] = args.search_limit

    result = client.domain_search(
        keywords=args.domain_search,
        conditions=args.conditions,
        match=args.match,
        **additional_params
    )
    print_result(result)


def main() -> int:
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()

    # Setup logging
    if args.debug:
        log_level = "DEBUG"
    elif args.verbose:
        log_level = "INFO"
    else:
        log_level = "WARNING"

    setup_logging(level=log_level)

    try:
        # Create configuration
        config = Config(
            api_key=args.api_key,
            timeout=args.timeout,
            config_file_path=args.config_file
        )

        # Create client
        with DomainIQClient(config) as client:

            # WHOIS operations
            if args.whois_lookup:
                handle_whois_lookup(client, args)

            # DNS operations
            elif args.dns_lookup:
                handle_dns_lookup(client, args)

            # Domain analysis
            elif args.domain_categorize:
                result = client.domain_categorize(args.domain_categorize)
                print_result(result)

            elif args.domain_snapshot:
                result = client.domain_snapshot(
                    args.domain_snapshot,
                    full=args.full,
                    no_cache=args.no_cache,
                    raw=args.raw,
                    width=args.width or 250,
                    height=args.height or 125
                )
                print_result(result)

            elif args.domain_snapshot_history:
                result = client.domain_snapshot_history(
                    args.domain_snapshot_history,
                    width=args.width or 250,
                    height=args.height or 125,
                    limit=args.snapshot_limit or 10
                )
                print_result(result)

            # Reports
            elif args.domain_report:
                result = client.domain_report(args.domain_report)
                print_result(result)

            elif args.name_report:
                result = client.name_report(args.name_report)
                print_result(result)

            elif args.organization_report:
                result = client.organization_report(args.organization_report)
                print_result(result)

            elif args.email_report:
                result = client.email_report(args.email_report)
                print_result(result)

            elif args.ip_report:
                result = client.ip_report(args.ip_report)
                print_result(result)

            # Search operations
            elif args.domain_search:
                handle_domain_search(client, args)

            elif args.reverse_search_type and args.reverse_search:
                result = client.reverse_search(
                    args.reverse_search_type,
                    args.reverse_search,
                    match=args.reverse_match
                )
                print_result(result)

            elif args.reverse_dns:
                result = client.reverse_dns(args.reverse_dns)
                print_result(result)

            elif args.reverse_ip_type and args.reverse_ip_data:
                result = client.reverse_ip(args.reverse_ip_type, args.reverse_ip_data)
                print_result(result)

            elif args.reverse_mx_type and args.reverse_mx_data:
                result = client.reverse_mx(
                    args.reverse_mx_type,
                    args.reverse_mx_data,
                    recursive=args.recursive
                )
                print_result(result)

            # Bulk operations
            elif args.bulk_dns:
                result = client.bulk_dns(args.bulk_dns)
                print_result(result)

            elif args.bulk_whois:
                result = client.bulk_whois(args.bulk_whois, args.bulk_whois_type)
                print_result(result)

            elif args.bulk_whois_ip:
                result = client.bulk_whois_ip(args.bulk_whois_ip)
                print_result(result)

            # Monitoring operations
            elif args.monitor_list:
                result = client.monitor_list()
                print_result(result)

            elif args.monitor_report_items:
                result = client.monitor_report_items(args.monitor_report_items)
                print_result(result)

            elif args.monitor_report_summary:
                result = client.monitor_report_summary(
                    args.monitor_report_summary,
                    item_id=args.monitor_item,
                    days_range=args.monitor_range
                )
                print_result(result)

            elif args.monitor_report_changes and args.monitor_change:
                result = client.monitor_report_changes(
                    args.monitor_report_changes,
                    args.monitor_change
                )
                print_result(result)

            # Monitor management
            elif args.create_monitor_report:
                report_type, name = args.create_monitor_report
                result = client.create_monitor_report(
                    report_type,
                    name,
                    email_alert=args.email_alert
                )
                print_result(result)

            elif args.add_monitor_item:
                report_id, item_type, items = args.add_monitor_item
                items_list = items.split(",")
                result = client.add_monitor_item(
                    int(report_id),
                    item_type,
                    items_list
                )
                print_result(result)

            elif args.enable_typos:
                report_id, item_id = map(int, args.enable_typos)
                result = client.enable_typos(report_id, item_id)
                print_result(result)

            elif args.disable_typos:
                report_id, item_id = map(int, args.disable_typos)
                result = client.disable_typos(report_id, item_id)
                print_result(result)

            elif args.modify_typo_strength:
                report_id, item_id, strength = map(int, args.modify_typo_strength)
                result = client.modify_typo_strength(report_id, item_id, strength)
                print_result(result)

            elif args.delete_monitor_item:
                result = client.delete_monitor_item(args.delete_monitor_item)
                print_result(result)

            elif args.delete_monitor_report:
                result = client.delete_monitor_report(args.delete_monitor_report)
                print_result(result)

            else:
                parser.print_help()
                return 1

    except DomainIQError:
        return 1
    except KeyboardInterrupt:
        return 1
    except Exception:
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
