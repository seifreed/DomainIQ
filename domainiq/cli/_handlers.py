"""Command handlers and serialization helpers for the DomainIQ CLI."""

import argparse

from domainiq._models import DomainSearchFilters, KeywordMatchType, SnapshotOptions
from domainiq._protocols import DNSProtocol, SearchProtocol, WhoisProtocol
from domainiq.constants import SNAPSHOT_DEFAULT_HEIGHT, SNAPSHOT_DEFAULT_WIDTH
from domainiq.search_filters import build_search_filters
from domainiq.validators import is_ip_address

from ._serialization import print_result
from ._types import DnsArgs, DomainSearchArgs, WhoisArgs


def build_snapshot_options(args: argparse.Namespace) -> SnapshotOptions:
    """Build SnapshotOptions from parsed CLI args."""
    return SnapshotOptions(
        full=args.snapshot_full,
        no_cache=args.no_cache,
        raw=args.raw,
        width=args.width if args.width is not None else SNAPSHOT_DEFAULT_WIDTH,
        height=args.height if args.height is not None else SNAPSHOT_DEFAULT_HEIGHT,
    )


def handle_whois_lookup(client: WhoisProtocol, args: WhoisArgs) -> None:
    """Handle WHOIS lookup command."""
    domain = None
    ip = None
    if is_ip_address(args.query):
        ip = args.query
    else:
        domain = args.query
    result = client.whois_lookup(
        domain=domain, ip=ip, full=args.full, current_only=args.current_only
    )
    print_result(result)


def handle_dns_lookup(client: DNSProtocol, args: DnsArgs) -> None:
    """Handle DNS lookup command."""
    result = client.dns_lookup(args.query, record_types=args.types)
    print_result(result)


def _build_domain_search_filters(args: DomainSearchArgs) -> DomainSearchFilters:
    return build_search_filters(
        count_only=args.count_only,
        exclude_dashed=args.exclude_dashed,
        exclude_numbers=args.exclude_numbers,
        exclude_idn=args.exclude_idn,
        min_length=args.min_length,
        max_length=args.max_length,
        min_create_date=args.min_create_date,
        max_create_date=args.max_create_date,
        limit=args.search_limit,
    )


def handle_domain_search(client: SearchProtocol, args: DomainSearchArgs) -> None:
    """Handle domain search command."""
    filters = _build_domain_search_filters(args)
    result = client.domain_search(
        keywords=args.keywords,
        conditions=args.conditions,
        match=KeywordMatchType(args.match),
        filters=filters or None,
    )
    print_result(result)
