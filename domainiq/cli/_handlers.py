"""Command handlers and serialization helpers for the DomainIQ CLI."""

import argparse
import base64
import dataclasses
import json
import sys
from datetime import datetime

from ..constants import SNAPSHOT_DEFAULT_HEIGHT, SNAPSHOT_DEFAULT_LIMIT, SNAPSHOT_DEFAULT_WIDTH
from ..exceptions import DomainIQError
from ..models import DomainSearchFilters, KeywordMatchType
from ..protocols import DNSProtocol, SearchProtocol, WhoisProtocol
from ..validators import is_ip_address, validate_date_string

_DEFAULT_SNAPSHOT_WIDTH = SNAPSHOT_DEFAULT_WIDTH
_DEFAULT_SNAPSHOT_HEIGHT = SNAPSHOT_DEFAULT_HEIGHT
_DEFAULT_SNAPSHOT_LIMIT = SNAPSHOT_DEFAULT_LIMIT


def _serialize(obj: object) -> object:
    """Serialize an object (dataclass, dict, list, or primitive) for JSON output."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode("ascii")
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize(item) for item in obj]
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _serialize(v) for k, v in vars(obj).items()}
    return obj


def print_result(result: object, indent: int = 2) -> None:
    """Print API result in formatted JSON."""
    if result is None:
        print("No data returned")
        return

    try:
        serialized = _serialize(result)
        print(json.dumps(serialized, indent=indent, default=str))
    except (TypeError, ValueError) as e:
        msg = f"Failed to serialize result as JSON: {e}"
        raise DomainIQError(msg) from e


def handle_whois_lookup(client: WhoisProtocol, args: argparse.Namespace) -> None:
    """Handle WHOIS lookup command."""
    domain = None
    ip = None

    query = args.whois_lookup
    if is_ip_address(query):
        ip = query
    else:
        domain = query

    result = client.whois_lookup(
        domain=domain, ip=ip, full=args.full, current_only=args.current_only
    )
    print_result(result)


def handle_dns_lookup(client: DNSProtocol, args: argparse.Namespace) -> None:
    """Handle DNS lookup command."""
    types = args.types.split(",") if args.types else None
    result = client.dns_lookup(args.dns_lookup, record_types=types)
    print_result(result)


def handle_domain_search(client: SearchProtocol, args: argparse.Namespace) -> None:
    """Handle domain search command."""
    filters: DomainSearchFilters = {}

    if args.count_only:
        filters["count_only"] = 1
    if args.exclude_dashed:
        filters["exclude_dashed"] = True
    if args.exclude_numbers:
        filters["exclude_numbers"] = True
    if args.exclude_idn:
        filters["exclude_idn"] = True
    if args.min_length is not None:
        filters["min_length"] = args.min_length
    if args.max_length is not None:
        filters["max_length"] = args.max_length
    if args.min_create_date:
        parsed = validate_date_string(args.min_create_date)
        if parsed is None:
            msg = f"Invalid date format for --min-create-date: {args.min_create_date}"
            raise ValueError(msg)
        filters["min_create_date"] = parsed
    if args.max_create_date:
        parsed = validate_date_string(args.max_create_date)
        if parsed is None:
            msg = f"Invalid date format for --max-create-date: {args.max_create_date}"
            raise ValueError(msg)
        filters["max_create_date"] = parsed
    if args.search_limit is not None:
        filters["limit"] = args.search_limit

    result = client.domain_search(
        keywords=args.domain_search,
        conditions=args.conditions,
        match=KeywordMatchType(args.match),
        filters=filters or None,
    )
    print_result(result)
