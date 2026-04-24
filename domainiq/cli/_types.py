"""Typed CLI argument containers (DTOs) for decoupling handlers from argparse."""

from __future__ import annotations

import argparse
from dataclasses import dataclass


@dataclass(frozen=True)
class WhoisArgs:
    query: str
    full: bool
    current_only: bool

    @classmethod
    def from_namespace(cls, args: argparse.Namespace) -> WhoisArgs:
        return cls(query=args.whois_lookup, full=args.full, current_only=args.current_only)


@dataclass(frozen=True)
class DnsArgs:
    query: str
    types: list[str] | None

    @classmethod
    def from_namespace(cls, args: argparse.Namespace) -> DnsArgs:
        types = args.types.split(",") if args.types else None
        return cls(query=args.dns_lookup, types=types)


@dataclass(frozen=True)
class DomainSearchArgs:
    keywords: list[str]
    conditions: list[str] | None
    match: str
    count_only: bool
    exclude_dashed: bool
    exclude_numbers: bool
    exclude_idn: bool
    min_length: int | None
    max_length: int | None
    min_create_date: str | None
    max_create_date: str | None
    search_limit: int | None

    @classmethod
    def from_namespace(cls, args: argparse.Namespace) -> DomainSearchArgs:
        return cls(
            keywords=args.domain_search,
            conditions=args.conditions,
            match=args.match,
            count_only=args.count_only,
            exclude_dashed=args.exclude_dashed,
            exclude_numbers=args.exclude_numbers,
            exclude_idn=args.exclude_idn,
            min_length=args.min_length,
            max_length=args.max_length,
            min_create_date=args.min_create_date,
            max_create_date=args.max_create_date,
            search_limit=args.search_limit,
        )
