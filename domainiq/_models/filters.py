"""Typed filter objects accepted by DomainIQ API helpers."""

from typing import TypedDict


class DomainSearchFilters(TypedDict, total=False):
    """Optional filters for domain_search. All fields are optional."""

    tld: str
    created_after: str
    created_before: str
    expired_after: str
    expired_before: str
    updated_after: str
    updated_before: str
    registrar: str
    registered_for: str
    changed_registrars: bool
    ns: str
    country: str
    no_parked: bool
    no_delisted: bool
    count_only: int
    exclude_dashed: bool
    exclude_numbers: bool
    exclude_idn: bool
    min_length: int
    max_length: int
    min_create_date: str
    max_create_date: str
    limit: int


__all__ = ["DomainSearchFilters"]
