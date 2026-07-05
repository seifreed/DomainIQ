"""Helpers for building public domain-search filter objects."""

from __future__ import annotations

from typing import TYPE_CHECKING, TypedDict

from .exceptions import DomainIQValidationError
from .validators import ensure_positive_int, validate_date_string

if TYPE_CHECKING:
    from typing import Unpack

    from ._models import DomainSearchFilters


class SearchFilterOptions(TypedDict, total=False):
    """Keyword options accepted by :func:`build_search_filters`."""

    count_only: bool
    exclude_dashed: bool
    exclude_numbers: bool
    exclude_idn: bool
    min_length: int | None
    max_length: int | None
    min_create_date: str | None
    max_create_date: str | None
    limit: int | None


def _validate_date_param(value: str, param_name: str) -> str:
    try:
        return validate_date_string(value)
    except DomainIQValidationError:
        msg = f"Invalid date format for {param_name}: {value}"
        raise DomainIQValidationError(msg, param_name=param_name) from None


def _validate_length_range(min_length: int | None, max_length: int | None) -> None:
    if min_length is not None and max_length is not None and min_length > max_length:
        msg = "min_length cannot be greater than max_length"
        raise DomainIQValidationError(msg, param_name="min_length")


def build_search_filters(
    **options: Unpack[SearchFilterOptions],
) -> DomainSearchFilters:
    """Build search filters, validating date strings when present."""
    min_length = options.get("min_length")
    max_length = options.get("max_length")
    limit = options.get("limit")
    min_create_date = options.get("min_create_date")
    max_create_date = options.get("max_create_date")

    filters: DomainSearchFilters = {}
    if options.get("count_only"):
        filters["count_only"] = 1
    if options.get("exclude_dashed"):
        filters["exclude_dashed"] = True
    if options.get("exclude_numbers"):
        filters["exclude_numbers"] = True
    if options.get("exclude_idn"):
        filters["exclude_idn"] = True
    if min_length is not None:
        min_length = ensure_positive_int("min_length", min_length)
    if max_length is not None:
        max_length = ensure_positive_int("max_length", max_length)
    if limit is not None:
        limit = ensure_positive_int("limit", limit)
    _validate_length_range(min_length, max_length)
    if min_length is not None:
        filters["min_length"] = min_length
    if max_length is not None:
        filters["max_length"] = max_length
    if min_create_date:
        filters["min_create_date"] = _validate_date_param(
            min_create_date,
            "min_create_date",
        )
    if max_create_date:
        filters["max_create_date"] = _validate_date_param(
            max_create_date,
            "max_create_date",
        )
    if limit is not None:
        filters["limit"] = limit
    return filters


__all__ = ["build_search_filters"]
