"""Helpers for building public domain-search filter objects."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .exceptions import DomainIQValidationError
from .validators import validate_date_string

if TYPE_CHECKING:
    from .models import DomainSearchFilters


def _validate_date_param(value: str, param_name: str) -> str:
    parsed = validate_date_string(value)
    if parsed is None:
        msg = f"Invalid date format for {param_name}: {value}"
        raise DomainIQValidationError(msg, param_name=param_name)
    return parsed


def build_search_filters(  # noqa: PLR0913 - filters map directly to CLI/API knobs.
    count_only: bool = False,
    exclude_dashed: bool = False,
    exclude_numbers: bool = False,
    exclude_idn: bool = False,
    min_length: int | None = None,
    max_length: int | None = None,
    min_create_date: str | None = None,
    max_create_date: str | None = None,
    limit: int | None = None,
) -> DomainSearchFilters:
    """Build search filters, validating date strings when present."""
    filters: DomainSearchFilters = {}
    if count_only:
        filters["count_only"] = 1
    if exclude_dashed:
        filters["exclude_dashed"] = True
    if exclude_numbers:
        filters["exclude_numbers"] = True
    if exclude_idn:
        filters["exclude_idn"] = True
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
