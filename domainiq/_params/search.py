"""Search request-parameter builders."""

from __future__ import annotations

import logging
from typing import Any

from ..constants import API_FLAG_ENABLED, API_INDEXED_PARAM
from ..exceptions import DomainIQValidationError
from ..models import (
    DomainSearchFilters,
    KeywordMatchType,
    ReverseIpSearchType,
    ReverseMatchType,
    ReverseMxSearchType,
    ReverseSearchType,
)
from ..utils import enum_value
from ..validators import validate_date_string

logger = logging.getLogger(__name__)


def _add_indexed_params(params: dict[str, Any], name: str, values: list[str]) -> None:
    for idx, value in enumerate(values, 1):
        params[API_INDEXED_PARAM.format(name=name, idx=idx)] = value


def _validate_conditions(keywords: list[str], conditions: list[str]) -> None:
    if len(conditions) > len(keywords):
        msg = "conditions list cannot be longer than keywords list"
        raise DomainIQValidationError(msg, param_name="conditions")
    if len(conditions) < len(keywords):
        logger.warning(
            "Fewer conditions (%d) than keywords (%d); "
            "keywords without conditions will use API defaults",
            len(conditions),
            len(keywords),
        )


def _validate_date_param(value: str, param_name: str) -> str:
    parsed = validate_date_string(value)
    if parsed is None:
        msg = f"Invalid date format for {param_name}: {value}"
        raise DomainIQValidationError(msg, param_name=param_name)
    return parsed


def build_search_filters(
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


def build_domain_search_params(
    keywords: list[str],
    conditions: list[str] | None,
    match: KeywordMatchType,
    filters: DomainSearchFilters | None,
) -> dict[str, Any]:
    """Build parameters for the keyword search endpoint."""
    if not keywords:
        msg = "keywords list cannot be empty"
        raise DomainIQValidationError(msg, param_name="keywords")
    params: dict[str, Any] = {
        "service": "domain_search",
        "match": enum_value(match),
    }
    _add_indexed_params(params, "keyword", keywords)
    if conditions:
        _validate_conditions(keywords, conditions)
        _add_indexed_params(params, "condition", conditions)
    if filters:
        params.update(filters)
    return params


def build_reverse_search_params(
    search_type: str | ReverseSearchType,
    search_term: str,
    match: ReverseMatchType,
) -> dict[str, Any]:
    """Build parameters for the reverse-search endpoint."""
    return {
        "service": "reverse_search",
        "type": enum_value(search_type),
        "search": search_term,
        "match": enum_value(match),
    }


def build_reverse_dns_params(domain: str) -> dict[str, Any]:
    """Build parameters for the reverse-DNS endpoint."""
    return {"service": "reverse_dns", "domain": domain}


def build_reverse_ip_params(
    search_type: ReverseIpSearchType | str,
    data: str,
) -> dict[str, Any]:
    """Build parameters for the reverse-IP endpoint."""
    return {"service": "reverse_ip", "type": search_type, "data": data}


def build_reverse_mx_params(
    search_type: ReverseMxSearchType | str,
    data: str,
    recursive: bool,
) -> dict[str, Any]:
    """Build parameters for the reverse-MX endpoint."""
    params: dict[str, Any] = {
        "service": "reverse_mx",
        "type": search_type,
        "data": data,
    }
    if recursive:
        params["recursive"] = API_FLAG_ENABLED
    return params
