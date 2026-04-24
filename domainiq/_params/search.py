"""Search request-parameter builders."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from domainiq.constants import API_FLAG_ENABLED, API_INDEXED_PARAM
from domainiq.exceptions import DomainIQValidationError
from domainiq.utils import enum_value

if TYPE_CHECKING:
    from domainiq._models import (
        DomainSearchFilters,
        KeywordMatchType,
        ReverseIpSearchType,
        ReverseMatchType,
        ReverseMxSearchType,
        ReverseSearchType,
    )

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
