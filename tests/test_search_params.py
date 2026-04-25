"""Unit tests for search request-parameter builders."""

from __future__ import annotations

import logging

import pytest

from domainiq._params.search import (
    build_domain_search_params,
    build_reverse_dns_params,
    build_reverse_ip_params,
    build_reverse_mx_params,
    build_reverse_search_params,
)
from domainiq.constants import API_FLAG_ENABLED
from domainiq.exceptions import DomainIQValidationError
from domainiq.models import (
    KeywordMatchType,
    ReverseIpSearchType,
    ReverseMatchType,
    ReverseMxSearchType,
    ReverseSearchType,
)


class TestDomainSearchParams:
    def test_indexes_keywords_conditions_and_merges_filters(self) -> None:
        params = build_domain_search_params(
            ["brand", "login"],
            ["contains", "begins"],
            KeywordMatchType.ALL,
            {"count_only": 1, "exclude_dashed": True},
        )

        assert params == {
            "service": "domain_search",
            "match": "all",
            "keyword[1]": "brand",
            "keyword[2]": "login",
            "condition[1]": "contains",
            "condition[2]": "begins",
            "count_only": 1,
            "exclude_dashed": True,
        }

    def test_empty_keywords_raise_validation_error(self) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            build_domain_search_params([], None, KeywordMatchType.ANY, None)

        assert exc_info.value.param_name == "keywords"

    @pytest.mark.parametrize("keywords", [[""], ["  "], ["brand", ""]])
    def test_empty_keyword_values_raise_validation_error(
        self, keywords: list[str]
    ) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            build_domain_search_params(keywords, None, KeywordMatchType.ANY, None)

        assert exc_info.value.param_name == "keywords"

    @pytest.mark.parametrize("conditions", [[""], ["  "]])
    def test_empty_condition_values_raise_validation_error(
        self, conditions: list[str]
    ) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            build_domain_search_params(
                ["brand"], conditions, KeywordMatchType.ANY, None
            )

        assert exc_info.value.param_name == "conditions"

    def test_short_conditions_warn_and_preserve_supplied_conditions(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="domainiq._params.search"):
            params = build_domain_search_params(
                ["brand", "login"], ["contains"], KeywordMatchType.ANY, None
            )

        assert "Fewer conditions" in caplog.text
        assert params["keyword[1]"] == "brand"
        assert params["keyword[2]"] == "login"
        assert params["condition[1]"] == "contains"
        assert "condition[2]" not in params

    def test_long_conditions_raise_validation_error(self) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            build_domain_search_params(
                ["brand"],
                ["contains", "begins"],
                KeywordMatchType.ANY,
                None,
            )

        assert exc_info.value.param_name == "conditions"

    def test_invalid_match_type_raises_validation_error(self) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            build_domain_search_params(["brand"], None, "garbage", None)

        assert exc_info.value.param_name == "match"


class TestReverseSearchParams:
    def test_reverse_search_uses_enum_wire_values(self) -> None:
        assert build_reverse_search_params(
            ReverseSearchType.EMAIL,
            "admin@example.com",
            ReverseMatchType.ENDS,
        ) == {
            "service": "reverse_search",
            "type": "email",
            "search": "admin@example.com",
            "match": "ends",
        }

    def test_reverse_dns_params(self) -> None:
        assert build_reverse_dns_params("example.com") == {
            "service": "reverse_dns",
            "domain": "example.com",
        }

    def test_reverse_ip_params(self) -> None:
        assert build_reverse_ip_params(ReverseIpSearchType.DOMAIN, "example.com") == {
            "service": "reverse_ip",
            "type": ReverseIpSearchType.DOMAIN,
            "data": "example.com",
        }

    def test_reverse_mx_omits_recursive_when_false(self) -> None:
        assert build_reverse_mx_params(
            ReverseMxSearchType.DOMAIN, "example.com", False
        ) == {
            "service": "reverse_mx",
            "type": ReverseMxSearchType.DOMAIN,
            "data": "example.com",
        }

    def test_reverse_mx_includes_recursive_flag_when_true(self) -> None:
        params = build_reverse_mx_params(ReverseMxSearchType.IP, "192.0.2.1", True)

        assert params["recursive"] == API_FLAG_ENABLED

    @pytest.mark.parametrize(
        ("build_params", "param_name"),
        [
            (lambda: build_reverse_dns_params("example..com"), "domain"),
            (
                lambda: build_reverse_search_params(
                    ReverseSearchType.EMAIL,
                    "bad local@example.com",
                    ReverseMatchType.CONTAINS,
                ),
                "search",
            ),
            (
                lambda: build_reverse_ip_params(
                    ReverseIpSearchType.IP, "999.999.999.999"
                ),
                "data",
            ),
            (
                lambda: build_reverse_ip_params(
                    ReverseIpSearchType.DOMAIN, "example..com"
                ),
                "data",
            ),
            (
                lambda: build_reverse_mx_params(
                    ReverseMxSearchType.DOMAIN, "example..com", False
                ),
                "data",
            ),
            (
                lambda: build_reverse_mx_params(
                    ReverseMxSearchType.IP, "999.999.999.999", False
                ),
                "data",
            ),
            (
                lambda: build_reverse_search_params(
                    "garbage",
                    "admin@example.com",
                    ReverseMatchType.CONTAINS,
                ),
                "type",
            ),
            (
                lambda: build_reverse_search_params(
                    ReverseSearchType.EMAIL,
                    "admin@example.com",
                    "garbage",
                ),
                "match",
            ),
            (lambda: build_reverse_ip_params("garbage", "192.0.2.1"), "type"),
            (lambda: build_reverse_mx_params("garbage", "example.com", False), "type"),
        ],
    )
    def test_reverse_params_reject_invalid_typed_values(
        self, build_params, param_name: str
    ) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            build_params()

        assert exc_info.value.param_name == param_name
