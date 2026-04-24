"""Unit tests for public search filter construction."""

from __future__ import annotations

import pytest

from domainiq.exceptions import DomainIQValidationError
from domainiq.search_filters import build_search_filters


class TestBuildSearchFilters:
    def test_empty_filters_return_empty_dict(self) -> None:
        assert build_search_filters() == {}

    def test_boolean_and_numeric_filters_are_included_when_set(self) -> None:
        filters = build_search_filters(
            count_only=True,
            exclude_dashed=True,
            exclude_numbers=True,
            exclude_idn=True,
            min_length=3,
            max_length=12,
            limit=50,
        )

        assert filters == {
            "count_only": 1,
            "exclude_dashed": True,
            "exclude_numbers": True,
            "exclude_idn": True,
            "min_length": 3,
            "max_length": 12,
            "limit": 50,
        }

    def test_valid_date_filters_are_preserved(self) -> None:
        filters = build_search_filters(
            min_create_date="2024-01-01",
            max_create_date="2024-12-31",
        )

        assert filters["min_create_date"] == "2024-01-01"
        assert filters["max_create_date"] == "2024-12-31"

    def test_invalid_min_date_raises_validation_error(self) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            build_search_filters(min_create_date="20240101")

        assert exc_info.value.param_name == "min_create_date"

    def test_invalid_max_date_raises_validation_error(self) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            build_search_filters(max_create_date="2024-99-99")

        assert exc_info.value.param_name == "max_create_date"

    @pytest.mark.parametrize(
        ("kwargs", "param_name"),
        [
            ({"min_length": 0}, "min_length"),
            ({"max_length": 0}, "max_length"),
            ({"limit": 0}, "limit"),
            ({"limit": -5}, "limit"),
        ],
    )
    def test_numeric_filters_must_be_positive(
        self, kwargs: dict[str, int], param_name: str
    ) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            build_search_filters(**kwargs)

        assert exc_info.value.param_name == param_name

    def test_min_length_cannot_exceed_max_length(self) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            build_search_filters(min_length=10, max_length=5)

        assert exc_info.value.param_name == "min_length"
