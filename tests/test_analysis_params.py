"""Unit tests for domain-analysis request-parameter builders."""

from __future__ import annotations

import pytest

from domainiq._params.analysis import (
    build_domain_categorize_params,
    build_domain_snapshot_history_params,
    build_domain_snapshot_params,
)
from domainiq.constants import API_FLAG_ENABLED
from domainiq.exceptions import DomainIQValidationError
from domainiq.models import SnapshotOptions


class TestDomainCategorizeParams:
    def test_categorize_joins_domains(self) -> None:
        assert build_domain_categorize_params(["example.com", "example.net"]) == {
            "service": "categorize",
            "domains": "example.com,example.net",
        }

    def test_categorize_requires_domains(self) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            build_domain_categorize_params([])

        assert exc_info.value.param_name == "domains"


class TestDomainSnapshotParams:
    def test_snapshot_uses_dimensions_without_optional_flags(self) -> None:
        params = build_domain_snapshot_params(
            "example.com",
            SnapshotOptions(width=640, height=480),
        )

        assert params == {
            "service": "snapshot",
            "domain": "example.com",
            "width": 640,
            "height": 480,
        }

    def test_snapshot_includes_enabled_optional_flags(self) -> None:
        params = build_domain_snapshot_params(
            "example.com",
            SnapshotOptions(full=True, no_cache=True, raw=True),
        )

        assert params["full"] == API_FLAG_ENABLED
        assert params["no_cache"] == API_FLAG_ENABLED
        assert params["raw"] == API_FLAG_ENABLED

    @pytest.mark.parametrize(
        ("options", "param_name"),
        [
            (SnapshotOptions(width=0, height=480), "SnapshotOptions.width"),
            (SnapshotOptions(width=True, height=480), "SnapshotOptions.width"),
            (SnapshotOptions(width=1.5, height=480), "SnapshotOptions.width"),
            (SnapshotOptions(width="640", height=480), "SnapshotOptions.width"),
            (SnapshotOptions(width=640, height=0), "SnapshotOptions.height"),
        ],
    )
    def test_snapshot_requires_positive_dimensions(
        self, options: SnapshotOptions, param_name: str
    ) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            build_domain_snapshot_params("example.com", options)

        assert exc_info.value.param_name == param_name


class TestDomainSnapshotHistoryParams:
    def test_snapshot_history_params(self) -> None:
        assert build_domain_snapshot_history_params("example.com", 640, 480, 5) == {
            "service": "snapshot_history",
            "domain": "example.com",
            "width": 640,
            "height": 480,
            "limit": 5,
        }

    @pytest.mark.parametrize(
        ("width", "height", "limit", "param_name"),
        [
            (0, 480, 5, "width"),
            (640, 0, 5, "height"),
            (640, 480, 0, "limit"),
        ],
    )
    def test_snapshot_history_requires_positive_values(
        self, width: int, height: int, limit: int, param_name: str
    ) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            build_domain_snapshot_history_params("example.com", width, height, limit)

        assert exc_info.value.param_name == param_name
