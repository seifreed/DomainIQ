"""Unit tests for DomainIQ utility helpers."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from typing import TYPE_CHECKING

import pytest

from domainiq.exceptions import DomainIQAPIError
from domainiq.utils import (
    assert_json_dict,
    compute_backoff,
    csv_to_dict_list,
    ensure_list_of_models,
    parse_retry_after,
    setup_logging,
    truncate_repr,
    validate_api_dict,
)

if TYPE_CHECKING:
    from pathlib import Path


class TestJsonAndReprHelpers:
    def test_assert_json_dict_accepts_dict(self) -> None:
        raw = {"ok": True}

        assert assert_json_dict(raw) is raw

    def test_assert_json_dict_rejects_other_json_shapes(self) -> None:
        with pytest.raises(DomainIQAPIError, match="Expected JSON dict"):
            assert_json_dict(["not", "a", "dict"])

    def test_validate_api_dict_accepts_non_empty_dict(self) -> None:
        raw = {"ok": True}

        assert validate_api_dict(raw, "TestResult") is raw

    def test_validate_api_dict_rejects_empty_dict(self) -> None:
        with pytest.raises(
            DomainIQAPIError, match="Expected TestResult but got empty dict"
        ):
            validate_api_dict({}, "TestResult")

    def test_validate_api_dict_rejects_missing_required_keys(self) -> None:
        with pytest.raises(
            DomainIQAPIError, match="Expected TestResult with at least one of"
        ):
            validate_api_dict({"other": 1}, "TestResult", ("required_a", "required_b"))

    def test_validate_api_dict_accepts_dict_with_required_key(self) -> None:
        raw = {"required_a": 1}

        assert validate_api_dict(raw, "TestResult", ("required_a", "required_b")) is raw

    def test_truncate_repr_shortens_long_values(self) -> None:
        value = "x" * 20

        assert truncate_repr(value, max_len=10).endswith("...")

    def test_truncate_repr_never_exceeds_max_len(self) -> None:
        value = "x" * 200

        result = truncate_repr(value, max_len=50)
        assert len(result) <= 50
        assert result.endswith("...")

    def test_truncate_repr_small_max_len(self) -> None:
        value = "x" * 20

        result = truncate_repr(value, max_len=2)
        assert len(result) <= 2

    def test_truncate_repr_max_len_three_includes_ellipsis_regression(
        self,
    ) -> None:
        value = "x" * 20

        result = truncate_repr(value, max_len=3)
        assert result == "..."


class TestRetryAndCsvHelpers:
    def test_compute_backoff_doubles_per_attempt(self) -> None:
        assert compute_backoff(2, 3) == 16.0

    def test_compute_backoff_capped_at_30_regression(self) -> None:
        """Regression: very large attempt caused integer overflow/hang."""
        assert compute_backoff(1, 1000) == compute_backoff(1, 30)

    def test_parse_retry_after(self) -> None:
        assert parse_retry_after({"Retry-After": "10"}) == 10
        assert parse_retry_after({"Retry-After": "0"}) == 0
        assert parse_retry_after({"Retry-After": "-5"}) is None
        assert parse_retry_after({"retry-after": "10"}) == 10
        assert parse_retry_after({"RETRY-AFTER": "10"}) == 10
        assert parse_retry_after({"Retry-After": "soon"}) is None
        assert parse_retry_after({"retry-after": "soon"}) is None
        assert parse_retry_after({}) is None

    def test_parse_retry_after_http_date(self) -> None:
        retry_at = datetime.now(UTC) + timedelta(seconds=60)
        header = format_datetime(retry_at, usegmt=True)

        retry_after = parse_retry_after({"Retry-After": header})

        assert retry_after is not None
        assert 45 <= retry_after <= 60

    def test_parse_retry_after_past_http_date_returns_none(self) -> None:
        retry_at = datetime.now(UTC) - timedelta(seconds=60)
        header = format_datetime(retry_at, usegmt=True)

        assert parse_retry_after({"Retry-After": header}) is None

    def test_csv_to_dict_list_parses_rows_and_empty_content(self) -> None:
        assert csv_to_dict_list("domain,ip\nexample.com,192.0.2.1\n") == [
            {"domain": "example.com", "ip": "192.0.2.1"}
        ]
        assert csv_to_dict_list("   ") == []

    def test_csv_to_dict_list_returns_empty_for_json_like_content_regression(
        self,
    ) -> None:
        """Regression: JSON-like strings are no longer misidentified as CSV errors."""
        assert csv_to_dict_list('{"domain": "example.com"}') == []

    def test_csv_to_dict_list_accepts_csv_starting_with_brace_regression(self) -> None:
        assert csv_to_dict_list('"{header",value\nexample.com,192.0.2.1\n') == [
            {"{header": "example.com", "value": "192.0.2.1"}
        ]


class TestModelListHelper:
    def test_ensure_list_of_models_wraps_dict_and_maps_lists(self) -> None:
        def factory(item: dict[str, object]) -> str:
            return str(item["name"]).upper()

        assert ensure_list_of_models({"name": "one"}, factory) == ["ONE"]
        assert ensure_list_of_models([{"name": "one"}, {"name": "two"}], factory) == [
            "ONE",
            "TWO",
        ]


class TestSetupLogging:
    def test_setup_logging_adds_one_stream_handler(self) -> None:
        logger = logging.getLogger("domainiq")
        original_handlers = list(logger.handlers)
        original_level = logger.level
        logger.handlers.clear()
        try:
            setup_logging("DEBUG")
            setup_logging("INFO")

            assert len(logger.handlers) == 1
            assert logger.level == logging.INFO
        finally:
            for handler in logger.handlers:
                handler.close()
            logger.handlers[:] = original_handlers
            logger.setLevel(original_level)

    def test_setup_logging_supports_file_handler(self, tmp_path: Path) -> None:
        logger = logging.getLogger("domainiq")
        original_handlers = list(logger.handlers)
        original_level = logger.level
        logger.handlers.clear()
        log_file = tmp_path / "domainiq.log"
        try:
            setup_logging("WARNING", filename=str(log_file))
            logger.warning("written")

            assert log_file.exists()
            assert "written" in log_file.read_text()
        finally:
            for handler in logger.handlers:
                handler.close()
            logger.handlers[:] = original_handlers
            logger.setLevel(original_level)

    def test_setup_logging_replaces_existing_handlers_regression(
        self, tmp_path: Path
    ) -> None:
        logger = logging.getLogger("domainiq")
        original_handlers = list(logger.handlers)
        original_level = logger.level
        logger.handlers.clear()
        log_file = tmp_path / "domainiq.log"
        try:
            setup_logging("INFO")
            setup_logging("WARNING", filename=str(log_file))
            logger.warning("written")

            assert len(logger.handlers) == 1
            assert isinstance(logger.handlers[0], logging.FileHandler)
            assert log_file.exists()
            assert "written" in log_file.read_text()
        finally:
            for handler in logger.handlers:
                handler.close()
            logger.handlers[:] = original_handlers
            logger.setLevel(original_level)
