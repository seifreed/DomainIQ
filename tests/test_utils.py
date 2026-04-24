"""Unit tests for DomainIQ utility helpers."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import pytest

from domainiq.exceptions import DomainIQAPIError, DomainIQError
from domainiq.utils import (
    assert_json_dict,
    compute_backoff,
    csv_to_dict_list,
    ensure_list_of_models,
    parse_retry_after,
    setup_logging,
    truncate_repr,
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

    def test_truncate_repr_shortens_long_values(self) -> None:
        value = "x" * 20

        assert truncate_repr(value, max_len=10).endswith("...")


class TestRetryAndCsvHelpers:
    def test_compute_backoff_doubles_per_attempt(self) -> None:
        assert compute_backoff(2, 3) == 16.0

    def test_parse_retry_after(self) -> None:
        assert parse_retry_after({"Retry-After": "10"}) == 10
        assert parse_retry_after({"retry-after": "10"}) == 10
        assert parse_retry_after({"RETRY-AFTER": "10"}) == 10
        assert parse_retry_after({"Retry-After": "soon"}) is None
        assert parse_retry_after({"retry-after": "soon"}) is None
        assert parse_retry_after({}) is None

    def test_csv_to_dict_list_parses_rows_and_empty_content(self) -> None:
        assert csv_to_dict_list("domain,ip\nexample.com,192.0.2.1\n") == [
            {"domain": "example.com", "ip": "192.0.2.1"}
        ]
        assert csv_to_dict_list("   ") == []

    def test_csv_to_dict_list_rejects_json_like_content(self) -> None:
        with pytest.raises(DomainIQError, match="Expected CSV"):
            csv_to_dict_list('{"domain": "example.com"}')


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
