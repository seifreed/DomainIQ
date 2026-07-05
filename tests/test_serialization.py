"""Tests for CLI result serialization."""

from __future__ import annotations

import base64
import dataclasses
import json
from datetime import UTC, datetime
from enum import Enum

import pytest

from domainiq.cli._serialization import print_result, serialize_result
from domainiq.exceptions import DomainIQError


class _TestEnum(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"


@dataclasses.dataclass
class _TestData:
    name: str
    value: int


class TestSerializeResult:
    def test_datetime_isoformat(self) -> None:
        dt = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        assert serialize_result(dt) == "2024-01-01T12:00:00+00:00"

    def test_bytes_base64(self) -> None:
        assert serialize_result(b"hello") == base64.b64encode(b"hello").decode("ascii")

    def test_enum_value_regression(self) -> None:
        """Regression: Enum serialized as repr name instead of value."""
        assert serialize_result(_TestEnum.ACTIVE) == "active"

    def test_tuple_treated_as_list_regression(self) -> None:
        """Regression: tuple contents bypassed serialization."""
        assert serialize_result((b"data",)) == [
            base64.b64encode(b"data").decode("ascii")
        ]

    def test_nested_tuple_in_dict_regression(self) -> None:
        """Regression: nested tuples were not recursively serialized."""
        result = serialize_result({"items": (b"a", b"b")})
        assert result == {
            "items": [
                base64.b64encode(b"a").decode("ascii"),
                base64.b64encode(b"b").decode("ascii"),
            ]
        }

    def test_dataclass_serialization(self) -> None:
        obj = _TestData(name="test", value=42)
        assert serialize_result(obj) == {"name": "test", "value": 42}

    def test_depth_limit(self) -> None:
        deeply_nested: dict[str, object] = {}
        current = deeply_nested
        for _ in range(101):
            child: dict[str, object] = {}
            current["child"] = child
            current = child
        with pytest.raises(DomainIQError):
            serialize_result(deeply_nested)


class TestPrintResult:
    def test_none_prints_no_data(self, capsys: pytest.CaptureFixture[str]) -> None:
        print_result(None)
        assert "No data returned" in capsys.readouterr().out

    def test_valid_json_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        print_result({"key": "value"})
        out = capsys.readouterr().out
        assert json.loads(out) == {"key": "value"}

    def test_enum_in_output_regression(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Regression: Enum in output produced invalid JSON."""
        print_result({"status": _TestEnum.ACTIVE})
        out = capsys.readouterr().out
        assert json.loads(out) == {"status": "active"}

    def test_tuple_in_output_regression(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Regression: tuple in output produced invalid JSON."""
        print_result({"items": (b"data",)})
        out = capsys.readouterr().out
        assert json.loads(out) == {"items": [base64.b64encode(b"data").decode("ascii")]}
