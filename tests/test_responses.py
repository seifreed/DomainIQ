"""Tests for HTTP response wrappers."""

from __future__ import annotations

import pytest

from domainiq.http._responses import SyncResponse, _decode_json_body


class TestDecodeJsonBody:
    def test_parses_valid_json_object(self) -> None:
        result = _decode_json_body('{"key": "value"}')
        assert result == {"key": "value"}

    def test_parses_valid_json_array(self) -> None:
        result = _decode_json_body("[1, 2, 3]")
        assert result == [1, 2, 3]

    def test_rejects_empty_body_with_clear_error(self) -> None:
        """Regression: empty string caused JSONDecodeError instead of ValueError."""
        with pytest.raises(ValueError, match="Response body is empty"):
            _decode_json_body("")

    def test_rejects_whitespace_only_body(self) -> None:
        with pytest.raises(ValueError, match="Response body is empty"):
            _decode_json_body("   \n\t  ")

    def test_rejects_scalar_json(self) -> None:
        with pytest.raises(ValueError, match="Expected JSON object or array"):
            _decode_json_body('"just a string"')


class TestSyncResponseJson:
    def test_lazy_decoding(self) -> None:
        response = SyncResponse(status_code=200, headers={}, text='{"ok": true}')
        assert response.json() == {"ok": True}
