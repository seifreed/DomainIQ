"""Unit tests for HTTP response classification policy."""

from __future__ import annotations

import pytest

from domainiq._request_pipeline import RequestPolicy, classify_http_response
from domainiq.exceptions import (
    DomainIQAPIError,
    DomainIQAuthenticationError,
    DomainIQRateLimitError,
)

_EMPTY_HEADERS: dict[str, str] = {}
_RETRY_HEADERS: dict[str, str] = {"Retry-After": "5"}
_POLICY = RequestPolicy(
    base_url="https://www.domainiq.com/api",
    timeout=30.0,
    max_retries=3,
    retry_delay=1,
)
_LONG_POLICY = RequestPolicy(
    base_url="https://www.domainiq.com/api",
    timeout=30.0,
    max_retries=10,
    retry_delay=1,
)
_DEEP_POLICY = RequestPolicy(
    base_url="https://www.domainiq.com/api",
    timeout=30.0,
    max_retries=5,
    retry_delay=1,
)


class TestSuccessStatus:
    def test_2xx_returns_none(self) -> None:
        assert classify_http_response(200, "", _EMPTY_HEADERS, 0, _POLICY) is None

    def test_201_returns_none(self) -> None:
        assert classify_http_response(201, "", _EMPTY_HEADERS, 0, _POLICY) is None

    def test_204_returns_none(self) -> None:
        assert classify_http_response(204, "", _EMPTY_HEADERS, 0, _POLICY) is None


class TestRetryableServerErrors:
    @pytest.mark.parametrize("status", [500, 502, 503, 504])
    def test_retryable_with_attempts_remaining_returns_delay(self, status: int) -> None:
        delay = classify_http_response(status, "error", _EMPTY_HEADERS, 0, _POLICY)
        assert isinstance(delay, float)
        assert delay > 0

    @pytest.mark.parametrize("status", [500, 502, 503, 504])
    def test_retryable_exhausted_raises_api_error(self, status: int) -> None:
        with pytest.raises(DomainIQAPIError) as exc_info:
            classify_http_response(status, "error", _EMPTY_HEADERS, 3, _POLICY)
        assert exc_info.value.status_code == status

    def test_delay_increases_with_attempt(self) -> None:
        delay0 = classify_http_response(500, "", _EMPTY_HEADERS, 0, _DEEP_POLICY)
        delay1 = classify_http_response(500, "", _EMPTY_HEADERS, 1, _DEEP_POLICY)
        assert delay0 is not None
        assert delay1 is not None
        assert delay1 >= delay0


class TestAuthenticationError:
    def test_401_raises_authentication_error(self) -> None:
        with pytest.raises(DomainIQAuthenticationError):
            classify_http_response(401, "Unauthorized", _EMPTY_HEADERS, 0, _POLICY)

    def test_401_never_retries(self) -> None:
        with pytest.raises(DomainIQAuthenticationError):
            classify_http_response(401, "Unauthorized", _EMPTY_HEADERS, 0, _LONG_POLICY)


class TestRateLimitError:
    def test_429_with_attempts_remaining_returns_delay(self) -> None:
        delay = classify_http_response(429, "rate limited", _EMPTY_HEADERS, 0, _POLICY)
        assert isinstance(delay, float)
        assert delay > 0

    def test_429_honours_retry_after_header(self) -> None:
        delay = classify_http_response(429, "rate limited", _RETRY_HEADERS, 0, _POLICY)
        assert delay == 5.0

    def test_429_exhausted_raises_rate_limit_error(self) -> None:
        with pytest.raises(DomainIQRateLimitError):
            classify_http_response(429, "rate limited", _EMPTY_HEADERS, 3, _POLICY)

    def test_rate_limit_error_has_correct_status_code(self) -> None:
        with pytest.raises(DomainIQRateLimitError) as exc_info:
            classify_http_response(429, "rate limited", _EMPTY_HEADERS, 3, _POLICY)
        assert exc_info.value.status_code == 429


class TestGeneric4xxErrors:
    @pytest.mark.parametrize("status", [400, 403, 404, 422])
    def test_4xx_raises_api_error(self, status: int) -> None:
        with pytest.raises(DomainIQAPIError) as exc_info:
            classify_http_response(status, "bad request", _EMPTY_HEADERS, 0, _POLICY)
        assert exc_info.value.status_code == status

    def test_4xx_never_retries(self) -> None:
        with pytest.raises(DomainIQAPIError):
            classify_http_response(400, "bad request", _EMPTY_HEADERS, 0, _LONG_POLICY)
