"""Exception classes for the DomainIQ library."""

from typing import Any, Generic, TypeVar

from ._http_constants import HTTP_TOO_MANY_REQUESTS, HTTP_UNAUTHORIZED

_T = TypeVar("_T")


class DomainIQError(Exception):
    """Base exception for all DomainIQ library errors."""

    def __init__(
        self, message: str, response_data: dict[str, Any] | None = None
    ) -> None:
        super().__init__(message)
        self.message = message
        self.response_data = response_data


class DomainIQAPIError(DomainIQError):
    """Exception raised when the DomainIQ API returns an error response."""

    _status_code: int | None = None  # subclasses may override as a class var

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        response_data: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, response_data)
        self.status_code = status_code if status_code is not None else self.__class__._status_code


class DomainIQAuthenticationError(DomainIQAPIError):
    """Exception raised when authentication fails (invalid API key, etc.)."""

    _status_code = HTTP_UNAUTHORIZED


class DomainIQRateLimitError(DomainIQAPIError):
    """Exception raised when rate limit is exceeded."""

    _status_code = HTTP_TOO_MANY_REQUESTS

    def __init__(
        self,
        message: str,
        retry_after: int | None = None,
        response_data: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, status_code=HTTP_TOO_MANY_REQUESTS, response_data=response_data)
        self.retry_after = retry_after


class DomainIQTimeoutError(DomainIQAPIError):
    """Exception raised when a request times out."""


class DomainIQConfigurationError(DomainIQError):
    """Exception raised when there's a configuration error."""


class DomainIQValidationError(DomainIQError):
    """Raised when a parameter fails domain-level validation.

    The ``param_name`` attribute identifies which parameter failed.
    Subclasses ``DomainIQError`` so callers using ``except DomainIQError``
    already handle it without changes.
    """

    def __init__(self, message: str, param_name: str | None = None) -> None:
        super().__init__(message)
        self.param_name = param_name


class DomainIQPartialResultsError(DomainIQError, Generic[_T]):
    """Raised when concurrent operations partially fail; carries successful results."""

    def __init__(self, cause: BaseException, partial_results: list[_T | None]) -> None:
        super().__init__(str(cause))
        self.__cause__ = cause
        self.partial_results: list[_T | None] = partial_results
