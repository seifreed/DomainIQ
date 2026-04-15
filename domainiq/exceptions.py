"""Exception classes for the DomainIQ library."""


class DomainIQError(Exception):
    """Base exception for all DomainIQ library errors."""

    def __init__(self, message: str, response_data: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.response_data = response_data


class DomainIQAPIError(DomainIQError):
    """Exception raised when the DomainIQ API returns an error response."""

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        response_data: dict | None = None,
    ) -> None:
        super().__init__(message, response_data)
        self.status_code = status_code


class DomainIQAuthenticationError(DomainIQAPIError):
    """Exception raised when authentication fails (invalid API key, etc.)."""


class DomainIQRateLimitError(DomainIQAPIError):
    """Exception raised when rate limit is exceeded."""

    def __init__(
        self,
        message: str,
        retry_after: int | None = None,
        response_data: dict | None = None,
    ) -> None:
        super().__init__(message, 429, response_data)
        self.retry_after = retry_after


class DomainIQTimeoutError(DomainIQError):
    """Exception raised when a request times out."""


class DomainIQConfigurationError(DomainIQError):
    """Exception raised when there's a configuration error."""
