"""Passive configuration object for the DomainIQ SDK."""

import logging
import os
from pathlib import Path
from typing import TypedDict

from ._key_sources import _ApiKeyLoader
from .constants import (
    API_KEY_MASK_LENGTH,
    DEFAULT_CONNECTOR_LIMIT,
    DEFAULT_CONNECTOR_LIMIT_PER_HOST,
    DEFAULT_MAX_RETRIES,
    DEFAULT_RETRY_DELAY,
    DEFAULT_TIMEOUT,
)
from .exceptions import DomainIQConfigurationError

logger = logging.getLogger(__name__)

_DEFAULT_BASE_URL = os.getenv(
    "DOMAINIQ_BASE_URL", "https://www.domainiq.com/api"
)
_DEFAULT_TIMEOUT = float(os.getenv("DOMAINIQ_TIMEOUT", str(DEFAULT_TIMEOUT)))
_DEFAULT_MAX_RETRIES = int(
    os.getenv("DOMAINIQ_MAX_RETRIES", str(DEFAULT_MAX_RETRIES))
)
_DEFAULT_RETRY_DELAY = int(
    os.getenv("DOMAINIQ_RETRY_DELAY", str(DEFAULT_RETRY_DELAY))
)
_DEFAULT_CONNECTOR_LIMIT = int(
    os.getenv("DOMAINIQ_CONNECTOR_LIMIT", str(DEFAULT_CONNECTOR_LIMIT))
)
_DEFAULT_CONNECTOR_LIMIT_PER_HOST = int(
    os.getenv(
        "DOMAINIQ_CONNECTOR_LIMIT_PER_HOST",
        str(DEFAULT_CONNECTOR_LIMIT_PER_HOST),
    )
)


class ConfigKwargs(TypedDict, total=False):
    """Keyword arguments accepted by Config."""

    api_key: str | None
    base_url: str
    timeout: float
    max_retries: int
    retry_delay: int
    config_file: str | Path | None
    connector_limit: int
    connector_limit_per_host: int


class Config:
    """Configuration object for DomainIQ clients."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = _DEFAULT_BASE_URL,
        timeout: float = _DEFAULT_TIMEOUT,
        max_retries: int = _DEFAULT_MAX_RETRIES,
        retry_delay: int = _DEFAULT_RETRY_DELAY,
        config_file: str | Path | None = None,
        connector_limit: int = _DEFAULT_CONNECTOR_LIMIT,
        connector_limit_per_host: int = _DEFAULT_CONNECTOR_LIMIT_PER_HOST,
        loader: _ApiKeyLoader | None = None,
    ) -> None:
        """Initialize configuration.

        Args:
            api_key: DomainIQ API key. If None, will try to load
                from environment or config file.
            base_url: Base URL for DomainIQ API.
            timeout: Request timeout in seconds (int or float).
            max_retries: Maximum number of retries for failed requests.
            retry_delay: Delay between retries in seconds.
            config_file: Path to config file containing API key.
                If None, defaults to ~/.domainiq.
            loader: Optional pre-built key loader (inject for testing or custom
                key sources). If None, a default _ApiKeyLoader is created.
        """
        self.base_url = base_url
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.connector_limit = connector_limit
        self.connector_limit_per_host = connector_limit_per_host
        self.config_file_path: Path = (
            Path(config_file) if config_file else Path.home() / ".domainiq"
        )
        self._loader = (
            loader if loader is not None else _ApiKeyLoader(self.config_file_path)
        )
        self.api_key = self._loader.load(api_key)

    def set_config_path(self, path: str | Path, api_key: str | None = None) -> None:
        """Set a custom config file path and reload the API key.

        Args:
            path: Path to the config file
            api_key: Explicitly provided API key. If provided, takes priority
                over the config file.
        """
        self.config_file_path = Path(path)
        self._loader = _ApiKeyLoader(self.config_file_path)
        self.api_key = self._loader.load(api_key)
        self.validate()

    def validate(self) -> None:
        """Validate the configuration.

        Raises:
            DomainIQConfigurationError: If configuration is invalid.
        """
        if not self.api_key:
            msg = "API key is required"
            raise DomainIQConfigurationError(msg)

        if not self.base_url:
            msg = "Base URL is required"
            raise DomainIQConfigurationError(msg)

        if self.timeout <= 0:
            msg = "Timeout must be positive"
            raise DomainIQConfigurationError(msg)

        if self.max_retries < 0:
            msg = "Max retries cannot be negative"
            raise DomainIQConfigurationError(msg)

        if self.retry_delay < 0:
            msg = "Retry delay cannot be negative"
            raise DomainIQConfigurationError(msg)

    def __repr__(self) -> str:
        """String representation (without exposing API key)."""
        masked = "*" * API_KEY_MASK_LENGTH if self.api_key else "None"
        return (
            f"Config(base_url='{self.base_url}', "
            f"timeout={self.timeout}, "
            f"max_retries={self.max_retries}, "
            f"retry_delay={self.retry_delay}, "
            f"api_key={masked})"
        )
