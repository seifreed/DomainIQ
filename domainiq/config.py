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

_DEFAULT_BASE_URL = os.getenv("DOMAINIQ_BASE_URL", "https://www.domainiq.com/api")


def _env_float(name: str, default: float) -> float:
    """Read a float environment setting, raising a config error if invalid."""
    raw_value = os.getenv(name)
    if raw_value is None:
        return default

    try:
        return float(raw_value)
    except ValueError as exc:
        msg = f"Invalid {name}: expected a number"
        raise DomainIQConfigurationError(msg) from exc


def _env_int(name: str, default: int) -> int:
    """Read an integer environment setting, raising a config error if invalid."""
    raw_value = os.getenv(name)
    if raw_value is None:
        return default

    try:
        return int(raw_value)
    except ValueError as exc:
        msg = f"Invalid {name}: expected an integer"
        raise DomainIQConfigurationError(msg) from exc


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

    def __init__(  # noqa: PLR0913 - config preserves explicit keyword options.
        self,
        api_key: str | None = None,
        base_url: str = _DEFAULT_BASE_URL,
        timeout: float | None = None,
        max_retries: int | None = None,
        retry_delay: int | None = None,
        config_file: str | Path | None = None,
        connector_limit: int | None = None,
        connector_limit_per_host: int | None = None,
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
            connector_limit: Maximum async connector pool size.
            connector_limit_per_host: Maximum async connections per host.
            loader: Optional pre-built key loader (inject for testing or custom
                key sources). If None, a default _ApiKeyLoader is created.
        """
        self.base_url = base_url
        self.timeout = (
            _env_float("DOMAINIQ_TIMEOUT", DEFAULT_TIMEOUT)
            if timeout is None
            else timeout
        )
        self.max_retries = (
            _env_int("DOMAINIQ_MAX_RETRIES", DEFAULT_MAX_RETRIES)
            if max_retries is None
            else max_retries
        )
        self.retry_delay = (
            _env_int("DOMAINIQ_RETRY_DELAY", DEFAULT_RETRY_DELAY)
            if retry_delay is None
            else retry_delay
        )
        self.connector_limit = (
            _env_int("DOMAINIQ_CONNECTOR_LIMIT", DEFAULT_CONNECTOR_LIMIT)
            if connector_limit is None
            else connector_limit
        )
        self.connector_limit_per_host = (
            _env_int(
                "DOMAINIQ_CONNECTOR_LIMIT_PER_HOST",
                DEFAULT_CONNECTOR_LIMIT_PER_HOST,
            )
            if connector_limit_per_host is None
            else connector_limit_per_host
        )
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

        if self.connector_limit <= 0:
            msg = "Connector limit must be positive"
            raise DomainIQConfigurationError(msg)

        if self.connector_limit_per_host <= 0:
            msg = "Connector limit per host must be positive"
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
