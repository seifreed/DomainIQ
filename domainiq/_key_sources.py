"""Passive API-key discovery sources for DomainIQ configuration.

The SDK resolves keys only from explicit, non-interactive sources:
- explicit parameter
- DOMAINIQ_API_KEY environment variable
- config file on disk
"""

import logging
import os
from pathlib import Path
from typing import Protocol

from .exceptions import DomainIQConfigurationError

logger = logging.getLogger(__name__)


class KeySource(Protocol):
    """Single-responsibility interface for reading an API key from one source."""

    def get_key(self) -> str | None:
        """Return the key, or None if this source has no key available."""
        ...


class _ParamKeySource:
    """Return an explicitly provided API key parameter."""

    def __init__(self, api_key: str | None) -> None:
        self._key = api_key

    def get_key(self) -> str | None:
        if self._key:
            logger.debug("Using API key from parameter")
        return self._key


class _EnvKeySource:
    """Read the API key from the DOMAINIQ_API_KEY environment variable."""

    def get_key(self) -> str | None:
        key = os.getenv("DOMAINIQ_API_KEY")
        if key:
            logger.debug("Using API key from DOMAINIQ_API_KEY environment variable")
        return key or None


class _FileKeySource:
    """Read the API key from a config file on disk."""

    def __init__(self, config_file_path: Path) -> None:
        self._path = config_file_path

    def get_key(self) -> str | None:
        if not self._path.exists():
            return None
        try:
            key = self._path.read_text().strip()
        except OSError as exc:
            logger.warning("Could not read config file %s: %s", self._path, exc)
            return None
        if key:
            logger.debug("Using API key from config file: %s", self._path)
            return key
        return None


class _ApiKeyLoader:
    """Chain-of-responsibility coordinator for passive API-key discovery."""

    def __init__(
        self,
        config_file_path: Path,
        sources: list[KeySource] | None = None,
    ) -> None:
        self._config_file_path = config_file_path
        self._sources = sources

    def load(self, api_key: str | None) -> str:
        """Run the discovery chain; return the resolved key or raise."""
        chain: list[KeySource]
        if self._sources is not None:
            chain = self._sources
        else:
            chain = [
                _ParamKeySource(api_key),
                _EnvKeySource(),
                _FileKeySource(self._config_file_path),
            ]
        for source in chain:
            key = source.get_key()
            if key:
                return key
        msg = (
            "No API key found. Please provide via:\n"
            "1. api_key parameter when creating client\n"
            "2. DOMAINIQ_API_KEY environment variable\n"
            "3. ~/.domainiq config file"
        )
        raise DomainIQConfigurationError(msg)
