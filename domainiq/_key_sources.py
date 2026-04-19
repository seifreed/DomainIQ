"""API key discovery sources and loader for DomainIQ configuration.

Defines the KeySource protocol and four concrete implementations:
- _ParamKeySource: explicit parameter
- _EnvKeySource: DOMAINIQ_API_KEY environment variable
- _FileKeySource: config file on disk
- _PromptKeySource: interactive TTY prompt with SIGALRM timeout

_ApiKeyLoader coordinates a chain-of-responsibility over these sources.
"""

import logging
import os
import signal
import time
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from .constants import INTERACTIVE_PROMPT_TIMEOUT
from .exceptions import DomainIQConfigurationError

logger = logging.getLogger(__name__)


class KeySource(Protocol):
    """Single-responsibility interface for reading an API key from one source."""

    def get_key(self) -> str | None:
        """Return the key, or None if this source has no key available."""
        ...

    def flush(self) -> None:
        """Persist any side-effect (e.g. write to disk) after validation passes."""
        ...


class _ParamKeySource:
    """Returns an explicitly provided API key parameter."""

    def __init__(self, api_key: str | None) -> None:
        self._key = api_key

    def get_key(self) -> str | None:
        if self._key:
            logger.debug("Using API key from parameter")
        return self._key

    def flush(self) -> None:
        pass


class _EnvKeySource:
    """Reads API key from the DOMAINIQ_API_KEY environment variable."""

    def get_key(self) -> str | None:
        key = os.getenv("DOMAINIQ_API_KEY")
        if key:
            logger.debug("Using API key from DOMAINIQ_API_KEY environment variable")
        return key or None

    def flush(self) -> None:
        pass


class _FileKeySource:
    """Reads API key from a config file on disk."""

    def __init__(self, config_file_path: Path) -> None:
        self._path = config_file_path

    def get_key(self) -> str | None:
        if not self._path.exists():
            return None
        try:
            key = self._path.read_text().strip()
            if key:
                logger.debug("Using API key from config file: %s", self._path)
                return key
        except OSError as e:
            logger.warning("Could not read config file %s: %s", self._path, e)
        return None

    def flush(self) -> None:
        pass


class _PromptKeySource:
    """Interactive TTY prompt with SIGALRM timeout. Writes to disk on flush().

    Architecture note: I/O is intentionally separated from key discovery.
    get_key() reads from the terminal only (no file writes).
    flush() calls _save_api_key() to persist only after validation passes,
    ensuring the file is never written with an unvalidated key.
    """

    def __init__(
        self,
        config_file_path: Path,
        is_interactive_fn: Callable[[], bool] | None = None,
    ) -> None:
        self._path = config_file_path
        self._pending: str | None = None
        self._check_interactive = is_interactive_fn if is_interactive_fn is not None else self._is_interactive

    def get_key(self) -> str | None:
        if not self._check_interactive() or os.getenv("DOMAINIQ_NO_PROMPT"):
            return None
        try:
            key = self._prompt_with_timeout(
                "Enter your DomainIQ API key: ",
                INTERACTIVE_PROMPT_TIMEOUT,
            )
            if key:
                self._pending = key
                logger.debug("Using API key from interactive input")
                return key
        except (KeyboardInterrupt, EOFError, TimeoutError):
            logger.debug("Interactive input cancelled or timed out")
        return None

    def flush(self) -> None:
        if self._pending:
            self._save_api_key(self._pending)
            self._pending = None

    def _save_api_key(self, api_key: str) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            # Create file with restricted permissions atomically
            # to avoid TOCTOU race where file is briefly world-readable
            fd = os.open(
                str(self._path),
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o600,
            )
            with os.fdopen(fd, "w") as f:
                f.write(api_key)
            logger.debug("API key saved to config file: %s", self._path)
        except OSError as e:
            logger.warning(
                "Could not save API key to config file %s: %s",
                self._path,
                e,
            )

    @staticmethod
    def _prompt_with_timeout(prompt: str, timeout: int) -> str:
        """Read a line from stdin with an optional POSIX timeout.

        On Windows (no SIGALRM) falls back to plain blocking input().

        Raises:
            TimeoutError: User did not respond within timeout seconds (POSIX only).
            KeyboardInterrupt: Propagated as-is.
            EOFError: Propagated as-is.
        """
        if not hasattr(signal, "SIGALRM"):
            return input(prompt).strip()

        def _alarm_handler(*_args: object) -> None:
            # SIGALRM handler — outer finally always cancels the alarm
            raise TimeoutError("Prompt timed out")

        old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
        old_alarm = signal.alarm(timeout)
        _start = time.monotonic()
        try:
            return input(prompt).strip()
        finally:
            signal.alarm(0)
            if old_handler is not None:
                signal.signal(signal.SIGALRM, old_handler)
            if old_alarm > 0:
                elapsed = int(time.monotonic() - _start)
                remaining = max(0, old_alarm - elapsed)
                signal.alarm(remaining)

    @staticmethod
    def _is_interactive() -> bool:
        """Check if both stdin and stdout are TTYs."""
        try:
            return os.isatty(0) and os.isatty(1)
        except (AttributeError, OSError):
            return False


class _ApiKeyLoader:
    """Chain-of-responsibility coordinator for API key discovery and persistence.

    Tries each KeySource in order; the first one to return a non-None key wins.
    Pass ``sources`` to inject a custom chain (useful for testing).
    """

    def __init__(
        self,
        config_file_path: Path,
        sources: list[KeySource] | None = None,
    ) -> None:
        self._config_file_path = config_file_path
        self._sources = sources
        self._active_source: KeySource | None = None

    def load(self, api_key: str | None) -> str:
        """Run the discovery chain; return resolved key or raise."""
        chain: list[KeySource] = self._sources if self._sources is not None else [
            _ParamKeySource(api_key),
            _EnvKeySource(),
            _FileKeySource(self._config_file_path),
            _PromptKeySource(self._config_file_path),
        ]
        for source in chain:
            key = source.get_key()
            if key:
                self._active_source = source
                return key
        msg = (
            "No API key found. Please provide via:\n"
            "1. api_key parameter when creating client\n"
            "2. DOMAINIQ_API_KEY environment variable\n"
            "3. ~/.domainiq config file\n"
            "4. Interactive prompt (when available)"
        )
        raise DomainIQConfigurationError(msg)

    def flush_pending(self) -> None:
        """Persist any side-effect from the active source (e.g. save interactive key)."""
        if self._active_source is not None:
            self._active_source.flush()
