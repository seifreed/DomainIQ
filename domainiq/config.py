"""Configuration management for DomainIQ library."""

import logging
import os
import signal
import time
from pathlib import Path
from collections.abc import Callable
from typing import Protocol, TypedDict

from .constants import (
    DEFAULT_CONNECTOR_LIMIT,
    DEFAULT_CONNECTOR_LIMIT_PER_HOST,
    DEFAULT_TIMEOUT,
    INTERACTIVE_PROMPT_TIMEOUT,
)
from .exceptions import DomainIQConfigurationError

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG_PATH = Path.home() / ".domainiq"

_DEFAULT_BASE_URL = os.getenv("DOMAINIQ_BASE_URL", "https://www.domainiq.com/api")
_DEFAULT_TIMEOUT = float(os.getenv("DOMAINIQ_TIMEOUT", str(DEFAULT_TIMEOUT)))
_DEFAULT_MAX_RETRIES = int(os.getenv("DOMAINIQ_MAX_RETRIES", "3"))
_DEFAULT_RETRY_DELAY = int(os.getenv("DOMAINIQ_RETRY_DELAY", "1"))
_DEFAULT_CONNECTOR_LIMIT = int(os.getenv("DOMAINIQ_CONNECTOR_LIMIT", str(DEFAULT_CONNECTOR_LIMIT)))
_DEFAULT_CONNECTOR_LIMIT_PER_HOST = int(os.getenv("DOMAINIQ_CONNECTOR_LIMIT_PER_HOST", str(DEFAULT_CONNECTOR_LIMIT_PER_HOST)))


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
        self._key = api_key or None

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
            raise TimeoutError("Prompt timed out")  # noqa: TRY301

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
            _PromptKeySource(self._config_file_path, is_interactive_fn=_PromptKeySource._is_interactive),
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


class Config:
    """Configuration class for DomainIQ client."""

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
        loader: "_ApiKeyLoader | None" = None,
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
            Path(config_file) if config_file else _DEFAULT_CONFIG_PATH
        )
        self._loader = loader if loader is not None else _ApiKeyLoader(self.config_file_path)
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
        # Run validation so any pending interactive key is persisted and the
        # new path/key combination is verified.
        self.validate()

    def validate(self) -> None:
        """Validate the configuration.

        Raises:
            DomainIQConfigurationError: If configuration is invalid.

        Side effects:
            If the API key was obtained via interactive prompt during construction,
            this method persists it to the config file (default ~/.domainiq, mode
            0o600) by calling loader.flush_pending(). No file is written if the key
            came from an environment variable or was passed directly.
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

        # Persist any interactively entered key now that validation passed
        self._loader.flush_pending()

    def __repr__(self) -> str:
        """String representation (without exposing API key)."""
        masked = "*" * 8 if self.api_key else "None"
        return (
            f"Config(base_url='{self.base_url}', "
            f"timeout={self.timeout}, "
            f"max_retries={self.max_retries}, "
            f"retry_delay={self.retry_delay}, "
            f"api_key={masked})"
        )
