"""Configuration management for DomainIQ library."""

import logging
import os
from pathlib import Path

from .exceptions import DomainIQConfigurationError

logger = logging.getLogger(__name__)


class Config:
    """Configuration class for DomainIQ client."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = "https://www.domainiq.com/api",
        timeout: int = 30,
        max_retries: int = 3,
        retry_delay: int = 1,
        config_file_path: str | None = None,
    ) -> None:
        """Initialize configuration.

        Args:
            api_key: DomainIQ API key. If None, will try to load from environment or config file.
            base_url: Base URL for DomainIQ API.
            timeout: Request timeout in seconds.
            max_retries: Maximum number of retries for failed requests.
            retry_delay: Delay between retries in seconds.
            config_file_path: Path to config file. Defaults to ~/.domainiq
        """
        self.base_url = base_url
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay

        # Set config file path
        if config_file_path:
            self.config_file_path = Path(config_file_path)
        else:
            self.config_file_path = Path.home() / ".domainiq"

        # Load API key
        self.api_key = self._load_api_key(api_key)

    def _load_api_key(self, api_key: str | None = None) -> str:
        """Load API key from various sources.

        Priority order:
        1. Provided api_key parameter
        2. DOMAINIQ_API_KEY environment variable
        3. Config file (~/.domainiq)
        4. Interactive prompt (only if no other sources available)

        Args:
            api_key: Explicitly provided API key

        Returns:
            The API key string

        Raises:
            DomainIQConfigurationError: If no API key can be found or loaded
        """
        # 1. Check provided parameter
        if api_key:
            logger.debug("Using API key from parameter")
            return api_key

        # 2. Check environment variable
        env_api_key = os.getenv("DOMAINIQ_API_KEY")
        if env_api_key:
            logger.debug("Using API key from DOMAINIQ_API_KEY environment variable")
            return env_api_key

        # 3. Check config file
        if self.config_file_path.exists():
            try:
                with open(self.config_file_path) as f:
                    file_api_key = f.read().strip()
                if file_api_key:
                    logger.debug(
                        "Using API key from config file: %s", self.config_file_path
                    )
                    return file_api_key
            except OSError as e:
                logger.warning(
                    "Could not read config file %s: %s", self.config_file_path, e
                )

        # 4. Interactive prompt (only in interactive environments)
        if self._is_interactive():
            try:
                interactive_key = input("Enter your DomainIQ API key: ").strip()
                if interactive_key:
                    # Save to config file for future use
                    self._save_api_key(interactive_key)
                    logger.debug("Using API key from interactive input")
                    return interactive_key
            except (KeyboardInterrupt, EOFError):
                logger.debug("Interactive input cancelled")

        # No API key found
        msg = (
            "No API key found. Please provide via:\n"
            "1. api_key parameter when creating client\n"
            "2. DOMAINIQ_API_KEY environment variable\n"
            "3. ~/.domainiq config file\n"
            "4. Interactive prompt (when available)"
        )
        raise DomainIQConfigurationError(msg)

    def _save_api_key(self, api_key: str) -> None:
        """Save API key to config file.

        Args:
            api_key: The API key to save
        """
        try:
            # Ensure parent directory exists
            self.config_file_path.parent.mkdir(parents=True, exist_ok=True)

            # Write API key to file with restricted permissions
            with open(self.config_file_path, "w") as f:
                f.write(api_key)

            # Set file permissions to be readable only by owner (Unix-like systems)
            try:
                os.chmod(self.config_file_path, 0o600)
            except (OSError, AttributeError):
                # chmod might not be available on Windows
                pass

            logger.debug("API key saved to config file: %s", self.config_file_path)

        except OSError as e:
            logger.warning(
                "Could not save API key to config file %s: %s", self.config_file_path, e
            )

    @staticmethod
    def _is_interactive() -> bool:
        """Check if running in an interactive environment.

        Returns:
            True if interactive, False otherwise
        """
        try:
            return os.isatty(0)  # Check if stdin is a terminal
        except (AttributeError, OSError):
            return False

    def validate(self) -> None:
        """Validate the configuration.

        Raises:
            DomainIQConfigurationError: If configuration is invalid
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
        return (
            f"Config(base_url='{self.base_url}', timeout={self.timeout}, "
            f"max_retries={self.max_retries}, retry_delay={self.retry_delay}, "
            f"api_key={'*' * min(8, len(self.api_key)) if self.api_key else None})"
        )
