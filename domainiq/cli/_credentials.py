"""Interactive credential helpers used only by the CLI."""

from __future__ import annotations

import os
import signal
import time
from pathlib import Path

from ..constants import INTERACTIVE_PROMPT_TIMEOUT
from ..exceptions import DomainIQConfigurationError


def _default_config_path(config_file: str | None) -> Path:
    return Path(config_file) if config_file else Path.home() / ".domainiq"


def _is_interactive() -> bool:
    """Return True when both stdin and stdout are attached to a TTY."""
    try:
        return os.isatty(0) and os.isatty(1)
    except (AttributeError, OSError):
        return False


def _prompt_with_timeout(prompt: str, timeout: int) -> str:
    """Read a line from stdin, using SIGALRM on POSIX when available."""
    if not hasattr(signal, "SIGALRM"):
        return input(prompt).strip()

    def _alarm_handler(*_args: object) -> None:
        raise TimeoutError("Prompt timed out")

    old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
    old_alarm = signal.alarm(timeout)
    start = time.monotonic()
    try:
        return input(prompt).strip()
    finally:
        signal.alarm(0)
        if old_handler is not None:
            signal.signal(signal.SIGALRM, old_handler)
        if old_alarm > 0:
            elapsed = int(time.monotonic() - start)
            signal.alarm(max(0, old_alarm - elapsed))


def _save_api_key(config_path: Path, api_key: str) -> None:
    config_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        str(config_path),
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    with os.fdopen(fd, "w") as file_obj:
        file_obj.write(api_key)


def prompt_for_api_key(config_file: str | None) -> str:
    """Prompt for an API key and persist it to the CLI config file."""
    if not _is_interactive() or os.getenv("DOMAINIQ_NO_PROMPT"):
        msg = (
            "No API key found. Please provide via:\n"
            "1. --api-key\n"
            "2. DOMAINIQ_API_KEY environment variable\n"
            "3. ~/.domainiq config file"
        )
        raise DomainIQConfigurationError(msg)

    try:
        api_key = _prompt_with_timeout(
            "Enter your DomainIQ API key: ",
            INTERACTIVE_PROMPT_TIMEOUT,
        )
    except (EOFError, KeyboardInterrupt, TimeoutError) as exc:
        msg = "Interactive API key entry was cancelled"
        raise DomainIQConfigurationError(msg) from exc

    api_key = api_key.strip()
    if not api_key:
        msg = "API key is required"
        raise DomainIQConfigurationError(msg)

    _save_api_key(_default_config_path(config_file), api_key)
    return api_key
