"""Interactive credential helpers used only by the CLI."""

from __future__ import annotations

import contextlib
import os
import signal
import time
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

from domainiq.constants import INTERACTIVE_PROMPT_TIMEOUT
from domainiq.exceptions import DomainIQConfigurationError

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

_NO_PROMPT_ENV = "DOMAINIQ_NO_PROMPT"


class _AlarmController(Protocol):
    """Timeout mechanism seam for the interactive prompt (real signal / test double)."""

    def supported(self) -> bool: ...
    def set_handler(self, on_timeout: Callable[[], None]) -> object: ...
    def restore_handler(self, previous: object) -> None: ...
    def set_alarm(self, seconds: int) -> int: ...


class _SignalAlarmController:
    """Default POSIX SIGALRM-based timeout controller."""

    def supported(self) -> bool:
        return hasattr(signal, "SIGALRM")

    def set_handler(self, on_timeout: Callable[[], None]) -> object:
        def _handler(*_args: object) -> None:
            on_timeout()

        return signal.signal(signal.SIGALRM, _handler)

    def restore_handler(self, previous: object) -> None:
        if previous is not None:
            handler = cast("int | Callable[[int, object], object] | None", previous)
            signal.signal(signal.SIGALRM, handler)

    def set_alarm(self, seconds: int) -> int:
        return signal.alarm(seconds)


def _default_config_path(config_file: str | None) -> Path:
    return Path(config_file) if config_file else Path.home() / ".domainiq"


def _is_interactive(isatty: Callable[[int], bool] = os.isatty) -> bool:
    """Return True when both stdin and stdout are attached to a TTY."""
    try:
        return isatty(0) and isatty(1)
    except AttributeError, OSError:
        return False


def _prompt_with_timeout(
    prompt: str,
    timeout: int,
    *,
    read_line: Callable[[str], str] = input,
    clock: Callable[[], float] = time.monotonic,
    alarm: _AlarmController | None = None,
) -> str:
    """Read a line from stdin, using SIGALRM on POSIX when available."""
    controller = alarm if alarm is not None else _SignalAlarmController()
    if not controller.supported():
        return read_line(prompt).strip()

    def _on_timeout() -> None:
        msg = "Prompt timed out"
        raise TimeoutError(msg)

    try:
        previous = controller.set_handler(_on_timeout)
    except ValueError:
        # signal.signal() raises ValueError when called from a non-main thread.
        return read_line(prompt).strip()
    old_alarm = controller.set_alarm(timeout)
    start = clock()
    try:
        return read_line(prompt).strip()
    finally:
        controller.set_alarm(0)
        controller.restore_handler(previous)
        if old_alarm > 0:
            elapsed = int(clock() - start)
            controller.set_alarm(max(0, old_alarm - elapsed))


def _save_api_key(config_path: Path, api_key: str) -> None:
    config_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        str(config_path),
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    try:
        with os.fdopen(fd, "w") as file_obj:
            file_obj.write(api_key)
    finally:
        with contextlib.suppress(OSError, FileNotFoundError):
            config_path.chmod(0o600)


def prompt_for_api_key(
    config_file: str | None,
    *,
    is_interactive: Callable[[], bool] = _is_interactive,
    prompt: Callable[[str, int], str] = _prompt_with_timeout,
    env: Mapping[str, str] | None = None,
) -> str:
    """Prompt for an API key and persist it to the CLI config file."""
    environ = env if env is not None else os.environ
    if not is_interactive() or environ.get(_NO_PROMPT_ENV):
        msg = (
            "No API key found. Please provide via:\n"
            "1. --api-key\n"
            "2. DOMAINIQ_API_KEY environment variable\n"
            "3. ~/.domainiq config file"
        )
        raise DomainIQConfigurationError(msg)

    try:
        api_key = prompt(
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
