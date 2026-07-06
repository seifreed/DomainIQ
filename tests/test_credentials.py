"""Unit tests for CLI credential prompting helpers."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from domainiq.cli._credentials import (
    _default_config_path,
    _prompt_with_timeout,
    prompt_for_api_key,
)
from domainiq.exceptions import DomainIQConfigurationError

if TYPE_CHECKING:
    from collections.abc import Callable

# POSIX mode bits (0o600) are not enforced on Windows, which secures files via
# ACLs instead; the permission assertions below only hold on POSIX platforms.
_POSIX_PERMISSIONS = sys.platform != "win32"

_PREVIOUS_HANDLER = object()


class _FakeClock:
    """Deterministic monotonic clock returning queued timestamps."""

    def __init__(self, times: list[float]) -> None:
        self._times = list(times)

    def __call__(self) -> float:
        return self._times.pop(0)


class _RecordingAlarm:
    """Real in-memory _AlarmController double recording every alarm setting."""

    def __init__(
        self,
        *,
        supported: bool = True,
        set_handler_error: BaseException | None = None,
        prior_alarm: int = 0,
    ) -> None:
        self._supported = supported
        self._set_handler_error = set_handler_error
        self._prior_alarm = prior_alarm
        self.handler: Callable[[], None] | None = None
        self.restored: object = "unset"
        self.alarm_calls: list[int] = []

    def supported(self) -> bool:
        return self._supported

    def set_handler(self, on_timeout: Callable[[], None]) -> object:
        if self._set_handler_error is not None:
            raise self._set_handler_error
        self.handler = on_timeout
        return _PREVIOUS_HANDLER

    def restore_handler(self, previous: object) -> None:
        self.restored = previous

    def set_alarm(self, seconds: int) -> int:
        self.alarm_calls.append(seconds)
        return self._prior_alarm if len(self.alarm_calls) == 1 else 0


def _returns(value: str) -> Callable[[str], str]:
    def _read(_prompt: str) -> str:
        return value

    return _read


def _raises_read(exc: type[BaseException]) -> Callable[[str], str]:
    def _read(_prompt: str) -> str:
        raise exc

    return _read


def _prompt_returning(value: str) -> Callable[[str, int], str]:
    def _prompt(_prompt: str, _timeout: int) -> str:
        return value

    return _prompt


def _prompt_raising(exc: type[BaseException]) -> Callable[[str, int], str]:
    def _prompt(_prompt: str, _timeout: int) -> str:
        raise exc

    return _prompt


class TestCredentialPrompting:
    def test_default_config_path_uses_home_when_missing(self) -> None:
        assert _default_config_path(None) == Path.home() / ".domainiq"

    def test_default_config_path_uses_explicit_config_file(
        self, tmp_path: Path
    ) -> None:
        target = tmp_path / "domainiq.key"
        assert _default_config_path(str(target)) == target

    def test_no_prompt_env_var_disables_interactive_prompt(self) -> None:
        with pytest.raises(DomainIQConfigurationError, match="No API key found"):
            prompt_for_api_key(
                None,
                is_interactive=lambda: True,
                env={"DOMAINIQ_NO_PROMPT": "1"},
            )

    @pytest.mark.parametrize("exc", [EOFError, KeyboardInterrupt, TimeoutError])
    def test_prompt_cancellation_is_configuration_error(
        self, exc: type[BaseException]
    ) -> None:
        with pytest.raises(DomainIQConfigurationError, match="cancelled"):
            prompt_for_api_key(
                None,
                is_interactive=lambda: True,
                prompt=_prompt_raising(exc),
                env={},
            )

    def test_empty_prompted_key_is_rejected(self) -> None:
        with pytest.raises(DomainIQConfigurationError, match="API key is required"):
            prompt_for_api_key(
                None,
                is_interactive=lambda: True,
                prompt=_prompt_returning(" "),
                env={},
            )

    def test_prompted_key_saved_to_config_file(self, tmp_path: Path) -> None:
        target = tmp_path / ".domainiq"
        api_key = prompt_for_api_key(
            str(target),
            is_interactive=lambda: True,
            prompt=_prompt_returning(" default_key "),
            env={},
        )
        assert api_key == "default_key"
        assert target.read_text() == "default_key"
        if _POSIX_PERMISSIONS:
            assert target.stat().st_mode & 0o777 == 0o600

    def test_prompted_key_enforces_permissions_on_existing_file_regression(
        self, tmp_path: Path
    ) -> None:
        """Regression: existing files with broad permissions were not restricted."""
        target = tmp_path / ".domainiq"
        target.write_text("old_key")
        target.chmod(0o644)

        prompt_for_api_key(
            str(target),
            is_interactive=lambda: True,
            prompt=_prompt_returning("new_key"),
            env={},
        )

        assert target.read_text() == "new_key"
        if _POSIX_PERMISSIONS:
            assert target.stat().st_mode & 0o777 == 0o600


class TestPromptWithTimeout:
    def test_prompt_without_sigalrm_uses_plain_input(self) -> None:
        alarm = _RecordingAlarm(supported=False)
        result = _prompt_with_timeout(
            "prompt: ", 5, read_line=_returns(" api-key "), alarm=alarm
        )
        assert result == "api-key"
        assert alarm.alarm_calls == []

    def test_prompt_restores_handler_and_prior_alarm(self) -> None:
        alarm = _RecordingAlarm(prior_alarm=9)
        result = _prompt_with_timeout(
            "prompt: ",
            5,
            read_line=_returns(" api-key "),
            clock=_FakeClock([100.0, 103.2]),
            alarm=alarm,
        )
        assert result == "api-key"
        assert alarm.restored is _PREVIOUS_HANDLER
        assert alarm.alarm_calls == [5, 0, 6]

    def test_prompt_restores_alarm_after_input_exception(self) -> None:
        alarm = _RecordingAlarm(prior_alarm=0)
        with pytest.raises(EOFError):
            _prompt_with_timeout(
                "prompt: ",
                5,
                read_line=_raises_read(EOFError),
                clock=_FakeClock([100.0]),
                alarm=alarm,
            )
        assert alarm.restored is _PREVIOUS_HANDLER
        assert alarm.alarm_calls == [5, 0]

    def test_prompt_fallback_when_signal_fails_from_thread(self) -> None:
        alarm = _RecordingAlarm(
            set_handler_error=ValueError("signal only works in main thread")
        )
        result = _prompt_with_timeout(
            "prompt: ", 5, read_line=_returns(" api-key "), alarm=alarm
        )
        assert result == "api-key"
        assert alarm.alarm_calls == []
