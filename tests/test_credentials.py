"""Unit tests for CLI credential prompting helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import call, patch

import pytest

from domainiq.cli import _credentials as credentials
from domainiq.cli._credentials import (
    _default_config_path,
    _prompt_with_timeout,
    prompt_for_api_key,
)
from domainiq.exceptions import DomainIQConfigurationError

if TYPE_CHECKING:
    from pathlib import Path


class TestCredentialPrompting:
    def test_default_config_path_uses_home_when_missing(self, tmp_path: Path) -> None:
        with patch("pathlib.Path.home", return_value=tmp_path):
            assert _default_config_path(None) == tmp_path / ".domainiq"

    def test_default_config_path_uses_explicit_config_file(
        self, tmp_path: Path
    ) -> None:
        target = tmp_path / "domainiq.key"

        assert _default_config_path(str(target)) == target

    def test_no_prompt_env_var_disables_interactive_prompt(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("DOMAINIQ_NO_PROMPT", "1")

        with (
            patch("domainiq.cli._credentials._is_interactive", return_value=True),
            pytest.raises(DomainIQConfigurationError, match="No API key found"),
        ):
            prompt_for_api_key(None)

    @pytest.mark.parametrize("exc", [EOFError, KeyboardInterrupt, TimeoutError])
    def test_prompt_cancellation_is_configuration_error(
        self, exc: type[BaseException]
    ) -> None:
        with (
            patch("domainiq.cli._credentials._is_interactive", return_value=True),
            patch("domainiq.cli._credentials._prompt_with_timeout", side_effect=exc),
            pytest.raises(DomainIQConfigurationError, match="cancelled"),
        ):
            prompt_for_api_key(None)

    def test_empty_prompted_key_is_rejected(self) -> None:
        with (
            patch("domainiq.cli._credentials._is_interactive", return_value=True),
            patch("domainiq.cli._credentials._prompt_with_timeout", return_value=" "),
            pytest.raises(DomainIQConfigurationError, match="API key is required"),
        ):
            prompt_for_api_key(None)

    def test_prompted_key_uses_default_path(self, tmp_path: Path) -> None:
        with (
            patch("pathlib.Path.home", return_value=tmp_path),
            patch("domainiq.cli._credentials._is_interactive", return_value=True),
            patch(
                "domainiq.cli._credentials._prompt_with_timeout",
                return_value=" default_key ",
            ),
        ):
            api_key = prompt_for_api_key(None)

        target = tmp_path / ".domainiq"
        assert api_key == "default_key"
        assert target.read_text() == "default_key"
        assert target.stat().st_mode & 0o777 == 0o600


class TestPromptWithTimeout:
    def test_prompt_without_sigalrm_uses_plain_input(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delattr(credentials.signal, "SIGALRM", raising=False)

        with patch("builtins.input", return_value=" api-key "):
            assert _prompt_with_timeout("prompt: ", 5) == "api-key"

    def test_prompt_restores_handler_and_prior_alarm(self) -> None:
        old_handler = object()

        with (
            patch("builtins.input", return_value=" api-key "),
            patch(
                "domainiq.cli._credentials.signal.signal",
                side_effect=[old_handler, None],
            ) as mock_signal,
            patch(
                "domainiq.cli._credentials.signal.alarm",
                side_effect=[9, 0, 0],
            ) as mock_alarm,
            patch(
                "domainiq.cli._credentials.time.monotonic",
                side_effect=[100.0, 103.2],
            ),
        ):
            result = _prompt_with_timeout("prompt: ", 5)

        assert result == "api-key"
        assert mock_signal.call_args_list[1] == call(
            credentials.signal.SIGALRM, old_handler
        )
        assert mock_alarm.call_args_list == [call(5), call(0), call(6)]

    def test_prompt_restores_alarm_after_input_exception(self) -> None:
        old_handler = object()

        with (
            patch("builtins.input", side_effect=EOFError),
            patch(
                "domainiq.cli._credentials.signal.signal",
                side_effect=[old_handler, None],
            ) as mock_signal,
            patch(
                "domainiq.cli._credentials.signal.alarm",
                side_effect=[0, 0],
            ) as mock_alarm,
            pytest.raises(EOFError),
        ):
            _prompt_with_timeout("prompt: ", 5)

        assert mock_signal.call_args_list[1] == call(
            credentials.signal.SIGALRM, old_handler
        )
        assert mock_alarm.call_args_list == [call(5), call(0)]
