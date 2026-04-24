"""Unit tests for CLI credential prompting helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from domainiq.cli._credentials import _default_config_path, prompt_for_api_key
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
