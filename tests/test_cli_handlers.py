"""Tests for DomainIQ CLI handlers, serialization, credentials, and main."""

from __future__ import annotations

import argparse
import base64
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import domainiq.cli as cli_module
from domainiq.cli import main
from domainiq.cli._args import create_parser
from domainiq.cli._credentials import _is_interactive, prompt_for_api_key
from domainiq.cli._handlers import (
    handle_dns_lookup,
    handle_domain_search,
    handle_whois_lookup,
)
from domainiq.cli._serialization import print_result
from domainiq.cli._serialization import serialize_result as _serialize
from domainiq.cli._types import DnsArgs, DomainSearchArgs, WhoisArgs
from domainiq.constants import (
    EXIT_NO_COMMAND as _EXIT_NO_COMMAND,
)
from domainiq.constants import (
    EXIT_SUCCESS as _EXIT_SUCCESS,
)
from domainiq.exceptions import DomainIQConfigurationError, DomainIQError


def _mock_client() -> MagicMock:
    return MagicMock()


class TestSerialize:
    def test_datetime_to_iso(self) -> None:
        dt = datetime(2024, 1, 15, 12, 0, 0)  # noqa: DTZ001
        assert _serialize(dt) == "2024-01-15T12:00:00"

    def test_bytes_to_base64(self) -> None:
        data = b"hello"
        result = _serialize(data)
        assert result == base64.b64encode(b"hello").decode("ascii")

    def test_dict_recursion(self) -> None:
        dt = datetime(2024, 1, 1)  # noqa: DTZ001
        result = _serialize({"ts": dt, "val": 42})
        assert result == {"ts": "2024-01-01T00:00:00", "val": 42}

    def test_list_recursion(self) -> None:
        result = _serialize([1, b"x", "y"])
        assert result[0] == 1
        assert isinstance(result[1], str)
        assert result[2] == "y"

    def test_dataclass_to_dict(self) -> None:
        @dataclass
        class Simple:
            name: str
            value: int

        result = _serialize(Simple(name="test", value=99))
        assert isinstance(result, dict)
        assert result["name"] == "test"
        assert result["value"] == 99

    def test_primitive_passthrough(self) -> None:
        assert _serialize(42) == 42
        assert _serialize("hello") == "hello"
        assert _serialize(None) is None


class TestPrintResult:
    def test_prints_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        print_result({"key": "value"})
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["key"] == "value"

    def test_prints_no_data_for_none(self, capsys: pytest.CaptureFixture[str]) -> None:
        print_result(None)
        captured = capsys.readouterr()
        assert "No data returned" in captured.out

    def test_uses_2_space_indent(self, capsys: pytest.CaptureFixture[str]) -> None:
        print_result({"a": 1})
        captured = capsys.readouterr()
        assert '  "a": 1' in captured.out


class TestHandleWhoisLookup:
    def test_domain_target_calls_whois_with_domain(self) -> None:
        client = _mock_client()
        client.whois_lookup.return_value = {}
        args = WhoisArgs(query="example.com", full=False, current_only=False)
        handle_whois_lookup(client, args)
        client.whois_lookup.assert_called_once_with(
            domain="example.com", ip=None, full=False, current_only=False
        )

    def test_ip_target_calls_whois_with_ip(self) -> None:
        client = _mock_client()
        client.whois_lookup.return_value = {}
        args = WhoisArgs(query="8.8.8.8", full=False, current_only=False)
        handle_whois_lookup(client, args)
        client.whois_lookup.assert_called_once_with(
            domain=None, ip="8.8.8.8", full=False, current_only=False
        )

    def test_full_flag_forwarded(self) -> None:
        client = _mock_client()
        client.whois_lookup.return_value = {}
        args = WhoisArgs(query="example.com", full=True, current_only=False)
        handle_whois_lookup(client, args)
        call_kwargs = client.whois_lookup.call_args.kwargs
        assert call_kwargs["full"] is True


class TestHandleDnsLookup:
    def test_no_types_passes_none(self) -> None:
        client = _mock_client()
        client.dns_lookup.return_value = []
        args = DnsArgs(query="example.com", types=None)
        handle_dns_lookup(client, args)
        client.dns_lookup.assert_called_once_with("example.com", record_types=None)

    def test_types_split_by_comma(self) -> None:
        client = _mock_client()
        client.dns_lookup.return_value = []
        args = DnsArgs(query="example.com", types=["A", "MX", "TXT"])
        handle_dns_lookup(client, args)
        client.dns_lookup.assert_called_once_with(
            "example.com", record_types=["A", "MX", "TXT"]
        )


class TestHandleDomainSearch:
    def _search_args(self, **kwargs: Any) -> DomainSearchArgs:
        defaults: dict[str, Any] = {
            "keywords": ["kw"],
            "conditions": None,
            "match": "any",
            "count_only": False,
            "exclude_dashed": False,
            "exclude_numbers": False,
            "exclude_idn": False,
            "min_length": None,
            "max_length": None,
            "min_create_date": None,
            "max_create_date": None,
            "search_limit": None,
        }
        defaults.update(kwargs)
        return DomainSearchArgs(**defaults)

    def test_basic_search_no_filters(self) -> None:
        client = _mock_client()
        client.domain_search.return_value = {}
        args = self._search_args(keywords=["kw"])
        handle_domain_search(client, args)
        client.domain_search.assert_called_once()
        call_kwargs = client.domain_search.call_args.kwargs
        assert call_kwargs["keywords"] == ["kw"]
        assert call_kwargs["filters"] is None

    def test_exclude_dashed_sets_filter(self) -> None:
        client = _mock_client()
        client.domain_search.return_value = {}
        args = self._search_args(exclude_dashed=True)
        handle_domain_search(client, args)
        call_kwargs = client.domain_search.call_args.kwargs
        assert call_kwargs["filters"]["exclude_dashed"] is True

    def test_count_only_sets_filter(self) -> None:
        client = _mock_client()
        client.domain_search.return_value = {}
        args = self._search_args(count_only=True)
        handle_domain_search(client, args)
        call_kwargs = client.domain_search.call_args.kwargs
        assert call_kwargs["filters"]["count_only"] == 1

    def test_min_max_length(self) -> None:
        client = _mock_client()
        client.domain_search.return_value = {}
        args = self._search_args(min_length=5, max_length=15)
        handle_domain_search(client, args)
        call_kwargs = client.domain_search.call_args.kwargs
        assert call_kwargs["filters"]["min_length"] == 5
        assert call_kwargs["filters"]["max_length"] == 15


class TestCliCredentials:
    def test_is_interactive_requires_both_stdin_and_stdout(self) -> None:
        with patch("os.isatty") as mock_isatty:
            mock_isatty.side_effect = lambda fd: fd == 0
            assert _is_interactive() is False

        with patch("os.isatty") as mock_isatty:
            mock_isatty.return_value = True
            assert _is_interactive() is True

    def test_prompt_for_api_key_persists_value(self, tmp_path) -> None:
        target = tmp_path / "domainiq.key"

        with (
            patch("domainiq.cli._credentials._is_interactive", return_value=True),
            patch(
                "domainiq.cli._credentials._prompt_with_timeout",
                return_value="interactive_key_xyz",
            ),
        ):
            api_key = prompt_for_api_key(str(target))

        assert api_key == "interactive_key_xyz"
        assert target.exists()
        assert target.read_text() == "interactive_key_xyz"

    def test_prompt_for_api_key_raises_when_non_interactive(self) -> None:
        with (
            patch("domainiq.cli._credentials._is_interactive", return_value=False),
            pytest.raises(DomainIQError, match="No API key found"),
        ):
            prompt_for_api_key(None)


class TestMain:
    def test_build_config_uses_direct_cli_args(self, tmp_path) -> None:
        config_file = tmp_path / "domainiq.key"
        args = argparse.Namespace(
            api_key="direct-key",
            timeout=12,
            config_file=str(config_file),
        )
        config = cli_module._build_config(args)

        assert config.api_key == "direct-key"
        assert config.timeout == 12
        assert config.config_file_path == config_file

    def test_build_config_prompts_after_missing_api_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        args = argparse.Namespace(api_key=None, timeout=9, config_file="missing.key")
        config_factory = MagicMock(
            side_effect=[
                DomainIQConfigurationError("No API key found"),
                MagicMock(api_key="prompted-key"),
            ]
        )
        monkeypatch.setattr(cli_module, "Config", config_factory)
        monkeypatch.setattr(cli_module, "prompt_for_api_key", lambda _path: "prompted")

        config = cli_module._build_config(args)

        assert config.api_key == "prompted-key"
        assert config_factory.call_args_list[1].kwargs == {
            "api_key": "prompted",
            "timeout": 9,
            "config_file": "missing.key",
        }

    def test_build_config_reraises_non_key_configuration_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        args = argparse.Namespace(api_key=None, timeout=9, config_file="missing.key")
        config_factory = MagicMock(
            side_effect=DomainIQConfigurationError(
                "Invalid DOMAINIQ_MAX_RETRIES: expected an integer"
            )
        )
        prompt = MagicMock()
        monkeypatch.setattr(cli_module, "Config", config_factory)
        monkeypatch.setattr(cli_module, "prompt_for_api_key", prompt)

        with pytest.raises(DomainIQConfigurationError, match="DOMAINIQ_MAX_RETRIES"):
            cli_module._build_config(args)

        prompt.assert_not_called()

    @pytest.mark.parametrize(
        ("exc", "debug", "expected_code", "expected_stderr"),
        [
            (DomainIQError("api failed"), False, 1, "Error: api failed"),
            (KeyboardInterrupt(), False, 130, ""),
            (ValueError("bad flag"), False, 1, "Invalid argument: bad flag"),
            (OSError("disk failed"), False, 1, "OSError: disk failed"),
        ],
    )
    def test_handle_cli_error_known_errors(
        self,
        exc: BaseException,
        debug: bool,
        expected_code: int,
        expected_stderr: str,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        assert cli_module._handle_cli_error(exc, debug) == expected_code
        assert expected_stderr in capsys.readouterr().err

    def test_handle_cli_error_prints_traceback_when_debug(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        print_exc = MagicMock()
        monkeypatch.setattr(cli_module.traceback, "print_exc", print_exc)

        assert cli_module._handle_cli_error(OSError("disk failed"), True) == 1
        print_exc.assert_called_once_with()

    def test_handle_cli_error_reraises_unknown_errors(self) -> None:
        with pytest.raises(RuntimeError, match="boom"):
            cli_module._handle_cli_error(RuntimeError("boom"), False)

    def test_main_no_command_exits_no_command(self) -> None:
        with (
            patch("sys.argv", ["domainiq", "--api-key", "key"]),
            patch("domainiq.cli._args.create_parser") as mock_create,
            patch("domainiq.client.DomainIQClient.__enter__") as mock_enter,
            patch("domainiq.client.DomainIQClient.__exit__", return_value=False),
        ):
            parser = create_parser()
            mock_create.return_value = parser
            mock_enter.return_value = _mock_client()
            code = main()
        assert code == _EXIT_NO_COMMAND

    def test_main_exits_1_on_domainiq_error(self) -> None:
        with (
            patch(
                "sys.argv",
                ["domainiq", "--api-key", "key", "--whois-lookup", "example.com"],
            ),
            patch("domainiq.client.DomainIQClient") as mock_cls,
        ):
            instance = mock_cls.return_value.__enter__.return_value
            instance.whois_lookup.side_effect = DomainIQError("test error")
            code = main()
        assert code == 1

    def test_main_keyboard_interrupt_exits_130(self) -> None:
        with (
            patch("sys.argv", ["domainiq", "--api-key", "key"]),
            patch("domainiq.client.DomainIQClient") as mock_cls,
        ):
            mock_cls.return_value.__enter__.side_effect = KeyboardInterrupt
            code = main()
        assert code == 130

    def test_main_prompts_when_sdk_config_has_no_key(self) -> None:
        with (
            patch("sys.argv", ["domainiq", "--whois-lookup", "example.com"]),
            patch(
                "domainiq.cli.Config",
                side_effect=[
                    DomainIQConfigurationError("No API key found"),
                    MagicMock(api_key="prompted"),
                ],
            ),
            patch("domainiq.cli.prompt_for_api_key", return_value="prompted"),
            patch("domainiq.client.DomainIQClient") as mock_cls,
        ):
            instance = mock_cls.return_value.__enter__.return_value
            instance.whois_lookup.return_value = {}
            code = main()

        assert code == _EXIT_SUCCESS
