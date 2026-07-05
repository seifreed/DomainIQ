"""Tests for DomainIQ CLI handlers, serialization, credentials, and main."""

from __future__ import annotations

import argparse
import base64
import json
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

import pytest

import domainiq.cli as cli_module
from domainiq.cli import main
from domainiq.cli._credentials import _is_interactive, prompt_for_api_key
from domainiq.cli._handlers import (
    build_snapshot_options,
    handle_dns_lookup,
    handle_domain_search,
    handle_whois_lookup,
)
from domainiq.cli._serialization import print_result
from domainiq.cli._serialization import serialize_result as _serialize
from domainiq.cli._types import DnsArgs, DomainSearchArgs, WhoisArgs
from domainiq.config import Config
from domainiq.constants import (
    EXIT_NO_COMMAND as _EXIT_NO_COMMAND,
)
from domainiq.constants import (
    EXIT_SUCCESS as _EXIT_SUCCESS,
)
from domainiq.exceptions import (
    DomainIQConfigurationError,
    DomainIQError,
    DomainIQValidationError,
)
from tests.conftest import StubClient

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


def _mock_client() -> StubClient:
    return StubClient()


class _RecordingCallable:
    """Callable double that records calls and yields queued results/errors.

    A hand-written stand-in for the CLI's ``Config`` factory, prompt, and
    ``traceback.print_exc`` seams: each ``__call__`` records its ``(args,
    kwargs)`` and returns the next queued result, raising it if it is an
    exception. With no queued results it returns ``None``.
    """

    def __init__(self, results: list[object] | None = None) -> None:
        self.calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        self._results: list[object] = list(results) if results is not None else []

    def __call__(self, *args: object, **kwargs: object) -> object:
        self.calls.append((args, kwargs))
        if not self._results:
            return None
        outcome = self._results.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class _RaisingContext:
    """Context manager whose ``__enter__`` raises, for main() failure paths."""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def __enter__(self) -> StubClient:
        raise self._exc

    def __exit__(self, *_exc: object) -> None:
        return None


def _client_factory(client: StubClient) -> Callable[[object], StubClient]:
    def _factory(_config: object) -> StubClient:
        return client

    return _factory


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

    def test_domainiq_error_from_depth_exceeded_is_caught_regression(self) -> None:
        """Regression: DomainIQError from serialize_result escaped print_result."""
        deeply_nested: dict[str, Any] = {}
        current = deeply_nested
        for _ in range(200):
            current["child"] = {}
            current = current["child"]
        with pytest.raises(DomainIQError):
            print_result(deeply_nested)


class TestBuildSnapshotOptions:
    def test_accepts_valid_dimensions(self) -> None:
        args = argparse.Namespace(
            snapshot_full=True,
            no_cache=False,
            raw=False,
            width=1024,
            height=768,
        )
        options = build_snapshot_options(args)
        assert options.width == 1024
        assert options.height == 768
        assert options.full is True

    def test_uses_defaults_when_dimensions_none(self) -> None:
        args = argparse.Namespace(
            snapshot_full=False,
            no_cache=False,
            raw=False,
            width=None,
            height=None,
        )
        options = build_snapshot_options(args)
        assert options.width == 250
        assert options.height == 125

    def test_rejects_zero_width(self) -> None:
        args = argparse.Namespace(
            snapshot_full=False,
            no_cache=False,
            raw=False,
            width=0,
            height=None,
        )
        with pytest.raises(DomainIQValidationError) as exc_info:
            build_snapshot_options(args)
        assert exc_info.value.param_name == "width"

    def test_rejects_negative_height(self) -> None:
        args = argparse.Namespace(
            snapshot_full=False,
            no_cache=False,
            raw=False,
            width=None,
            height=-1,
        )
        with pytest.raises(DomainIQValidationError) as exc_info:
            build_snapshot_options(args)
        assert exc_info.value.param_name == "height"


class TestHandleWhoisLookup:
    def test_domain_target_calls_whois_with_domain(self) -> None:
        client = _mock_client()
        args = WhoisArgs(query="example.com", full=False, current_only=False)
        handle_whois_lookup(client, args)
        calls = client.calls_to("whois_lookup")
        assert len(calls) == 1
        assert calls[0].args == ()
        assert calls[0].kwargs == {
            "domain": "example.com",
            "ip": None,
            "full": False,
            "current_only": False,
        }

    def test_ip_target_calls_whois_with_ip(self) -> None:
        client = _mock_client()
        args = WhoisArgs(query="8.8.8.8", full=False, current_only=False)
        handle_whois_lookup(client, args)
        calls = client.calls_to("whois_lookup")
        assert len(calls) == 1
        assert calls[0].args == ()
        assert calls[0].kwargs == {
            "domain": None,
            "ip": "8.8.8.8",
            "full": False,
            "current_only": False,
        }

    def test_full_flag_forwarded(self) -> None:
        client = _mock_client()
        args = WhoisArgs(query="example.com", full=True, current_only=False)
        handle_whois_lookup(client, args)
        call_kwargs = client.calls_to("whois_lookup")[-1].kwargs
        assert call_kwargs["full"] is True


class TestHandleDnsLookup:
    def test_no_types_passes_none(self) -> None:
        client = _mock_client()
        args = DnsArgs(query="example.com", types=None)
        handle_dns_lookup(client, args)
        calls = client.calls_to("dns_lookup")
        assert len(calls) == 1
        assert calls[0].args == ("example.com",)
        assert calls[0].kwargs == {"record_types": None}

    def test_types_split_by_comma(self) -> None:
        client = _mock_client()
        args = DnsArgs(query="example.com", types=["A", "MX", "TXT"])
        handle_dns_lookup(client, args)
        calls = client.calls_to("dns_lookup")
        assert len(calls) == 1
        assert calls[0].args == ("example.com",)
        assert calls[0].kwargs == {"record_types": ["A", "MX", "TXT"]}


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
        args = self._search_args(keywords=["kw"])
        handle_domain_search(client, args)
        calls = client.calls_to("domain_search")
        assert len(calls) == 1
        call_kwargs = calls[-1].kwargs
        assert call_kwargs["keywords"] == ["kw"]
        assert call_kwargs["filters"] is None

    def test_exclude_dashed_sets_filter(self) -> None:
        client = _mock_client()
        args = self._search_args(exclude_dashed=True)
        handle_domain_search(client, args)
        call_kwargs = client.calls_to("domain_search")[-1].kwargs
        assert call_kwargs["filters"]["exclude_dashed"] is True

    def test_count_only_sets_filter(self) -> None:
        client = _mock_client()
        args = self._search_args(count_only=True)
        handle_domain_search(client, args)
        call_kwargs = client.calls_to("domain_search")[-1].kwargs
        assert call_kwargs["filters"]["count_only"] == 1

    def test_min_max_length(self) -> None:
        client = _mock_client()
        args = self._search_args(min_length=5, max_length=15)
        handle_domain_search(client, args)
        call_kwargs = client.calls_to("domain_search")[-1].kwargs
        assert call_kwargs["filters"]["min_length"] == 5
        assert call_kwargs["filters"]["max_length"] == 15


class TestCliCredentials:
    def test_is_interactive_requires_both_stdin_and_stdout(self) -> None:
        assert _is_interactive(isatty=lambda fd: fd == 0) is False
        assert _is_interactive(isatty=lambda _fd: True) is True

    def test_prompt_for_api_key_persists_value(self, tmp_path: Path) -> None:
        target = tmp_path / "domainiq.key"

        api_key = prompt_for_api_key(
            str(target),
            is_interactive=lambda: True,
            prompt=lambda _prompt, _timeout: "interactive_key_xyz",
            env={},
        )

        assert api_key == "interactive_key_xyz"
        assert target.exists()
        assert target.read_text() == "interactive_key_xyz"

    def test_prompt_for_api_key_raises_when_non_interactive(self) -> None:
        with pytest.raises(DomainIQError, match="No API key found"):
            prompt_for_api_key(None, is_interactive=lambda: False, env={})


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

    def test_build_config_prompts_after_missing_api_key(self) -> None:
        args = argparse.Namespace(api_key=None, timeout=9, config_file="missing.key")
        config_factory = _RecordingCallable(
            [
                DomainIQConfigurationError("No API key found"),
                argparse.Namespace(api_key="prompted-key"),
            ]
        )

        config = cli_module._build_config(
            args,
            config_factory=config_factory,
            prompt=lambda _path: "prompted",
        )

        assert config.api_key == "prompted-key"
        assert config_factory.calls[1][1] == {
            "api_key": "prompted",
            "timeout": 9,
            "config_file": "missing.key",
        }

    def test_build_config_reraises_non_key_configuration_error(self) -> None:
        args = argparse.Namespace(api_key=None, timeout=9, config_file="missing.key")
        config_factory = _RecordingCallable(
            [
                DomainIQConfigurationError(
                    "Invalid DOMAINIQ_MAX_RETRIES: expected an integer"
                )
            ]
        )
        prompt = _RecordingCallable()

        with pytest.raises(DomainIQConfigurationError, match="DOMAINIQ_MAX_RETRIES"):
            cli_module._build_config(args, config_factory=config_factory, prompt=prompt)

        assert prompt.calls == []

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

    def test_handle_cli_error_prints_traceback_when_debug(self) -> None:
        print_exc = _RecordingCallable()

        code = cli_module._handle_cli_error(
            OSError("disk failed"), debug=True, print_exc=print_exc
        )

        assert code == 1
        assert print_exc.calls == [((), {})]

    def test_handle_cli_error_reraises_unknown_errors(self) -> None:
        with pytest.raises(RuntimeError, match="boom"):
            cli_module._handle_cli_error(RuntimeError("boom"), False)

    def test_main_no_command_exits_no_command(self) -> None:
        code = main(
            ["--api-key", "key"],
            client_factory=_client_factory(StubClient()),
        )
        assert code == _EXIT_NO_COMMAND

    def test_main_exits_1_on_domainiq_error(self) -> None:
        client = StubClient()
        client.set_error("whois_lookup", DomainIQError("test error"))

        code = main(
            ["--api-key", "key", "--whois-lookup", "example.com"],
            client_factory=_client_factory(client),
        )
        assert code == 1

    def test_main_keyboard_interrupt_exits_130(self) -> None:
        code = main(
            ["--api-key", "key"],
            client_factory=lambda _config: _RaisingContext(KeyboardInterrupt()),
        )
        assert code == 130

    def test_main_prompts_when_sdk_config_has_no_key(self) -> None:
        config = Config(api_key="prompted")

        code = main(
            ["--whois-lookup", "example.com"],
            build_config=lambda _args: config,
            client_factory=_client_factory(StubClient()),
        )

        assert code == _EXIT_SUCCESS
