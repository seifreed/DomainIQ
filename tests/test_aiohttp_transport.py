"""Unit tests for the aiohttp transport without real network I/O."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar, NoReturn

import pytest

from domainiq.http import AiohttpTransport

if TYPE_CHECKING:
    from types import TracebackType


class FakeClientError(Exception):
    """Fake aiohttp client exception."""


class FakeTimeout:
    def __init__(self, total: float) -> None:
        self.total = total


class FakeConnector:
    def __init__(self, limit: int, limit_per_host: int) -> None:
        self.limit = limit
        self.limit_per_host = limit_per_host


class FakeResponseContext:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response

    async def __aenter__(self) -> FakeResponse:
        return self.response

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _tb: TracebackType | None,
    ) -> None:
        return None


class FakeResponse:
    status: ClassVar[int] = 200
    headers: ClassVar[dict[str, str]] = {"Content-Type": "application/json"}

    async def text(self) -> str:
        return '{"ok": true}'


class FakeSession:
    def __init__(self, connector: FakeConnector) -> None:
        self.connector = connector
        self.closed = False
        self.calls: list[dict[str, Any]] = []
        self.error: BaseException | None = None

    def get(
        self,
        url: str,
        params: dict[str, str],
        timeout: FakeTimeout,
    ) -> FakeResponseContext:
        self.calls.append({"url": url, "params": params, "timeout": timeout})
        if self.error is not None:
            raise self.error
        return FakeResponseContext(FakeResponse())

    async def close(self) -> None:
        self.closed = True


class FakeAiohttpModule:
    ClientError = FakeClientError
    ClientTimeout = FakeTimeout
    TCPConnector = FakeConnector

    def __init__(self) -> None:
        self.sessions: list[FakeSession] = []

    def ClientSession(self, connector: FakeConnector) -> FakeSession:  # noqa: N802
        session = FakeSession(connector)
        self.sessions.append(session)
        return session


def _patch_aiohttp(monkeypatch: pytest.MonkeyPatch) -> FakeAiohttpModule:
    fake_module = FakeAiohttpModule()

    def _import_fake_aiohttp(_name: str) -> FakeAiohttpModule:
        return fake_module

    monkeypatch.setattr(
        "domainiq.http._aiohttp_transport.importlib.import_module",
        _import_fake_aiohttp,
    )
    return fake_module


@pytest.mark.asyncio
class TestAiohttpTransport:
    async def test_get_creates_session_and_returns_response(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_module = _patch_aiohttp(monkeypatch)
        transport = AiohttpTransport(timeout=10, connector_limit=5)

        response = await transport.get(
            "https://api.example.test",
            {"service": "whois"},
            3,
        )

        assert response.status_code == 200
        assert response.text == '{"ok": true}'
        assert response.json() == {"ok": True}
        assert transport.is_open is True
        assert fake_module.sessions[0].connector.limit == 5
        assert fake_module.sessions[0].calls[0]["timeout"].total == 3

    async def test_close_closes_open_session(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_module = _patch_aiohttp(monkeypatch)
        transport = AiohttpTransport(timeout=10)
        await transport.get("https://api.example.test", {}, 3)

        await transport.close()

        assert fake_module.sessions[0].closed is True
        assert transport.is_open is False

    async def test_client_error_is_translated_to_os_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_module = _patch_aiohttp(monkeypatch)
        transport = AiohttpTransport(timeout=10)
        session = await transport._get_session()
        session.error = FakeClientError("boom")

        with pytest.raises(OSError, match="boom"):
            await transport.get("https://api.example.test", {}, 3)

        assert fake_module.sessions[0] is session

    async def test_timeout_error_is_preserved(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_aiohttp(monkeypatch)
        transport = AiohttpTransport(timeout=10)
        session = await transport._get_session()
        session.error = TimeoutError("slow")

        with pytest.raises(TimeoutError):
            await transport.get("https://api.example.test", {}, 3)


def test_missing_aiohttp_raises_import_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise_import_error(name: str) -> NoReturn:
        msg = f"No module named {name}"
        raise ImportError(msg)

    monkeypatch.setattr(
        "domainiq.http._aiohttp_transport.importlib.import_module",
        _raise_import_error,
    )

    with pytest.raises(ImportError, match="aiohttp is required"):
        AiohttpTransport(timeout=10)
