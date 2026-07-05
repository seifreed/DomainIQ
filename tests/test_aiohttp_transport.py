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
        self.closed = False

    async def close(self) -> None:
        self.closed = True


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
        if self.connector is not None:
            await self.connector.close()


class FakeAiohttpModule:
    ClientError = FakeClientError
    ClientTimeout = FakeTimeout
    TCPConnector = FakeConnector

    def __init__(self) -> None:
        self.sessions: list[FakeSession] = []
        self.session_error: BaseException | None = None

    def ClientSession(self, connector: FakeConnector) -> FakeSession:  # noqa: N802
        if self.session_error is not None:
            raise self.session_error
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

    async def test_close_prevents_subsequent_get_calls(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_aiohttp(monkeypatch)
        transport = AiohttpTransport(timeout=10)
        await transport.get("https://api.example.test", {}, 3)

        await transport.close()

        with pytest.raises(RuntimeError, match="Transport is closed"):
            await transport.get("https://api.example.test", {}, 3)

    async def test_close_closes_connector_regression(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_module = _patch_aiohttp(monkeypatch)
        transport = AiohttpTransport(timeout=10)
        await transport.get("https://api.example.test", {}, 3)

        await transport.close()

        assert fake_module.sessions[0].connector.closed is True

    async def test_get_session_after_close_raises_runtime_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_aiohttp(monkeypatch)
        transport = AiohttpTransport(timeout=10)
        await transport.close()

        with pytest.raises(RuntimeError, match="Transport is closed"):
            await transport._get_session()

    async def test_close_prevents_get_via_get_session_race_regression(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression: redundant _closed check outside lock caused TOCTOU race."""
        _patch_aiohttp(monkeypatch)
        transport = AiohttpTransport(timeout=10)

        await transport.close()

        with pytest.raises(RuntimeError, match="Transport is closed"):
            await transport.get("https://api.example.test", {}, 3)

    async def test_connector_closed_on_session_recreation_regression(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression: old connector was never closed when session was recreated."""
        fake_module = _patch_aiohttp(monkeypatch)
        transport = AiohttpTransport(timeout=10)
        await transport.get("https://api.example.test", {}, 3)
        first_connector = fake_module.sessions[0].connector

        fake_module.sessions[0].closed = True
        await transport.get("https://api.example.test", {}, 3)
        second_connector = fake_module.sessions[1].connector

        assert first_connector.closed is True
        assert second_connector.closed is False

    async def test_runtime_error_closed_session_translated_to_os_error_regression(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression: RuntimeError from aiohttp closed session escaped retry loop."""
        _patch_aiohttp(monkeypatch)
        transport = AiohttpTransport(timeout=10)
        session = await transport._get_session()
        session.error = RuntimeError("Session is closed")

        with pytest.raises(OSError, match="Session is closed"):
            await transport.get("https://api.example.test", {}, 3)

    async def test_connector_closed_on_session_init_failure_regression(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression: TCPConnector leaked when ClientSession raised."""
        fake_module = _patch_aiohttp(monkeypatch)
        fake_module.session_error = RuntimeError("boom")
        transport = AiohttpTransport(timeout=10)

        with pytest.raises(RuntimeError, match="boom"):
            await transport._get_session()

        # Connector was created but should be closed on failure.
        assert fake_module.sessions == []

    async def test_connector_closed_on_base_exception_during_session_init_regression(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression: BaseException subclasses leaked the TCPConnector."""
        fake_module = _patch_aiohttp(monkeypatch)
        fake_module.session_error = KeyboardInterrupt()
        transport = AiohttpTransport(timeout=10)

        with pytest.raises(KeyboardInterrupt):
            await transport._get_session()

        # Connector was created but should be closed on failure.
        assert transport._connector is None or transport._connector.closed is True


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
