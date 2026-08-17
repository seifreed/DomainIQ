"""Unit tests for the aiohttp transport without real network I/O."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar, NoReturn, cast

import pytest

from domainiq.http import AiohttpTransport

if TYPE_CHECKING:
    from collections.abc import Callable
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

    def _open_session(self, connector: FakeConnector) -> FakeSession:
        if self.session_error is not None:
            raise self.session_error
        session = FakeSession(connector)
        self.sessions.append(session)
        return session

    # aiohttp exposes ClientSession as a callable; alias the impl to match.
    ClientSession = _open_session


def _importer(fake_module: FakeAiohttpModule) -> Callable[[str], object]:
    def _import(_name: str) -> object:
        return fake_module

    return _import


@pytest.mark.asyncio
class TestAiohttpTransport:
    async def test_get_creates_session_and_returns_response(self) -> None:
        fake_module = FakeAiohttpModule()
        transport = AiohttpTransport(connector_limit=5, importer=_importer(fake_module))

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

    async def test_close_closes_open_session(self) -> None:
        fake_module = FakeAiohttpModule()
        transport = AiohttpTransport(importer=_importer(fake_module))
        await transport.get("https://api.example.test", {}, 3)

        await transport.close()

        assert fake_module.sessions[0].closed is True
        assert transport.is_open is False

    async def test_client_error_is_translated_to_os_error(self) -> None:
        fake_module = FakeAiohttpModule()
        transport = AiohttpTransport(importer=_importer(fake_module))
        session = cast("FakeSession", await transport._get_session())
        session.error = FakeClientError("boom")

        with pytest.raises(OSError, match="boom"):
            await transport.get("https://api.example.test", {}, 3)

        assert fake_module.sessions[0] is session

    async def test_unicode_decode_error_propagates_regression(self) -> None:
        """Regression: decode errors were remapped to OSError and retried."""
        fake_module = FakeAiohttpModule()
        transport = AiohttpTransport(importer=_importer(fake_module))
        session = await transport._get_session()
        session.error = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid")

        with pytest.raises(UnicodeDecodeError):
            await transport.get("https://api.example.test", {}, 3)

    async def test_timeout_error_is_preserved(self) -> None:
        fake_module = FakeAiohttpModule()
        transport = AiohttpTransport(importer=_importer(fake_module))
        session = await transport._get_session()
        session.error = TimeoutError("slow")

        with pytest.raises(TimeoutError):
            await transport.get("https://api.example.test", {}, 3)

    async def test_close_prevents_subsequent_get_calls(self) -> None:
        fake_module = FakeAiohttpModule()
        transport = AiohttpTransport(importer=_importer(fake_module))
        await transport.get("https://api.example.test", {}, 3)

        await transport.close()

        with pytest.raises(RuntimeError, match="Transport is closed"):
            await transport.get("https://api.example.test", {}, 3)

    async def test_close_closes_connector_regression(self) -> None:
        fake_module = FakeAiohttpModule()
        transport = AiohttpTransport(importer=_importer(fake_module))
        await transport.get("https://api.example.test", {}, 3)

        await transport.close()

        assert fake_module.sessions[0].connector.closed is True

    async def test_get_session_after_close_raises_runtime_error(self) -> None:
        fake_module = FakeAiohttpModule()
        transport = AiohttpTransport(importer=_importer(fake_module))
        await transport.close()

        with pytest.raises(RuntimeError, match="Transport is closed"):
            await transport._get_session()

    async def test_close_prevents_get_via_get_session_race_regression(self) -> None:
        """Regression: redundant _closed check outside lock caused TOCTOU race."""
        fake_module = FakeAiohttpModule()
        transport = AiohttpTransport(importer=_importer(fake_module))

        await transport.close()

        with pytest.raises(RuntimeError, match="Transport is closed"):
            await transport.get("https://api.example.test", {}, 3)

    async def test_connector_closed_on_session_recreation_regression(self) -> None:
        """Regression: old connector was never closed when session was recreated."""
        fake_module = FakeAiohttpModule()
        transport = AiohttpTransport(importer=_importer(fake_module))
        await transport.get("https://api.example.test", {}, 3)
        first_connector = fake_module.sessions[0].connector

        fake_module.sessions[0].closed = True
        await transport.get("https://api.example.test", {}, 3)
        second_connector = fake_module.sessions[1].connector

        assert first_connector.closed is True
        assert second_connector.closed is False

    async def test_runtime_error_closed_session_translated_to_os_error_regression(
        self,
    ) -> None:
        """Regression: RuntimeError from aiohttp closed session escaped retry loop."""
        fake_module = FakeAiohttpModule()
        transport = AiohttpTransport(importer=_importer(fake_module))
        session = await transport._get_session()
        session.error = RuntimeError("Session is closed")

        with pytest.raises(OSError, match="Session is closed"):
            await transport.get("https://api.example.test", {}, 3)

    async def test_connector_closed_on_session_init_failure_regression(self) -> None:
        """Regression: TCPConnector leaked when ClientSession raised."""
        fake_module = FakeAiohttpModule()
        fake_module.session_error = RuntimeError("boom")
        transport = AiohttpTransport(importer=_importer(fake_module))

        with pytest.raises(RuntimeError, match="boom"):
            await transport._get_session()

        # Connector was created but should be closed on failure.
        assert fake_module.sessions == []

    async def test_connector_closed_on_base_exception_during_session_init_regression(
        self,
    ) -> None:
        """Regression: BaseException subclasses leaked the TCPConnector."""
        fake_module = FakeAiohttpModule()
        fake_module.session_error = KeyboardInterrupt()
        transport = AiohttpTransport(importer=_importer(fake_module))

        with pytest.raises(KeyboardInterrupt):
            await transport._get_session()

        # Connector was created but should be closed on failure.
        assert transport._connector is None or transport._connector.closed is True

    async def test_non_closed_runtime_error_propagates(self) -> None:
        fake_module = FakeAiohttpModule()
        transport = AiohttpTransport(importer=_importer(fake_module))
        session = await transport._get_session()
        session.error = RuntimeError("unexpected boom")

        with pytest.raises(RuntimeError, match="unexpected boom"):
            await transport.get("https://api.example.test", {}, 3)

    async def test_try_sync_close_closes_connector(self) -> None:
        fake_module = FakeAiohttpModule()
        transport = AiohttpTransport(importer=_importer(fake_module))

        class _SyncConnector:
            def __init__(self) -> None:
                self.closed = False

            def close(self) -> None:
                self.closed = True

        connector = _SyncConnector()
        transport._connector = connector

        transport.try_sync_close()

        assert connector.closed is True
        assert transport.is_open is False

    async def test_try_sync_close_without_connector_is_safe(self) -> None:
        fake_module = FakeAiohttpModule()
        transport = AiohttpTransport(importer=_importer(fake_module))

        transport.try_sync_close()

        assert transport.is_open is False

    async def test_try_sync_close_connector_without_close_is_dropped(self) -> None:
        fake_module = FakeAiohttpModule()
        transport = AiohttpTransport(importer=_importer(fake_module))
        transport._connector = object()  # no close attribute

        transport.try_sync_close()

        assert transport._connector is None


def test_missing_aiohttp_raises_import_error() -> None:
    def _raise_import_error(name: str) -> NoReturn:
        msg = f"No module named {name}"
        raise ImportError(msg)

    with pytest.raises(ImportError, match="aiohttp is required"):
        AiohttpTransport(importer=_raise_import_error)
