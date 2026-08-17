"""Tests for the account-limits (`limits`) endpoint end to end."""

from __future__ import annotations

import argparse
from typing import TYPE_CHECKING, cast

import pytest

from domainiq._params.limits import build_limits_params
from domainiq.cli._args import create_parser
from domainiq.cli._dispatch import _dispatch_limits
from domainiq.exceptions import DomainIQAPIError

from .conftest import StubClient, make_async_response, make_sync_response

if TYPE_CHECKING:
    from domainiq import DomainIQClient
    from domainiq.async_client import AsyncDomainIQClient
    from domainiq.protocols import LimitsProtocol

    from .conftest import MockAsyncTransport, MockSyncTransport


class TestBuildLimitsParams:
    def test_builds_service_only_params(self) -> None:
        assert build_limits_params() == {"service": "limits"}


class TestLimitsMixin:
    def test_sync_account_limits(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        mock_transport.enqueue(make_sync_response(200, '{"queries_remaining": 100}'))
        assert mock_client.account_limits() == {"queries_remaining": 100}

    def test_sync_empty_payload_is_rejected(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        mock_transport.enqueue(make_sync_response(200, "{}"))
        with pytest.raises(DomainIQAPIError):
            mock_client.account_limits()

    @pytest.mark.asyncio
    async def test_async_account_limits(
        self,
        mock_async_transport: MockAsyncTransport,
        mock_async_client: AsyncDomainIQClient,
    ) -> None:
        mock_async_transport.enqueue(
            make_async_response(200, '{"queries_remaining": 42}')
        )
        assert await mock_async_client.account_limits() == {"queries_remaining": 42}


class TestLimitsCli:
    def test_parser_accepts_limits_flag(self) -> None:
        assert create_parser().parse_args(["--limits"]).limits is True
        assert create_parser().parse_args([]).limits is False

    def test_dispatch_runs_when_flag_set(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        client = StubClient()
        client.set_result("account_limits", {"queries_remaining": 5})
        args = argparse.Namespace(limits=True)

        result = _dispatch_limits(cast("LimitsProtocol", client), args)

        assert result.executed is True
        assert result.errored is False
        assert len(client.calls_to("account_limits")) == 1
        assert "queries_remaining" in capsys.readouterr().out

    def test_dispatch_noop_when_flag_absent(self) -> None:
        client = StubClient()
        args = argparse.Namespace(limits=False)

        result = _dispatch_limits(cast("LimitsProtocol", client), args)

        assert result.executed is False
        assert client.calls_to("account_limits") == []
