"""Tests for the queued-request (`queue`) endpoint end to end."""

from __future__ import annotations

import argparse
from typing import TYPE_CHECKING, cast

import pytest

from domainiq._params.queue import build_queue_params, build_submit_queued_params
from domainiq.cli._args import create_parser
from domainiq.cli._dispatch import _dispatch_queue
from domainiq.cli._handlers import handle_queue, handle_submit_queued
from domainiq.cli._types import QueueArgs, SubmitQueuedArgs
from domainiq.cli._validation import validate_args
from domainiq.deserializers import parse_queue_result
from domainiq.exceptions import DomainIQValidationError

from .conftest import RecordedCall, StubClient, make_async_response, make_sync_response

if TYPE_CHECKING:
    from domainiq import DomainIQClient
    from domainiq.async_client import AsyncDomainIQClient
    from domainiq.protocols import QueueProtocol

    from .conftest import MockAsyncTransport, MockSyncTransport


class TestBuildQueueParams:
    def test_valid_params_are_stripped(self) -> None:
        assert build_queue_params("  h1  ", "  status  ") == {
            "service": "queue",
            "hash": "h1",
            "action": "status",
        }

    @pytest.mark.parametrize(
        ("request_hash", "action"),
        [("", "status"), ("   ", "status"), ("h1", ""), ("h1", "   ")],
    )
    def test_empty_values_are_rejected(self, request_hash: str, action: str) -> None:
        with pytest.raises(DomainIQValidationError):
            build_queue_params(request_hash, action)


class TestParseQueueResult:
    def test_reads_status_hash_and_payload(self) -> None:
        result = parse_queue_result(
            {"status": "done", "hash": "h1", "result": {"x": 1}}
        )
        assert result.status == "done"
        assert result.request_hash == "h1"
        assert result.data == {"x": 1}

    def test_missing_payload_gives_none_data(self) -> None:
        result = parse_queue_result({"status": "pending", "hash": "h1"})
        assert result.status == "pending"
        assert result.data is None

    def test_non_container_payload_gives_none_data(self) -> None:
        assert parse_queue_result({"result": "not-a-container"}).data is None


class TestQueueMixin:
    def test_sync_check_queue(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        mock_transport.enqueue(
            make_sync_response(200, '{"result": {"status": "done", "hash": "h1"}}')
        )
        result = mock_client.check_queue("h1", "status")
        assert result.status == "done"
        assert result.request_hash == "h1"

    @pytest.mark.asyncio
    async def test_async_check_queue(
        self,
        mock_async_transport: MockAsyncTransport,
        mock_async_client: AsyncDomainIQClient,
    ) -> None:
        mock_async_transport.enqueue(
            make_async_response(200, '{"result": {"status": "pending"}}')
        )
        result = await mock_async_client.check_queue("h1", "status")
        assert result.status == "pending"


class TestQueueCli:
    def test_parser_accepts_queue_flags(self) -> None:
        args = create_parser().parse_args(
            ["--queue-hash", "h1", "--queue-action", "status"]
        )
        assert args.queue_hash == "h1"
        assert args.queue_action == "status"

    def test_queue_args_from_namespace(self) -> None:
        args = argparse.Namespace(queue_hash="h1", queue_action="status")
        queue_args = QueueArgs.from_namespace(args)
        assert queue_args.request_hash == "h1"
        assert queue_args.action == "status"

    def test_handle_queue_invokes_client(self) -> None:
        client = StubClient()
        handle_queue(cast("QueueProtocol", client), QueueArgs("h1", "status"))
        assert len(client.calls_to("check_queue")) == 1

    def test_dispatch_runs_when_both_present(self) -> None:
        client = StubClient()
        args = argparse.Namespace(
            queue_hash="h1", queue_action="status", submit_queued=None
        )
        result = _dispatch_queue(cast("QueueProtocol", client), args)
        assert result.executed is True
        assert len(client.calls_to("check_queue")) == 1

    def test_dispatch_noop_when_absent(self) -> None:
        client = StubClient()
        args = argparse.Namespace(
            queue_hash=None, queue_action=None, submit_queued=None
        )
        result = _dispatch_queue(cast("QueueProtocol", client), args)
        assert result.executed is False

    def test_validation_requires_both_flags(self) -> None:
        parser = create_parser()
        hash_only = validate_args(parser.parse_args(["--queue-hash", "h1"]))
        action_only = validate_args(parser.parse_args(["--queue-action", "status"]))
        paired = validate_args(
            parser.parse_args(["--queue-hash", "h1", "--queue-action", "status"])
        )
        assert any("--queue-action" in error for error in hash_only)
        assert any("--queue-hash" in error for error in action_only)
        assert paired == []


class TestBuildSubmitQueuedParams:
    def test_adds_service_and_queued_flag(self) -> None:
        assert build_submit_queued_params("whois", {"domain": "example.com"}) == {
            "domain": "example.com",
            "service": "whois",
            "queued": 1,
        }

    def test_service_wins_over_params_and_is_stripped(self) -> None:
        params = build_submit_queued_params("  whois  ", {"service": "dns"})
        assert params["service"] == "whois"
        assert params["queued"] == 1

    @pytest.mark.parametrize("service", ["", "   "])
    def test_empty_service_is_rejected(self, service: str) -> None:
        with pytest.raises(DomainIQValidationError):
            build_submit_queued_params(service, {})


class TestSubmitQueuedMixin:
    def test_sync_submit_queued(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        mock_transport.enqueue(
            make_sync_response(200, '{"status": "queued", "hash": "h9"}')
        )
        result = mock_client.submit_queued("whois", domain="example.com")
        assert result.status == "queued"
        assert result.request_hash == "h9"

    @pytest.mark.asyncio
    async def test_async_submit_queued(
        self,
        mock_async_transport: MockAsyncTransport,
        mock_async_client: AsyncDomainIQClient,
    ) -> None:
        mock_async_transport.enqueue(
            make_async_response(200, '{"status": "queued", "hash": "h9"}')
        )
        result = await mock_async_client.submit_queued("whois", domain="example.com")
        assert result.status == "queued"


class TestSubmitQueuedCli:
    def test_parser_accepts_submit_queued_flags(self) -> None:
        args = create_parser().parse_args(
            [
                "--submit-queued",
                "whois",
                "--queued-param",
                "domain=example.com",
                "--queued-param",
                "full=1",
            ]
        )
        assert args.submit_queued == "whois"
        assert args.queued_param == ["domain=example.com", "full=1"]

    def test_submit_queued_args_from_namespace(self) -> None:
        args = argparse.Namespace(
            submit_queued="whois", queued_param=["domain=example.com", "full=1"]
        )
        submit_args = SubmitQueuedArgs.from_namespace(args)
        assert submit_args.service == "whois"
        assert submit_args.params == {"domain": "example.com", "full": "1"}

    def test_submit_queued_args_without_params(self) -> None:
        args = argparse.Namespace(submit_queued="limits", queued_param=None)
        assert SubmitQueuedArgs.from_namespace(args).params == {}

    def test_handle_submit_queued_invokes_client(self) -> None:
        client = StubClient()
        handle_submit_queued(
            cast("QueueProtocol", client),
            SubmitQueuedArgs("whois", {"domain": "example.com"}),
        )
        calls = client.calls_to("submit_queued")
        assert calls == [RecordedCall(("whois",), {"domain": "example.com"})]

    def test_dispatch_runs_submit_queued(self) -> None:
        client = StubClient()
        args = argparse.Namespace(
            queue_hash=None,
            queue_action=None,
            submit_queued="whois",
            queued_param=["domain=example.com"],
        )
        result = _dispatch_queue(cast("QueueProtocol", client), args)
        assert result.executed is True
        assert len(client.calls_to("submit_queued")) == 1

    def test_validation_rejects_malformed_pairs(self) -> None:
        parser = create_parser()
        malformed = validate_args(
            parser.parse_args(
                ["--submit-queued", "whois", "--queued-param", "no-equals"]
            )
        )
        empty_key = validate_args(
            parser.parse_args(["--submit-queued", "whois", "--queued-param", "=v"])
        )
        orphan = validate_args(
            parser.parse_args(["--queued-param", "domain=example.com"])
        )
        valid = validate_args(
            parser.parse_args(
                ["--submit-queued", "whois", "--queued-param", "domain=example.com"]
            )
        )
        assert any("KEY=VALUE" in error for error in malformed)
        assert any("KEY=VALUE" in error for error in empty_key)
        assert any("--submit-queued" in error for error in orphan)
        assert valid == []
