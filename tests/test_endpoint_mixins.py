"""Endpoint mixin tests exercised through real client request paths."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

import pytest

from domainiq._models import BulkWhoisType, DNSRecordType, SnapshotOptions

from .conftest import (
    MockAsyncTransport,
    MockSyncTransport,
    make_async_response,
    make_sync_response,
)

if TYPE_CHECKING:
    from domainiq import DomainIQClient
    from domainiq.async_client import AsyncDomainIQClient


class TestBulkMixins:
    def test_sync_bulk_methods_parse_csv_and_empty_results(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        mock_transport.enqueue(
            make_sync_response(200, "domain,ip\nexample.com,192.0.2.1\n")
        )
        mock_transport.enqueue(
            make_sync_response(200, "domain,status\nexample.org,ok\n")
        )
        mock_transport.enqueue(make_sync_response(200, ""))

        dns = mock_client.bulk_dns(["example.com"])
        whois = mock_client.bulk_whois(["example.org"], BulkWhoisType.CACHED)
        whois_ip = mock_client.bulk_whois_ip(["example.net"])

        assert dns == [{"domain": "example.com", "ip": "192.0.2.1"}]
        assert whois == [{"domain": "example.org", "status": "ok"}]
        assert whois_ip == []
        assert [call["params"]["service"] for call in mock_transport.calls] == [
            "bulk_dns",
            "bulk_whois",
            "bulk_whois_ip",
        ]
        assert mock_transport.calls[1]["params"]["type"] == "cached"

    @pytest.mark.asyncio
    async def test_async_bulk_methods_parse_csv(
        self,
        mock_async_transport: MockAsyncTransport,
        mock_async_client: AsyncDomainIQClient,
    ) -> None:
        mock_async_transport.enqueue(
            make_async_response(200, "domain,ip\nexample.com,192.0.2.1\n")
        )
        mock_async_transport.enqueue(
            make_async_response(200, "domain,status\nexample.org,ok\n")
        )
        mock_async_transport.enqueue(
            make_async_response(200, "domain,status\nexample.net,ok\n")
        )

        dns = await mock_async_client.bulk_dns(["example.com"])
        whois = await mock_async_client.bulk_whois(["example.org"])
        whois_ip = await mock_async_client.bulk_whois_ip(["example.net"])

        assert dns[0]["domain"] == "example.com"
        assert whois[0]["status"] == "ok"
        assert whois_ip[0]["domain"] == "example.net"


class TestDNSMixins:
    def test_sync_dns_method_parses_records_and_forwards_types(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        mock_transport.enqueue(
            make_sync_response(
                200,
                (
                    '{"domain": "example.com", "records": ['
                    '{"name": "example.com", "type": "A", "value": "192.0.2.1"}'
                    "]}"
                )
            )
        )

        result = mock_client.dns_lookup("example.com", [DNSRecordType.A, "MX"])

        assert result.domain == "example.com"
        assert result.records[0].value == "192.0.2.1"
        assert mock_transport.calls[0]["params"]["service"] == "dns"
        assert mock_transport.calls[0]["params"]["q"] == "example.com"
        assert mock_transport.calls[0]["params"]["types"] == "A,MX"

    @pytest.mark.asyncio
    async def test_async_dns_method_parses_records_and_forwards_types(
        self,
        mock_async_transport: MockAsyncTransport,
        mock_async_client: AsyncDomainIQClient,
    ) -> None:
        mock_async_transport.enqueue(
            make_async_response(
                200,
                (
                    '{"domain": "example.net", "records": ['
                    '{"name": "example.net", "type": "MX", "value": "mail.example.net"}'
                    "]}"
                )
            )
        )

        result = await mock_async_client.dns_lookup(
            "example.net", [DNSRecordType.MX]
        )

        assert result.domain == "example.net"
        assert result.records[0].type == "MX"
        assert mock_async_transport.calls[0]["params"]["service"] == "dns"
        assert mock_async_transport.calls[0]["params"]["types"] == "MX"


class TestDomainAnalysisMixins:
    def test_sync_domain_analysis_methods(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        raw = base64.b64encode(b"png").decode("ascii")
        mock_transport.enqueue(
            make_sync_response(
                200, '[{"domain": "example.com", "categories": ["security"]}]'
            )
        )
        mock_transport.enqueue(
            make_sync_response(
                200,
                (
                    '{"domain": "example.com", "screenshot_url": "https://img", '
                    f'"raw": "{raw}", "width": 640, "height": 480}}'
                ),
            )
        )
        mock_transport.enqueue(
            make_sync_response(
                200, '[{"domain": "example.com", "screenshot_url": "https://old"}]'
            )
        )

        categories = mock_client.domain_categorize(["example.com"])
        snapshot = mock_client.domain_snapshot(
            "example.com", SnapshotOptions(width=640, height=480, raw=True)
        )
        history = mock_client.domain_snapshot_history("example.com", limit=1)

        assert categories[0].categories == ["security"]
        assert snapshot.raw_data == b"png"
        assert history[0].screenshot_url == "https://old"
        assert [call["params"]["service"] for call in mock_transport.calls] == [
            "categorize",
            "snapshot",
            "snapshot_history",
        ]

    @pytest.mark.asyncio
    async def test_async_domain_analysis_methods(
        self,
        mock_async_transport: MockAsyncTransport,
        mock_async_client: AsyncDomainIQClient,
    ) -> None:
        mock_async_transport.enqueue(
            make_async_response(200, '{"domain": "example.com", "categories": []}')
        )
        mock_async_transport.enqueue(
            make_async_response(200, '{"domain": "example.com", "width": 250}')
        )
        mock_async_transport.enqueue(
            make_async_response(200, '[{"domain": "example.com", "height": 125}]')
        )

        categories = await mock_async_client.domain_categorize(["example.com"])
        snapshot = await mock_async_client.domain_snapshot("example.com")
        history = await mock_async_client.domain_snapshot_history("example.com")

        assert categories[0].domain == "example.com"
        assert snapshot.width == 250
        assert history[0].height == 125


class TestSearchMixins:
    def test_sync_search_methods(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        for body in (
            '{"results": ["example.com"]}',
            '{"matches": [{"email": "admin@example.com"}]}',
            '{"matches": [{"domain": "example.com"}]}',
            '{"matches": [{"ip": "192.0.2.1"}]}',
            '{"matches": [{"mx": "mail.example.com"}]}',
        ):
            mock_transport.enqueue(make_sync_response(200, body))

        domain = mock_client.domain_search(
            ["brand"], filters={"count_only": 1}, exclude_dashed=True
        )
        reverse = mock_client.reverse_search("email", "admin@example.com")
        dns = mock_client.reverse_dns("example.com")
        ip = mock_client.reverse_ip("ip", "192.0.2.1")
        mx = mock_client.reverse_mx("domain", "example.com", recursive=True)

        assert domain["results"] == ["example.com"]
        assert reverse["matches"][0]["email"] == "admin@example.com"
        assert dns["matches"][0]["domain"] == "example.com"
        assert ip["matches"][0]["ip"] == "192.0.2.1"
        assert mx["matches"][0]["mx"] == "mail.example.com"
        assert mock_transport.calls[0]["params"]["exclude_dashed"] == "1"
        assert mock_transport.calls[-1]["params"]["recursive"] == "1"

    @pytest.mark.asyncio
    async def test_async_search_methods(
        self,
        mock_async_transport: MockAsyncTransport,
        mock_async_client: AsyncDomainIQClient,
    ) -> None:
        for body in (
            '{"results": []}',
            '{"reverse": "search"}',
            '{"reverse": "dns"}',
            '{"reverse": "ip"}',
            '{"reverse": "mx"}',
        ):
            mock_async_transport.enqueue(make_async_response(200, body))

        assert await mock_async_client.domain_search(["brand"]) == {"results": []}
        assert await mock_async_client.reverse_search("email", "admin") == {
            "reverse": "search"
        }
        assert await mock_async_client.reverse_dns("example.com") == {"reverse": "dns"}
        assert await mock_async_client.reverse_ip("ip", "192.0.2.1") == {
            "reverse": "ip"
        }
        assert await mock_async_client.reverse_mx("domain", "example.com") == {
            "reverse": "mx"
        }


class TestReportMixins:
    def test_sync_report_methods(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        for body in (
            '{"domain": "example.com", "whois": {"domain": "example.com"}}',
            '{"name": "Alice Example", "domains": ["example.com"]}',
            '{"organization": "Example Org", "domains": ["example.org"]}',
            '{"email": "admin@example.com", "domains": ["example.net"]}',
            '{"ip": "192.0.2.1", "domains": ["example.com"]}',
        ):
            mock_transport.enqueue(make_sync_response(200, body))

        domain = mock_client.domain_report("example.com")
        name = mock_client.name_report("Alice Example")
        organization = mock_client.organization_report("Example Org")
        email = mock_client.email_report("admin@example.com")
        ip = mock_client.ip_report("192.0.2.1")

        assert domain.domain == "example.com"
        assert domain.whois_data is not None
        assert domain.whois_data.domain == "example.com"
        assert name["name"] == "Alice Example"
        assert organization["organization"] == "Example Org"
        assert email["email"] == "admin@example.com"
        assert ip["ip"] == "192.0.2.1"
        assert [call["params"]["service"] for call in mock_transport.calls] == [
            "domain_report",
            "name_report",
            "organization_report",
            "email_report",
            "ip_report",
        ]
        assert mock_transport.calls[1]["params"]["name"] == "Alice Example"
        assert mock_transport.calls[2]["params"]["organization"] == "Example Org"

    @pytest.mark.asyncio
    async def test_async_report_methods(
        self,
        mock_async_transport: MockAsyncTransport,
        mock_async_client: AsyncDomainIQClient,
    ) -> None:
        for body in (
            '{"domain": "example.com"}',
            '{"name": "Alice Example"}',
            '{"organization": "Example Org"}',
            '{"email": "admin@example.com"}',
            '{"ip": "192.0.2.1"}',
        ):
            mock_async_transport.enqueue(make_async_response(200, body))

        domain = await mock_async_client.domain_report("example.com")
        name = await mock_async_client.name_report("Alice Example")
        organization = await mock_async_client.organization_report("Example Org")
        email = await mock_async_client.email_report("admin@example.com")
        ip = await mock_async_client.ip_report("192.0.2.1")

        assert domain.domain == "example.com"
        assert name["name"] == "Alice Example"
        assert organization["organization"] == "Example Org"
        assert email["email"] == "admin@example.com"
        assert ip["ip"] == "192.0.2.1"
        assert [call["params"]["service"] for call in mock_async_transport.calls] == [
            "domain_report",
            "name_report",
            "organization_report",
            "email_report",
            "ip_report",
        ]


class TestMonitorMixins:
    def test_sync_monitor_methods(
        self, mock_transport: MockSyncTransport, mock_client: DomainIQClient
    ) -> None:
        bodies = [
            '[{"id": 1, "name": "watch", "type": "domain"}]',
            '{"items": [{"value": "example.com"}]}',
            '{"summary": true}',
            '{"changes": []}',
            '{"id": 2, "name": "new", "type": "domain", "email_alerts": "1"}',
            '{"added": true}',
            '{"enabled": true}',
            '{"disabled": true}',
            '{"strength": 10}',
            '{"deleted_item": true}',
            '{"deleted_report": true}',
        ]
        for body in bodies:
            mock_transport.enqueue(make_sync_response(200, body))

        reports = mock_client.monitor_list()
        items = mock_client.monitor_report_items(1)
        summary = mock_client.monitor_report_summary(1, item_id=2, days_range=7)
        changes = mock_client.monitor_report_changes(1, 3)
        created = mock_client.create_monitor_report("domain", "new")
        added = mock_client.add_monitor_item(1, "domain", ["example.com"], enabled=True)
        enabled = mock_client.enable_typos(1, 2)
        disabled = mock_client.disable_typos(1, 2)
        strength = mock_client.modify_typo_strength(1, 2, 10)
        deleted_item = mock_client.delete_monitor_item(2)
        deleted_report = mock_client.delete_monitor_report(1)

        assert reports[0].name == "watch"
        assert items["items"][0]["value"] == "example.com"
        assert summary["summary"] is True
        assert changes["changes"] == []
        assert created.email_alerts is True
        assert added["added"] is True
        assert enabled["enabled"] is True
        assert disabled["disabled"] is True
        assert strength["strength"] == 10
        assert deleted_item["deleted_item"] is True
        assert deleted_report["deleted_report"] is True

    @pytest.mark.asyncio
    async def test_async_monitor_methods(
        self,
        mock_async_transport: MockAsyncTransport,
        mock_async_client: AsyncDomainIQClient,
    ) -> None:
        for body in (
            '[{"id": 1, "name": "watch", "type": "domain"}]',
            '{"items": []}',
            '{"summary": true}',
            '{"changes": []}',
            '{"id": 2, "name": "new", "type": "domain"}',
            '{"added": true}',
            '{"enabled": true}',
            '{"disabled": true}',
            '{"strength": 10}',
            '{"deleted_item": true}',
            '{"deleted_report": true}',
        ):
            mock_async_transport.enqueue(make_async_response(200, body))

        assert (await mock_async_client.monitor_list())[0].name == "watch"
        assert await mock_async_client.monitor_report_items(1) == {"items": []}
        assert await mock_async_client.monitor_report_summary(1) == {"summary": True}
        assert await mock_async_client.monitor_report_changes(1, 3) == {"changes": []}
        assert (await mock_async_client.create_monitor_report("domain", "new")).id == 2
        assert await mock_async_client.add_monitor_item(
            1,
            "domain",
            ["example.com"],
        ) == {"added": True}
        assert await mock_async_client.enable_typos(1, 2) == {"enabled": True}
        assert await mock_async_client.disable_typos(1, 2) == {"disabled": True}
        assert await mock_async_client.modify_typo_strength(1, 2, 10) == {
            "strength": 10
        }
        assert await mock_async_client.delete_monitor_item(2) == {"deleted_item": True}
        assert await mock_async_client.delete_monitor_report(1) == {
            "deleted_report": True
        }
