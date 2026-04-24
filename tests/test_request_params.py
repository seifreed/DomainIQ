"""Unit tests for residual request-parameter builders."""

from __future__ import annotations

import pytest

from domainiq._params.bulk import (
    build_bulk_dns_params,
    build_bulk_whois_ip_params,
    build_bulk_whois_params,
)
from domainiq._params.dns import build_dns_params
from domainiq._params.whois import build_whois_params
from domainiq.constants import API_FLAG_ENABLED
from domainiq.exceptions import DomainIQValidationError
from domainiq.models import BulkWhoisType, DNSRecordType


class TestWhoisParams:
    def test_domain_lookup_includes_enabled_flags(self) -> None:
        assert build_whois_params(" example.com ", None, True, True) == {
            "service": "whois",
            "domain": "example.com",
            "full": API_FLAG_ENABLED,
            "current_only": API_FLAG_ENABLED,
        }

    def test_ip_lookup_omits_disabled_flags(self) -> None:
        assert build_whois_params(None, " 192.0.2.1 ", False, False) == {
            "service": "whois",
            "ip": "192.0.2.1",
        }

    @pytest.mark.parametrize(
        ("domain", "ip", "param_name"),
        [
            (None, None, "domain"),
            ("", None, "domain"),
            (None, " ", "ip"),
            ("example.com", "192.0.2.1", "domain"),
        ],
    )
    def test_invalid_targets_raise_validation_error(
        self, domain: str | None, ip: str | None, param_name: str
    ) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            build_whois_params(domain, ip, False, False)

        assert exc_info.value.param_name == param_name


class TestDnsParams:
    def test_dns_without_record_types(self) -> None:
        assert build_dns_params("example.com", None) == {
            "service": "dns",
            "q": "example.com",
        }

    def test_dns_with_string_and_enum_record_types(self) -> None:
        assert build_dns_params("example.com", ["A", DNSRecordType.MX]) == {
            "service": "dns",
            "q": "example.com",
            "types": "A,MX",
        }


class TestBulkParams:
    def test_bulk_dns_params(self) -> None:
        assert build_bulk_dns_params(["example.com", "example.net"]) == {
            "service": "bulk_dns",
            "domains": ["example.com", "example.net"],
        }

    def test_bulk_whois_params_use_enum_wire_value(self) -> None:
        assert build_bulk_whois_params(["example.com"], BulkWhoisType.CACHED) == {
            "service": "bulk_whois",
            "type": "cached",
            "domains": ["example.com"],
        }

    def test_bulk_whois_params_accept_string_lookup_type(self) -> None:
        assert build_bulk_whois_params(["example.com"], "live") == {
            "service": "bulk_whois",
            "type": "live",
            "domains": ["example.com"],
        }

    def test_bulk_whois_ip_params(self) -> None:
        assert build_bulk_whois_ip_params(["192.0.2.1"]) == {
            "service": "bulk_whois_ip",
            "domains": ["192.0.2.1"],
        }

    @pytest.mark.parametrize(
        ("builder", "param_name"),
        [
            (build_bulk_dns_params, "domains"),
            (
                lambda values: build_bulk_whois_params(values, BulkWhoisType.LIVE),
                "items",
            ),
            (build_bulk_whois_ip_params, "domains"),
        ],
    )
    def test_bulk_params_require_non_empty_lists(
        self, builder, param_name: str
    ) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            builder([])

        assert exc_info.value.param_name == param_name
