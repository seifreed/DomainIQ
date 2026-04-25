"""Unit tests for residual request-parameter builders."""

from __future__ import annotations

import pytest

from domainiq._params.analysis import (
    build_domain_categorize_params,
    build_domain_snapshot_history_params,
    build_domain_snapshot_params,
)
from domainiq._params.bulk import (
    build_bulk_dns_params,
    build_bulk_whois_ip_params,
    build_bulk_whois_params,
)
from domainiq._params.dns import build_dns_params
from domainiq._params.reports import (
    build_domain_report_params,
    build_email_report_params,
    build_ip_report_params,
)
from domainiq._params.whois import build_whois_params
from domainiq.constants import API_FLAG_ENABLED
from domainiq.exceptions import DomainIQValidationError
from domainiq.models import BulkWhoisType, DNSRecordType, SnapshotOptions


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

    def test_ipv6_lookup_is_valid_target(self) -> None:
        assert build_whois_params(None, " 2001:db8::1 ", False, False) == {
            "service": "whois",
            "ip": "2001:db8::1",
        }

    @pytest.mark.parametrize(
        ("domain", "ip", "param_name"),
        [
            (None, None, "domain"),
            ("", None, "domain"),
            (None, " ", "ip"),
            ("example.com", "192.0.2.1", "domain"),
            ("invalid", None, "domain"),
            ("example..com", None, "domain"),
            (None, "999.999.999.999", "ip"),
            (None, "not.an.ip", "ip"),
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

    @pytest.mark.parametrize("record_types", [[""], ["  "], ["A", ""]])
    def test_dns_rejects_empty_record_types(self, record_types: list[str]) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            build_dns_params("example.com", record_types)

        assert exc_info.value.param_name == "record_types"


class TestReportParams:
    def test_report_params_accept_valid_targets(self) -> None:
        assert build_domain_report_params("example.com") == {
            "service": "domain_report",
            "domain": "example.com",
        }
        assert build_email_report_params("admin@example.com") == {
            "service": "email_report",
            "email": "admin@example.com",
        }
        assert build_ip_report_params("192.0.2.1") == {
            "service": "ip_report",
            "ip": "192.0.2.1",
        }

    @pytest.mark.parametrize(
        ("builder", "value", "param_name"),
        [
            (build_domain_report_params, "example..com", "domain"),
            (build_email_report_params, "bad local@example.com", "email"),
            (build_ip_report_params, "999.999.999.999", "ip"),
        ],
    )
    def test_report_params_reject_invalid_targets(
        self, builder, value: str, param_name: str
    ) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            builder(value)

        assert exc_info.value.param_name == param_name


class TestAnalysisParams:
    def test_domain_categorize_params(self) -> None:
        assert build_domain_categorize_params(["example.com", "example.net"]) == {
            "service": "categorize",
            "domains": "example.com,example.net",
        }

    def test_domain_snapshot_params(self) -> None:
        params = build_domain_snapshot_params("example.com", SnapshotOptions(raw=True))

        assert params == {
            "service": "snapshot",
            "domain": "example.com",
            "width": 250,
            "height": 125,
            "raw": API_FLAG_ENABLED,
        }

    def test_domain_snapshot_history_params(self) -> None:
        assert build_domain_snapshot_history_params("example.com", 1024, 768, 10) == {
            "service": "snapshot_history",
            "domain": "example.com",
            "width": 1024,
            "height": 768,
            "limit": 10,
        }

    @pytest.mark.parametrize("domains", [[""], ["  "], ["example.com", ""]])
    def test_domain_categorize_rejects_empty_domain_values(
        self, domains: list[str]
    ) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            build_domain_categorize_params(domains)

        assert exc_info.value.param_name == "domains"

    @pytest.mark.parametrize("domains", [["example..com"], ["example.com", "invalid"]])
    def test_domain_categorize_rejects_invalid_domains(
        self, domains: list[str]
    ) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            build_domain_categorize_params(domains)

        assert exc_info.value.param_name == "domains"

    @pytest.mark.parametrize(
        "builder",
        [
            lambda domain: build_domain_snapshot_params(domain, SnapshotOptions()),
            lambda domain: build_domain_snapshot_history_params(domain, 1024, 768, 10),
        ],
    )
    def test_snapshot_params_reject_invalid_domain(self, builder) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            builder("example..com")

        assert exc_info.value.param_name == "domain"


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

    @pytest.mark.parametrize(
        ("builder", "values", "param_name"),
        [
            (build_bulk_dns_params, [""], "domains"),
            (build_bulk_dns_params, ["  "], "domains"),
            (build_bulk_dns_params, ["example.com", ""], "domains"),
            (
                lambda vals: build_bulk_whois_params(vals, BulkWhoisType.LIVE),
                [""],
                "items",
            ),
            (build_bulk_whois_ip_params, [""], "domains"),
        ],
    )
    def test_bulk_params_reject_empty_list_values(
        self, builder, values: list[str], param_name: str
    ) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            builder(values)

        assert exc_info.value.param_name == param_name

    @pytest.mark.parametrize(
        ("builder", "values", "param_name"),
        [
            (build_bulk_dns_params, ["example..com"], "domains"),
            (build_bulk_dns_params, ["example.com", "invalid"], "domains"),
            (
                lambda vals: build_bulk_whois_params(vals, BulkWhoisType.LIVE),
                ["example..com"],
                "items",
            ),
            (
                lambda vals: build_bulk_whois_params(vals, BulkWhoisType.LIVE),
                ["example.com", "invalid"],
                "items",
            ),
        ],
    )
    def test_bulk_domain_params_reject_invalid_domains(
        self, builder, values: list[str], param_name: str
    ) -> None:
        with pytest.raises(DomainIQValidationError) as exc_info:
            builder(values)

        assert exc_info.value.param_name == param_name
