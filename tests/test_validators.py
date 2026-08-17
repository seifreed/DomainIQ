"""Regression tests for validators."""

from __future__ import annotations

import pytest

from domainiq.exceptions import DomainIQValidationError
from domainiq.validators import (
    ensure_positive_int,
    validate_dns_name,
    validate_domain,
    validate_whois_target,
)


class TestValidateDomain:
    def test_rejects_malformed_ip_as_domain_regression(self) -> None:
        """Regression: '123.456.789.0' passed as a valid domain."""
        assert validate_domain("123.456.789.0") is False

    def test_rejects_numeric_only_labels_regression(self) -> None:
        """Regression: domains looking like invalid IPs were accepted."""
        assert validate_domain("999.888.777.666") is False
        assert validate_domain("192.168.1.1") is False

    def test_accepts_all_numeric_non_ipv4_labels_regression(self) -> None:
        """Regression: valid DNS names like 123.456 were rejected."""
        assert validate_domain("123.456") is True

    def test_rejects_underscore_labels(self) -> None:
        """Registrable hostnames must not contain underscore labels."""
        assert validate_domain("_dmarc.example.com") is False


class TestValidateDnsName:
    @pytest.mark.parametrize(
        "name",
        [
            "_dmarc.example.com",
            "selector._domainkey.example.com",
            "_sip._tcp.example.com",
            "example.com",
        ],
    )
    def test_accepts_underscore_labels_regression(self, name: str) -> None:
        """Regression: DMARC/DKIM/SRV underscore names were rejected for DNS."""
        assert validate_dns_name(name) is True

    def test_rejects_malformed_names(self) -> None:
        assert validate_dns_name("example..com") is False
        assert validate_dns_name("-bad.example.com") is False
        assert validate_dns_name("192.168.1.1") is False


class TestValidateWhoisTarget:
    def test_rejects_non_string_domain_regression(self) -> None:
        """Regression: passing int as domain raised AttributeError."""
        with pytest.raises(DomainIQValidationError, match="must be a string"):
            validate_whois_target(domain=123, ip=None)

    def test_rejects_non_string_ip_regression(self) -> None:
        """Regression: passing int as ip raised AttributeError."""
        with pytest.raises(DomainIQValidationError, match="must be a string"):
            validate_whois_target(domain=None, ip=123)


class TestEnsurePositiveInt:
    def test_error_message_uses_repr_regression(self) -> None:
        """Regression: empty string was invisible in error message."""
        with pytest.raises(DomainIQValidationError, match="got ''"):
            ensure_positive_int("count", "")
