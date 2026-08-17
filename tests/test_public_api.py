"""Tests for the package's public export surface."""

from __future__ import annotations

import importlib

import domainiq


def test_all_names_are_importable() -> None:
    """Every name in __all__ must resolve to a real attribute."""
    for name in domainiq.__all__:
        assert hasattr(domainiq, name), name


def test_all_is_sorted_and_unique() -> None:
    assert domainiq.__all__ == sorted(domainiq.__all__)
    assert len(domainiq.__all__) == len(set(domainiq.__all__))


def test_typed_method_arguments_are_exported() -> None:
    """Enums and result types used by public methods are reachable at the root."""
    models = importlib.import_module("domainiq.models")
    for name in (
        "DNSRecordType",
        "BulkWhoisType",
        "ReverseSearchType",
        "ReverseIpSearchType",
        "ReverseMxSearchType",
        "MonitorItemType",
        "MonitorReportType",
        "DomainCategory",
        "DomainSnapshot",
    ):
        assert name in domainiq.__all__, name
        assert getattr(domainiq, name) is getattr(models, name)


def test_config_is_exported() -> None:
    assert domainiq.Config is importlib.import_module("domainiq.config").Config
