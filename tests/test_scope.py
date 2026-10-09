"""
Tests for RECONYX — Scope filtering and domain management.
"""

from __future__ import annotations

import pytest
from reconyx.scope import ScopeManager, _root_domain


class TestScopeManager:
    def test_basic_subdomain_in_scope(self):
        sm = ScopeManager(target="example.com")
        assert sm.in_scope("sub.example.com") is True
        assert sm.in_scope("api.example.com") is True
        assert sm.in_scope("example.com") is True

    def test_out_of_scope_domain(self):
        sm = ScopeManager(target="example.com")
        assert sm.in_scope("evil.com") is False
        assert sm.in_scope("notexample.com") is False

    def test_excluded_domain(self):
        sm = ScopeManager(
            target="example.com",
            excluded=["staging.example.com"],
        )
        assert sm.in_scope("staging.example.com") is False
        assert sm.in_scope("api.example.com") is True

    def test_wildcard_excluded(self):
        sm = ScopeManager(
            target="example.com",
            excluded=["*.dev.example.com"],
        )
        assert sm.in_scope("test.dev.example.com") is False
        assert sm.in_scope("api.example.com") is True

    def test_custom_allowed_domains(self):
        sm = ScopeManager(
            target="example.com",
            allowed=["api.example.com", "*.staging.example.com"],
        )
        assert sm.in_scope("api.example.com") is True
        assert sm.in_scope("v2.staging.example.com") is True
        assert sm.in_scope("admin.example.com") is False

    def test_wildcard_scope(self):
        sm = ScopeManager(target="sub.example.com", wildcard_scope=True)
        # Should accept anything under example.com
        assert sm.in_scope("other.example.com") is True
        assert sm.in_scope("deep.sub.example.com") is True

    def test_filter_list(self):
        sm = ScopeManager(
            target="example.com",
            excluded=["test.example.com"],
        )
        domains = ["api.example.com", "test.example.com", "evil.com", "www.example.com"]
        filtered = sm.filter(domains)
        assert "api.example.com" in filtered
        assert "www.example.com" in filtered
        assert "test.example.com" not in filtered
        assert "evil.com" not in filtered

    def test_add_allowed(self):
        sm = ScopeManager(target="example.com", allowed=["api.example.com"])
        sm.add_allowed("admin.example.com")
        assert sm.in_scope("admin.example.com") is True

    def test_add_excluded(self):
        sm = ScopeManager(target="example.com")
        sm.add_excluded("staging.example.com")
        assert sm.in_scope("staging.example.com") is False

    def test_case_insensitive(self):
        sm = ScopeManager(target="Example.COM")
        assert sm.in_scope("API.EXAMPLE.COM") is True


class TestRootDomain:
    def test_two_labels(self):
        assert _root_domain("example.com") == "example.com"

    def test_three_labels(self):
        assert _root_domain("sub.example.com") == "example.com"

    def test_deep_subdomain(self):
        assert _root_domain("a.b.c.example.com") == "example.com"
