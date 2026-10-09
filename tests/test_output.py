"""
Tests for RECONYX v2.0 — Output file management and directory creation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from reconyx.output import OutputManager, build_scan_summary, build_summary


class TestOutputManager:
    @pytest.fixture
    def manager(self, tmp_path):
        return OutputManager(base_dir=tmp_path, target="example.com")

    def test_creates_directory(self, tmp_path):
        out = OutputManager(base_dir=tmp_path, target="test.com")
        assert (tmp_path / "test.com").is_dir()

    def test_write_lines(self, manager):
        lines = ["api.example.com", "www.example.com", "mail.example.com"]
        dest = manager.write_lines("recon.txt", lines)
        assert dest.exists()
        content = dest.read_text().strip().splitlines()
        assert "api.example.com" in content
        assert "mail.example.com" in content

    def test_write_lines_sorted(self, manager):
        lines = ["z.example.com", "a.example.com", "m.example.com"]
        dest = manager.write_lines("recon.txt", lines)
        content = dest.read_text().strip().splitlines()
        assert content == sorted(lines)

    def test_write_lines_dedup(self, manager):
        lines = ["a.example.com", "a.example.com", "b.example.com"]
        dest = manager.write_lines("recon.txt", lines)
        content = dest.read_text().strip().splitlines()
        assert content.count("a.example.com") == 1

    def test_overwrite_safety_preserves_non_empty_recon_txt(self, manager):
        """Never overwrite previous results with empty files after a failed scan."""
        initial = ["api.example.com", "admin.example.com"]
        manager.save_subdomains(initial)
        assert len(manager.read_lines("recon.txt")) == 2

        # A failed scan produces 0 findings
        manager.save_subdomains([])
        # Verify previous findings were protected and preserved!
        preserved = manager.read_lines("recon.txt")
        assert len(preserved) == 2
        assert "api.example.com" in preserved

    def test_save_live_urls(self, manager):
        urls = ["https://api.example.com", "https://www.example.com"]
        dest = manager.save_live_urls(urls)
        assert dest.name == "live.txt"
        assert sorted(dest.read_text().strip().splitlines()) == sorted(urls)

    def test_save_live_hosts(self, manager):
        hosts = ["api.example.com", "www.example.com"]
        dest = manager.save_live_hosts(hosts)
        assert dest.name == "live_hosts.txt"
        assert sorted(dest.read_text().strip().splitlines()) == sorted(hosts)

    def test_save_httpx_jsonl(self, manager):
        data = [
            {"url": "https://api.example.com", "status_code": 200},
            {"url": "https://www.example.com", "status_code": 301},
        ]
        dest = manager.save_httpx_jsonl(data)
        assert dest.name == "httpx_results.jsonl"
        lines = [json.loads(l) for l in dest.read_text().strip().splitlines()]
        assert len(lines) == 2
        assert lines[0]["url"] == "https://api.example.com"

    def test_save_scan_summary(self, manager):
        summary = build_scan_summary(
            target="example.com",
            total_raw=100,
            unique=50,
            new=10,
            sources_attempted=8,
            sources_ok=7,
            sources_fail=1,
            per_source_counts={"crtsh": 30, "subfinder": 40},
            failures={"amass": "Tool not installed"},
            live_count=15,
            elapsed="5.2s",
            output_dir=str(manager.base),
        )
        dest = manager.save_scan_summary(summary)
        assert dest.name == "scan_summary.json"
        loaded = json.loads(dest.read_text())
        assert loaded["target"] == "example.com"
        assert loaded["unique_subdomains"] == 50
        assert loaded["live_websites"] == 15
        assert loaded["sources_successful"] == 7
        assert "timestamp" in loaded

    def test_previous_subdomains_reads_recon_txt(self, manager):
        subs = ["api.example.com", "www.example.com"]
        manager.save_subdomains(subs)
        result = manager.previous_subdomains()
        assert set(result) == set(subs)

    def test_archive_previous(self, manager):
        subs = ["api.example.com"]
        manager.save_subdomains(subs)
        backup = manager.archive_previous("recon.txt")
        assert backup is not None
        assert backup.exists()
        assert backup.name != "recon.txt"
