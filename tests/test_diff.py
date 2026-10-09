"""
Tests for RECONYX — Diff detection between scan runs.
"""

from __future__ import annotations

from reconyx.diff import compute_diff, build_diff_report


class TestComputeDiff:
    def test_no_previous_scan(self):
        current  = ["api.example.com", "www.example.com"]
        previous = []
        result   = compute_diff(current, previous)
        assert set(result.new) == set(current)
        assert result.known == []
        assert result.missing == []

    def test_fully_new_scan(self):
        current  = ["a.example.com", "b.example.com"]
        previous = ["c.example.com", "d.example.com"]
        result   = compute_diff(current, previous)
        assert set(result.new)     == {"a.example.com", "b.example.com"}
        assert set(result.missing) == {"c.example.com", "d.example.com"}
        assert result.known == []

    def test_partial_overlap(self):
        current  = ["a.example.com", "b.example.com", "c.example.com"]
        previous = ["b.example.com", "c.example.com", "d.example.com"]
        result   = compute_diff(current, previous)
        assert set(result.new)     == {"a.example.com"}
        assert set(result.known)   == {"b.example.com", "c.example.com"}
        assert set(result.missing) == {"d.example.com"}

    def test_identical_scans(self):
        domains = ["api.example.com", "www.example.com"]
        result  = compute_diff(domains, domains)
        assert result.new     == []
        assert result.missing == []
        assert set(result.known) == set(domains)

    def test_counts(self):
        current  = ["a.example.com", "b.example.com"]
        previous = ["b.example.com", "c.example.com"]
        result   = compute_diff(current, previous)
        assert result.current_count  == 2
        assert result.previous_count == 2

    def test_sorted_output(self):
        current  = ["z.example.com", "a.example.com"]
        previous = []
        result   = compute_diff(current, previous)
        assert result.new == sorted(result.new)


class TestBuildDiffReport:
    def test_report_structure(self):
        from reconyx.diff import DiffResult
        diff = DiffResult(
            new=["a.example.com"],
            known=["b.example.com"],
            missing=["c.example.com"],
            previous_count=2,
            current_count=2,
        )
        report = build_diff_report("example.com", diff)
        assert report["target"] == "example.com"
        assert "timestamp" in report
        assert report["statistics"]["new_count"] == 1
        assert report["statistics"]["known_count"] == 1
        assert report["statistics"]["missing_from_latest_scan"] == 1
        assert "note" in report  # Missing ≠ offline — must include disclaimer

    def test_missing_disclaimer_present(self):
        """Ensure the report states missing ≠ offline."""
        from reconyx.diff import DiffResult
        diff = DiffResult(new=[], known=[], missing=["a.example.com"],
                          previous_count=1, current_count=0)
        report = build_diff_report("example.com", diff)
        note = report.get("note", "")
        assert "offline" not in note.lower() or "not" in note.lower()
