"""
Tests for RECONYX v2.0 — Full Reconnaissance Pipeline Integration.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from reconyx.config import ReconConfig
from reconyx.engine import ReconEngine


@pytest.mark.asyncio
async def test_full_pipeline_execution_without_probe(tmp_path):
    """Test full pipeline when probing is skipped (not authorised)."""
    config = ReconConfig(
        target="example.com",
        output_base=str(tmp_path),
        probe_authorised=False,
    )

    engine = ReconEngine(config)

    # Mock sources to return deterministic results
    mock_findings = {
        "crtsh": ["api.example.com", "dev.example.com"],
        "alienvault": ["dev.example.com", "admin.example.com"],
    }

    with patch.object(engine, "_run_sources", return_value=mock_findings):
        stats = await engine.run()

    assert stats["target"] == "example.com"
    assert stats["unique"] == 3  # api, dev, admin
    assert stats["total_raw"] == 4
    assert stats["live_count"] == 0

    recon_file = tmp_path / "example.com" / "recon.txt"
    assert recon_file.exists()
    lines = recon_file.read_text().strip().splitlines()
    assert lines == ["admin.example.com", "api.example.com", "dev.example.com"]

    summary_file = tmp_path / "example.com" / "scan_summary.json"
    assert summary_file.exists()


@pytest.mark.asyncio
async def test_full_pipeline_execution_with_authorised_probe(tmp_path):
    """Test full pipeline with active HTTPX probing authorised."""
    config = ReconConfig(
        target="example.com",
        output_base=str(tmp_path),
        probe_authorised=True,
    )

    engine = ReconEngine(config)

    mock_findings = {
        "crtsh": ["api.example.com", "admin.example.com"],
    }

    mock_probe_result = {
        "available": True,
        "results": [
            {"url": "https://api.example.com", "host": "api.example.com", "status_code": 200},
        ],
        "live_urls": ["https://api.example.com"],
        "live_hosts": ["api.example.com"],
        "json_lines": ['{"url": "https://api.example.com", "status_code": 200}'],
    }

    with patch.object(engine, "_run_sources", return_value=mock_findings), \
         patch("reconyx.engine.probe_subdomains", return_value=mock_probe_result):
        stats = await engine.run()

    assert stats["unique"] == 2
    assert stats["live_count"] == 1

    out_dir = tmp_path / "example.com"
    assert (out_dir / "recon.txt").exists()
    assert (out_dir / "live.txt").exists()
    assert (out_dir / "live_hosts.txt").exists()
    assert (out_dir / "httpx_results.jsonl").exists()
    assert (out_dir / "scan_summary.json").exists()

    live_lines = (out_dir / "live.txt").read_text().strip().splitlines()
    assert live_lines == ["https://api.example.com"]

    live_hosts_lines = (out_dir / "live_hosts.txt").read_text().strip().splitlines()
    assert live_hosts_lines == ["api.example.com"]


@pytest.mark.asyncio
async def test_full_pipeline_with_no_probe_flag(tmp_path):
    """Test full pipeline explicitly passing no_probe=True."""
    config = ReconConfig(
        target="example.com",
        output_base=str(tmp_path),
        probe_authorised=True,
        no_probe=True,
    )

    engine = ReconEngine(config)
    mock_findings = {"crtsh": ["api.example.com"]}

    with patch.object(engine, "_run_sources", return_value=mock_findings), \
         patch("reconyx.engine.probe_subdomains") as mock_probe:
        stats = await engine.run()

    # Probe should not be called at all
    mock_probe.assert_not_called()
    assert stats["live_count"] == 0


@pytest.mark.asyncio
async def test_full_pipeline_source_status_counts_and_amass_skip(tmp_path):
    """Test that scan_summary records accurate 6-state status breakdown and Amass is skipped by default."""
    config = ReconConfig(
        target="example.com",
        output_base=str(tmp_path),
        probe_authorised=False,
    )

    engine = ReconEngine(config)

    # Let _run_sources execute with mocked source modules
    with patch("reconyx.engine.tool_available", return_value=True), \
         patch("reconyx.modules.crtsh.enumerate", new=AsyncMock(return_value=["sub1.example.com"])), \
         patch("reconyx.modules.alienvault.enumerate", new=AsyncMock(return_value=[])), \
         patch("reconyx.modules.wayback.enumerate", new=AsyncMock(side_effect=RuntimeError("API down"))), \
         patch("reconyx.modules.commoncrawl.enumerate", new=AsyncMock(side_effect=TimeoutError("Timed out"))):

        # Configure only these sources to keep test fast and focused
        config.sources = {
            "crtsh": True,
            "alienvault": True,
            "wayback": True,
            "commoncrawl": True,
            "amass": False,
        }

        stats = await engine.run()

    summary_file = tmp_path / "example.com" / "scan_summary.json"
    assert summary_file.exists()

    import json
    data = json.loads(summary_file.read_text())
    assert "status_counts" in data
    assert data["status_counts"]["SUCCESS"] == 1   # crtsh
    assert data["status_counts"]["EMPTY"] == 1     # alienvault
    assert data["status_counts"]["FAILED"] == 1    # wayback
    assert data["status_counts"]["TIMEOUT"] == 1   # commoncrawl
    assert data["status_counts"]["SKIPPED"] >= 1   # amass is skipped (optional)


@pytest.mark.asyncio
async def test_full_pipeline_preserves_previous_recon_txt_on_zero_findings(tmp_path):
    """Verify previous recon.txt is preserved when a scan yields 0 findings, and counts distinguish saved file vs scan findings."""
    config = ReconConfig(
        target="example.com",
        output_base=str(tmp_path),
        probe_authorised=False,
    )

    # Pre-populate recon.txt with existing findings
    target_dir = tmp_path / "example.com"
    target_dir.mkdir(parents=True)
    recon_file = target_dir / "recon.txt"
    recon_file.write_text("old1.example.com\nold2.example.com\n")

    engine = ReconEngine(config)

    # Emulate a scan where all sources return 0 findings
    with patch.object(engine, "_run_sources", return_value={}):
        stats = await engine.run()

    # The current scan discovered 0 unique subdomains
    assert stats["unique"] == 0
    # But recon.txt was preserved and not wiped!
    preserved = engine.output.read_lines("recon.txt")
    assert len(preserved) == 2
    assert "old1.example.com" in preserved
    assert "old2.example.com" in preserved
