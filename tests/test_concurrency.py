"""
Tests for RECONYX v2.0.3 Concurrency, Timeout Enforcement & Status Handling.
Deterministic tests using simulated sources with monotonic timestamps.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from rich.console import Console

from reconyx.config import ReconConfig
from reconyx.console import get_console, set_console
from reconyx.engine import ReconEngine
from reconyx.utils import PartialResultError, setup_logging


class MockConfig(ReconConfig):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.target = "example.com"
        self.timeout = 5
        self.concurrency = 10
        self.no_probe = True


@pytest.mark.asyncio
async def test_deterministic_concurrency_execution(tmp_path):
    """
    Verify that two concurrent sources each taking ~0.20s finish in
    substantially less than 0.40s (sequential execution).
    """
    config = MockConfig()
    config.output_base = str(tmp_path)
    engine = ReconEngine(config)

    async def slow_source_1(target, cfg):
        await asyncio.sleep(0.20)
        return ["s1.example.com"]

    async def slow_source_2(target, cfg):
        await asyncio.sleep(0.20)
        return ["s2.example.com"]

    with patch("reconyx.modules.crtsh.enumerate", new=slow_source_1), \
         patch("reconyx.modules.alienvault.enumerate", new=slow_source_2):

        config.sources = {
            "crtsh": True,
            "alienvault": True,
            "amass": False,
        }

        t_start = time.perf_counter()
        stats = await engine.run()
        elapsed = time.perf_counter() - t_start

    # Concurrency verification:
    # Sequentially they would take >= 0.40s.
    # Concurrently they should complete in substantially less than 0.40s (e.g. < 0.35s).
    assert elapsed < 0.35, f"Execution took {elapsed:.2f}s, expected < 0.35s for concurrent tasks"
    assert stats["unique"] == 2
    assert "s1.example.com" in (tmp_path / "example.com" / "recon.txt").read_text()
    assert "s2.example.com" in (tmp_path / "example.com" / "recon.txt").read_text()


@pytest.mark.asyncio
async def test_slow_source_does_not_block_fast_source(tmp_path):
    """
    Verify that a slow or timed-out source does not prevent successful sources
    from saving their findings.
    """
    config = MockConfig()
    config.output_base = str(tmp_path)
    config.timeout = 1  # 1s per-source timeout
    engine = ReconEngine(config)

    async def fast_source(target, cfg):
        await asyncio.sleep(0.05)
        return ["fast.example.com"]

    async def hanging_source(target, cfg):
        await asyncio.sleep(10.0)  # Simulates hanging API
        return ["slow.example.com"]

    with patch("reconyx.modules.crtsh.enumerate", new=fast_source), \
         patch("reconyx.modules.alienvault.enumerate", new=hanging_source):

        config.sources = {
            "crtsh": True,
            "alienvault": True,
            "amass": False,
        }

        stats = await engine.run()

    summary_file = tmp_path / "example.com" / "scan_summary.json"
    assert summary_file.exists()
    summary = json.loads(summary_file.read_text())

    # Fast source findings are preserved
    recon_file = tmp_path / "example.com" / "recon.txt"
    assert "fast.example.com" in recon_file.read_text()
    assert stats["status_counts"]["SUCCESS"] == 1
    assert stats["status_counts"]["TIMEOUT"] == 1


@pytest.mark.asyncio
async def test_all_six_source_status_classifications(tmp_path):
    """
    Verify exact status classification across SUCCESS, EMPTY, PARTIAL, TIMEOUT, FAILED, SKIPPED
    in both memory and scan_summary.json.
    """
    config = MockConfig()
    config.output_base = str(tmp_path)
    engine = ReconEngine(config)

    async def mock_success(target, cfg):
        return ["valid1.example.com", "valid2.example.com"]

    async def mock_empty(target, cfg):
        return []

    async def mock_partial(target, cfg):
        raise PartialResultError(["partial.example.com"], "Preserved before timeout")

    async def mock_timeout(target, cfg):
        raise TimeoutError("Deadline exceeded")

    async def mock_failed(target, cfg):
        raise RuntimeError("Database connection reset")

    with patch("reconyx.modules.crtsh.enumerate", new=mock_success), \
         patch("reconyx.modules.alienvault.enumerate", new=mock_empty), \
         patch("reconyx.modules.wayback.enumerate", new=mock_partial), \
         patch("reconyx.modules.commoncrawl.enumerate", new=mock_timeout), \
         patch("reconyx.modules.hackertarget.enumerate", new=mock_failed):

        config.sources = {
            "crtsh": True,
            "alienvault": True,
            "wayback": True,
            "commoncrawl": True,
            "hackertarget": True,
            "amass": False,  # SKIPPED
        }

        stats = await engine.run()

    summary_file = tmp_path / "example.com" / "scan_summary.json"
    summary = json.loads(summary_file.read_text())

    # Verify status counts in memory stats and json summary
    counts = summary["status_counts"]
    assert counts["SUCCESS"] == 1
    assert counts["EMPTY"] == 1
    assert counts["PARTIAL"] == 1
    assert counts["TIMEOUT"] == 1
    assert counts["FAILED"] == 1
    assert counts["SKIPPED"] >= 1  # Amass is skipped

    # Verify failures dict only holds genuine failures (hackertarget), not timeouts
    assert "hackertarget" in summary["failures"]
    assert "commoncrawl" not in summary["failures"]

    # Verify timeouts dict holds timed-out source
    assert "commoncrawl" in summary["timeouts"]

    # Verify recon.txt contains both SUCCESS and PARTIAL findings
    recon_content = (tmp_path / "example.com" / "recon.txt").read_text()
    assert "valid1.example.com" in recon_content
    assert "partial.example.com" in recon_content


def test_shared_console_singleton():
    """Verify get_console() returns a consistent singleton instance."""
    c1 = get_console()
    c2 = get_console()
    assert c1 is c2
    assert isinstance(c1, Console)


def test_setup_logging_no_duplicate_handlers(tmp_path):
    """Verify setup_logging does not duplicate handlers when called multiple times."""
    log_file = tmp_path / "reconyx.log"
    setup_logging("INFO", str(log_file))
    setup_logging("DEBUG", str(log_file))

    r_logger = logging.getLogger("reconyx")
    # Should have exactly 2 handlers (1 RichHandler + 1 FileHandler)
    assert len(r_logger.handlers) == 2
    r_logger.info("Test log message")

    assert log_file.exists()
    content = log_file.read_text(encoding="utf-8")
    assert "Test log message" in content


def test_cli_rejects_non_positive_timeout():
    """Verify CLI rejects --timeout <= 0."""
    from reconyx.cli import _run_recon

    cfg = MockConfig()
    cfg.timeout = 0
    with pytest.raises(SystemExit) as exc:
        _run_recon(cfg)
    assert exc.value.code == 1

    cfg.timeout = -10
    with pytest.raises(SystemExit) as exc:
        _run_recon(cfg)
    assert exc.value.code == 1
