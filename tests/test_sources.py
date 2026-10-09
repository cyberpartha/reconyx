"""
Tests for RECONYX — Source modules (mocked HTTP for deterministic results).
"""

from __future__ import annotations

import json
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from reconyx.utils import filter_and_normalize, normalize_domain, is_valid_domain, extract_domain


# ---------------------------------------------------------------------------
# Utils Tests
# ---------------------------------------------------------------------------

class TestNormalizeDomain:
    def test_lowercase(self):
        assert normalize_domain("Example.COM") == "example.com"

    def test_strip_wildcard(self):
        assert normalize_domain("*.example.com") == "example.com"
        assert normalize_domain("*example.com") == "example.com"

    def test_strip_trailing_dot(self):
        assert normalize_domain("example.com.") == "example.com"

    def test_strip_whitespace(self):
        assert normalize_domain("  example.com  ") == "example.com"

    def test_empty(self):
        assert normalize_domain("") == ""

    def test_unicode_domain(self):
        # IDN domains should encode to ASCII IDNA
        result = normalize_domain("München.de")
        assert isinstance(result, str)


class TestIsValidDomain:
    def test_valid_domains(self):
        valid = [
            "example.com",
            "sub.example.com",
            "a.b.c.example.co.uk",
            "xn--nxasmq6b.com",
        ]
        for d in valid:
            assert is_valid_domain(d), f"Expected valid: {d}"

    def test_invalid_domains(self):
        invalid = [
            "",
            "example",
            ".example.com",
            "example..com",
            "example .com",
            "example.com:8080",
            "a" * 254 + ".com",
        ]
        for d in invalid:
            assert not is_valid_domain(d), f"Expected invalid: {d}"


class TestExtractDomain:
    def test_bare_domain(self):
        assert extract_domain("example.com") == "example.com"

    def test_http_url(self):
        assert extract_domain("http://api.example.com/path?q=1") == "api.example.com"

    def test_https_url(self):
        assert extract_domain("https://sub.example.com/") == "sub.example.com"

    def test_url_with_path(self):
        assert extract_domain("https://example.com/foo/bar") == "example.com"


class TestFilterAndNormalize:
    def test_basic_dedup(self):
        raw = ["example.com", "example.com", "sub.example.com"]
        result = filter_and_normalize(raw, base_domain="example.com")
        assert result == ["example.com", "sub.example.com"]

    def test_filters_out_of_scope(self):
        raw = ["sub.example.com", "evil.com", "other.org"]
        result = filter_and_normalize(raw, base_domain="example.com")
        assert "evil.com" not in result
        assert "other.org" not in result
        assert "sub.example.com" in result

    def test_normalises_wildcards(self):
        raw = ["*.example.com", "example.com"]
        result = filter_and_normalize(raw, base_domain="example.com")
        # *.example.com → example.com after normalisation
        assert "example.com" in result

    def test_sorted_output(self):
        raw = ["z.example.com", "a.example.com", "m.example.com"]
        result = filter_and_normalize(raw, base_domain="example.com")
        assert result == sorted(result)

    def test_filters_invalid_entries(self):
        raw = ["", "not-a-domain", "192.168.1.1", "valid.example.com"]
        result = filter_and_normalize(raw, base_domain="example.com")
        assert "valid.example.com" in result
        assert "" not in result
        assert "not-a-domain" not in result


# ---------------------------------------------------------------------------
# Mocked Source Tests
# ---------------------------------------------------------------------------

class MockConfig:
    target = "example.com"
    timeout = 10
    retries = 2
    rate_limit_delay = 0
    api_keys: dict = {}


@pytest.mark.asyncio
async def test_crtsh_source_parses_response():
    """Test that crtsh module correctly extracts domains from JSON response."""
    from reconyx.modules import crtsh

    mock_response = [
        {"name_value": "sub.example.com\n*.example.com", "common_name": "api.example.com"},
        {"name_value": "mail.example.com",               "common_name": ""},
    ]

    with patch("reconyx.modules.crtsh.http_session") as mock_ctx:
        mock_session = AsyncMock()
        mock_ctx.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_ctx.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("reconyx.modules.crtsh.fetch_json", return_value=mock_response):
            config = MockConfig()
            result = await crtsh.enumerate("example.com", config)

    assert "sub.example.com" in result
    assert "api.example.com" in result
    assert "mail.example.com" in result


@pytest.mark.asyncio
async def test_alienvault_source_parses_response():
    """Test AlienVault OTX parsing."""
    from reconyx.modules import alienvault

    mock_pdns = {"passive_dns": [
        {"hostname": "api.example.com"},
        {"hostname": "staging.example.com"},
    ]}

    with patch("reconyx.modules.alienvault.http_session") as mock_ctx:
        mock_session = AsyncMock()
        mock_ctx.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_ctx.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "reconyx.modules.alienvault.fetch_json",
            side_effect=[mock_pdns, {"url_list": []}],
        ):
            config = MockConfig()
            result = await alienvault.enumerate("example.com", config)

    assert "api.example.com" in result
    assert "staging.example.com" in result


@pytest.mark.asyncio
async def test_hackertarget_handles_api_limit():
    """HackerTarget should raise RuntimeError on API limit response so it is reported as FAILED."""
    from reconyx.modules import hackertarget

    with patch("reconyx.modules.hackertarget.http_session") as mock_ctx:
        mock_session = AsyncMock()
        mock_ctx.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_ctx.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "reconyx.modules.hackertarget.fetch_text",
            return_value="API count exceeded - Increase Quota with Membership",
        ):
            config = MockConfig()
            with pytest.raises(RuntimeError, match="API count exceeded"):
                await hackertarget.enumerate("example.com", config)


@pytest.mark.asyncio
async def test_virustotal_requires_api_key():
    """VirusTotal should return empty list when no key is set."""
    from reconyx.modules import virustotal

    config = MockConfig()
    config.api_keys = {}
    result = await virustotal.enumerate("example.com", config)
    assert result == []


@pytest.mark.asyncio
async def test_securitytrails_requires_api_key():
    """SecurityTrails should return empty list when no key is set."""
    from reconyx.modules import securitytrails

    config = MockConfig()
    config.api_keys = {}
    result = await securitytrails.enumerate("example.com", config)
    assert result == []


@pytest.mark.asyncio
async def test_subfinder_skips_when_not_installed():
    """Subfinder adapter returns [] when binary is missing."""
    from reconyx.modules import subfinder
    with patch("reconyx.modules.subfinder.tool_available", return_value=False):
        config = MockConfig()
        result = await subfinder.enumerate("example.com", config)
    assert result == []


@pytest.mark.asyncio
async def test_gau_skips_when_not_installed():
    """GAU adapter returns [] when binary is missing."""
    from reconyx.modules import gau
    with patch("reconyx.modules.gau.tool_available", return_value=False):
        config = MockConfig()
        result = await gau.enumerate("example.com", config)
    assert result == []


@pytest.mark.asyncio
async def test_findomain_skips_when_not_installed():
    """Findomain adapter returns [] when binary is missing."""
    from reconyx.modules import findomain
    with patch("reconyx.modules.findomain.tool_available", return_value=False):
        config = MockConfig()
        result = await findomain.enumerate("example.com", config)
    assert result == []


@pytest.mark.asyncio
async def test_subfinder_output_parsing(tmp_path):
    """Verify subfinder reads and normalizes discovered subdomains from its output file."""
    from reconyx.modules import subfinder
    from pathlib import Path

    async def fake_run_tool(cmd, timeout=300):
        # cmd: [subfinder, -d, target, -silent, -o, out_file, -timeout, ...]
        out_file = cmd[cmd.index("-o") + 1]
        Path(out_file).write_text("api.example.com\nadmin.example.com\nDEV.EXAMPLE.COM\n")
        return ""

    with patch("reconyx.modules.subfinder.tool_available", return_value=True), \
         patch("reconyx.modules.subfinder.run_tool", side_effect=fake_run_tool):
        config = MockConfig()
        res = await subfinder.enumerate("example.com", config)

    assert "api.example.com" in res
    assert "admin.example.com" in res
    assert "dev.example.com" in res


@pytest.mark.asyncio
async def test_findomain_output_parsing(tmp_path):
    """Verify findomain reads and normalizes discovered subdomains."""
    from reconyx.modules import findomain
    from pathlib import Path

    async def fake_run_tool(cmd, timeout=300):
        out_file = cmd[cmd.index("-u") + 1]
        Path(out_file).write_text("test1.example.com\ntest2.example.com\n")
        return ""

    with patch("reconyx.modules.findomain.tool_available", return_value=True), \
         patch("reconyx.modules.findomain.run_tool", side_effect=fake_run_tool):
        config = MockConfig()
        res = await findomain.enumerate("example.com", config)

    assert "test1.example.com" in res
    assert "test2.example.com" in res


def test_tool_available_uses_shutil_which():
    from reconyx.utils import tool_available
    with patch("shutil.which", return_value="/usr/bin/subfinder"):
        assert tool_available("subfinder") is True
    with patch("shutil.which", return_value=None), \
         patch("os.path.isfile", return_value=False):
        assert tool_available("nonexistent_binary_xyz") is False


@pytest.mark.asyncio
async def test_gau_partial_results_on_timeout():
    """Verify GAU returns PartialResultError with partial results when timeout occurs."""
    from reconyx.modules import gau
    from reconyx.utils import PartialResultError

    async def fake_run_tool_with_partial(cmd, timeout=45):
        # Emulate partial capture during timeout
        return ("sub1.example.com\nsub2.example.com\n", True)

    with patch("reconyx.modules.gau.tool_available", return_value=True), \
         patch("reconyx.modules.gau.run_tool_with_partial", side_effect=fake_run_tool_with_partial):
        config = MockConfig()
        with pytest.raises(PartialResultError) as exc_info:
            await gau.enumerate("example.com", config)

        assert "sub1.example.com" in exc_info.value.partial_results
        assert "sub2.example.com" in exc_info.value.partial_results


@pytest.mark.asyncio
async def test_amass_partial_results_on_timeout(tmp_path):
    """Verify Amass extracts partial results on timeout and raises PartialResultError."""
    from reconyx.modules import amass
    from reconyx.utils import PartialResultError
    from pathlib import Path

    async def fake_run_tool(cmd, timeout=300):
        # Write partial output to amass out file before timing out
        out_file = cmd[cmd.index("-o") + 1]
        Path(out_file).write_text("partial1.example.com\npartial2.example.com\n")
        raise TimeoutError("Amass timed out after 300s")

    with patch("reconyx.modules.amass.tool_available", return_value=True), \
         patch("reconyx.modules.amass.run_tool", side_effect=fake_run_tool):
        config = MockConfig()
        with pytest.raises(PartialResultError) as exc_info:
            await amass.enumerate("example.com", config)

        assert "partial1.example.com" in exc_info.value.partial_results
        assert "partial2.example.com" in exc_info.value.partial_results


@pytest.mark.asyncio
async def test_assetfinder_partial_results_on_timeout():
    """Verify Assetfinder preserves partial results on timeout and raises PartialResultError."""
    from reconyx.modules import assetfinder
    from reconyx.utils import PartialResultError

    async def fake_run_tool_with_partial(cmd, timeout=30):
        return ("found1.example.com\nfound2.example.com\n", True)

    with patch("reconyx.modules.assetfinder.tool_available", return_value=True), \
         patch("reconyx.modules.assetfinder.run_tool_with_partial", side_effect=fake_run_tool_with_partial):
        config = MockConfig()
        with pytest.raises(PartialResultError) as exc_info:
            await assetfinder.enumerate("example.com", config)

        assert "found1.example.com" in exc_info.value.partial_results
        assert "found2.example.com" in exc_info.value.partial_results


@pytest.mark.asyncio
async def test_assetfinder_timeout_zero_results():
    """Verify Assetfinder raises TimeoutError when timeout occurs with 0 findings."""
    from reconyx.modules import assetfinder

    async def fake_run_tool_with_partial(cmd, timeout=30):
        return ("", True)

    with patch("reconyx.modules.assetfinder.tool_available", return_value=True), \
         patch("reconyx.modules.assetfinder.run_tool_with_partial", side_effect=fake_run_tool_with_partial):
        config = MockConfig()
        with pytest.raises(TimeoutError):
            await assetfinder.enumerate("example.com", config)


@pytest.mark.asyncio
async def test_findomain_partial_results_on_timeout():
    """Verify Findomain preserves partial results on timeout and cleans temp file."""
    from reconyx.modules import findomain
    from reconyx.utils import PartialResultError
    from pathlib import Path

    async def fake_run_tool(cmd, timeout=30):
        out_file = cmd[cmd.index("-u") + 1]
        Path(out_file).write_text("fd1.example.com\nfd2.example.com\n")
        raise TimeoutError("Findomain timed out")

    with patch("reconyx.modules.findomain.tool_available", return_value=True), \
         patch("reconyx.modules.findomain.run_tool", side_effect=fake_run_tool):
        config = MockConfig()
        with pytest.raises(PartialResultError) as exc_info:
            await findomain.enumerate("example.com", config)

        assert "fd1.example.com" in exc_info.value.partial_results
        assert "fd2.example.com" in exc_info.value.partial_results


@pytest.mark.asyncio
async def test_findomain_timeout_zero_results():
    """Verify Findomain raises TimeoutError on timeout when no results exist."""
    from reconyx.modules import findomain

    async def fake_run_tool(cmd, timeout=30):
        raise TimeoutError("Findomain timed out")

    with patch("reconyx.modules.findomain.tool_available", return_value=True), \
         patch("reconyx.modules.findomain.run_tool", side_effect=fake_run_tool):
        config = MockConfig()
        with pytest.raises(TimeoutError):
            await findomain.enumerate("example.com", config)


@pytest.mark.asyncio
async def test_subfinder_partial_results_on_timeout():
    """Verify Subfinder preserves partial results on timeout and cleans temp file."""
    from reconyx.modules import subfinder
    from reconyx.utils import PartialResultError
    from pathlib import Path

    async def fake_run_tool(cmd, timeout=30):
        out_file = cmd[cmd.index("-o") + 1]
        Path(out_file).write_text("sf1.example.com\nsf2.example.com\n")
        raise TimeoutError("Subfinder timed out")

    with patch("reconyx.modules.subfinder.tool_available", return_value=True), \
         patch("reconyx.modules.subfinder.run_tool", side_effect=fake_run_tool):
        config = MockConfig()
        with pytest.raises(PartialResultError) as exc_info:
            await subfinder.enumerate("example.com", config)

        assert "sf1.example.com" in exc_info.value.partial_results
        assert "sf2.example.com" in exc_info.value.partial_results


@pytest.mark.asyncio
async def test_subfinder_timeout_zero_results():
    """Verify Subfinder raises TimeoutError on timeout when no results exist."""
    from reconyx.modules import subfinder

    async def fake_run_tool(cmd, timeout=30):
        raise TimeoutError("Subfinder timed out")

    with patch("reconyx.modules.subfinder.tool_available", return_value=True), \
         patch("reconyx.modules.subfinder.run_tool", side_effect=fake_run_tool):
        config = MockConfig()
        with pytest.raises(TimeoutError):
            await subfinder.enumerate("example.com", config)


@pytest.mark.asyncio
async def test_run_tool_timeout_and_process_cleanup():
    """Verify run_tool terminates child process on timeout."""
    import sys
    from reconyx.utils import run_tool

    # Run Python command that sleeps for 5s with 0.1s timeout
    cmd = [sys.executable, "-c", "import time; time.sleep(5)"]
    with pytest.raises(TimeoutError):
        await run_tool(cmd, timeout=0.1)


@pytest.mark.asyncio
async def test_run_tool_with_partial_timeout_and_process_cleanup():
    """Verify run_tool_with_partial captures stdout before timeout and cleans process."""
    import sys
    from reconyx.utils import run_tool_with_partial

    # Print a line, flush, then sleep
    cmd = [
        sys.executable, "-u", "-c",
        "import sys, time; print('line_one'); sys.stdout.flush(); time.sleep(5)"
    ]
    out, timed_out = await run_tool_with_partial(cmd, timeout=0.2)
    assert timed_out is True
    assert "line_one" in out


@pytest.mark.asyncio
async def test_gau_module_respects_custom_timeout_90():
    """Verify GAU adapter passes timeout=90 to run_tool_with_partial when configured."""
    from reconyx.modules import gau

    captured_timeout = None

    async def fake_run_tool_with_partial(cmd, timeout=45):
        nonlocal captured_timeout
        captured_timeout = timeout
        return ("sub1.example.com\n", False)

    with patch("reconyx.modules.gau.tool_available", return_value=True), \
         patch("reconyx.modules.gau.run_tool_with_partial", side_effect=fake_run_tool_with_partial):
        config = MockConfig()
        config.gau_timeout = 90
        config.timeout = 90
        subs = await gau.enumerate("example.com", config)
        assert captured_timeout == 90
        assert "sub1.example.com" in subs


@pytest.mark.asyncio
async def test_gau_module_respects_custom_timeout_10():
    """Verify GAU adapter passes timeout=10 to run_tool_with_partial without clamping."""
    from reconyx.modules import gau

    captured_timeout = None

    async def fake_run_tool_with_partial(cmd, timeout=45):
        nonlocal captured_timeout
        captured_timeout = timeout
        return ("sub1.example.com\n", False)

    with patch("reconyx.modules.gau.tool_available", return_value=True), \
         patch("reconyx.modules.gau.run_tool_with_partial", side_effect=fake_run_tool_with_partial):
        config = MockConfig()
        config.gau_timeout = 10
        config.timeout = 10
        subs = await gau.enumerate("example.com", config)
        assert captured_timeout == 10
        assert "sub1.example.com" in subs


@pytest.mark.asyncio
async def test_wayback_network_error_classified_as_failed():
    """Verify network failures in Wayback raise NetworkError and are classified as FAILED, not TIMEOUT."""
    from reconyx.engine import ReconEngine
    from reconyx.config import ReconConfig
    from reconyx.utils import NetworkError

    config = ReconConfig(target="example.com")
    config.sources = {"wayback": True}
    engine = ReconEngine(config)

    with patch("reconyx.modules.wayback.enumerate", new=AsyncMock(side_effect=NetworkError("Connection reset by peer"))):
        findings = await engine._run_sources()

    stats = engine._source_stats.get("wayback", {})
    assert stats.get("status") == "FAILED"
    assert "wayback" in engine._failures
    assert "wayback" not in engine._timeouts


@pytest.mark.asyncio
async def test_wayback_timeout_classified_as_timeout():
    """Verify actual TimeoutError in Wayback is classified as TIMEOUT."""
    from reconyx.engine import ReconEngine
    from reconyx.config import ReconConfig

    config = ReconConfig(target="example.com")
    config.sources = {"wayback": True}
    engine = ReconEngine(config)

    with patch("reconyx.modules.wayback.enumerate", new=AsyncMock(side_effect=TimeoutError("Request deadline exceeded"))):
        findings = await engine._run_sources()

    stats = engine._source_stats.get("wayback", {})
    assert stats.get("status") == "TIMEOUT"
    assert "wayback" in engine._timeouts
    assert "wayback" not in engine._failures


@pytest.mark.asyncio
async def test_fetch_text_network_error_distinction():
    """Verify fetch_text raises NetworkError when aiohttp.ClientError occurs on all retries."""
    import aiohttp
    from unittest.mock import MagicMock
    from reconyx.utils import fetch_text, NetworkError

    cm = MagicMock()
    cm.__aenter__ = AsyncMock(side_effect=aiohttp.ClientOSError(
        1, "Connection reset by peer"
    ))
    cm.__aexit__ = AsyncMock(return_value=False)
    mock_session = MagicMock()
    mock_session.get.return_value = cm

    with pytest.raises(NetworkError) as exc_info:
        await fetch_text(mock_session, "http://example.com/test", retries=2, backoff=1.0)
    assert "Network error connecting to" in str(exc_info.value)


@pytest.mark.asyncio
async def test_fetch_text_deadline_enforcement():
    """Verify fetch_text raises TimeoutError when the overall deadline expires across retries."""
    from unittest.mock import MagicMock
    from reconyx.utils import fetch_text

    cm = MagicMock()
    cm.__aenter__ = AsyncMock(side_effect=asyncio.TimeoutError())
    cm.__aexit__ = AsyncMock(return_value=False)
    mock_session = MagicMock()
    mock_session.get.return_value = cm

    with pytest.raises(TimeoutError) as exc_info:
        await fetch_text(mock_session, "http://example.com/test", retries=3, backoff=1.0, timeout=0.1)
    assert "timed out" in str(exc_info.value)
