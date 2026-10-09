"""
Tests for RECONYX — ProjectDiscovery HTTPX Probing Module.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from reconyx.config import ReconConfig
from reconyx.modules.httpx_probe import (
    extract_probe_host,
    find_projectdiscovery_httpx,
    is_projectdiscovery_httpx,
    probe_subdomains,
)
from reconyx.output import OutputManager
from reconyx.engine import ReconEngine


class TestHttpxDetection:
    def test_detects_projectdiscovery_via_version(self):
        mock_result = MagicMock()
        mock_result.stdout = "httpx v1.6.8 (ProjectDiscovery)"
        mock_result.stderr = ""
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result), \
             patch("shutil.which", return_value="/usr/bin/httpx"):
            assert is_projectdiscovery_httpx("/usr/bin/httpx") is True

    def test_rejects_python_httpx_cli(self):
        mock_result = MagicMock()
        # Python httpx outputs "unrecognized arguments: -version" or "next generation HTTP client"
        mock_result.stdout = "HTTPX - A next generation HTTP client"
        mock_result.stderr = "error: unrecognized arguments: -version"
        mock_result.returncode = 2

        with patch("subprocess.run", return_value=mock_result), \
             patch("shutil.which", return_value="/usr/bin/httpx"):
            assert is_projectdiscovery_httpx("/usr/bin/httpx") is False

    def test_finds_httpx_toolkit_fallback(self):
        with patch("shutil.which") as mock_which, \
             patch("reconyx.modules.httpx_probe.is_projectdiscovery_httpx", side_effect=lambda p: "httpx-toolkit" in p):
            mock_which.side_effect = lambda name: "/usr/bin/httpx-toolkit" if name == "httpx-toolkit" else None
            found = find_projectdiscovery_httpx()
            assert found == "/usr/bin/httpx-toolkit"

    def test_missing_httpx_returns_none(self):
        with patch("shutil.which", return_value=None), \
             patch("os.path.isfile", return_value=False):
            assert find_projectdiscovery_httpx() is None


class TestHttpxProbing:
    @pytest.mark.asyncio
    async def test_empty_input_file_returns_empty_results(self, tmp_path):
        empty_recon = tmp_path / "recon.txt"
        empty_recon.write_text("")
        config = ReconConfig(target="example.com")

        res = await probe_subdomains(empty_recon, config)
        assert res["available"] is True
        assert res["results"] == []
        assert res["live_urls"] == []
        assert res["live_hosts"] == []

    @pytest.mark.asyncio
    async def test_missing_binary_returns_not_available(self, tmp_path):
        recon = tmp_path / "recon.txt"
        recon.write_text("api.example.com\n")
        config = ReconConfig(target="example.com")

        with patch("reconyx.modules.httpx_probe.find_projectdiscovery_httpx", return_value=None):
            res = await probe_subdomains(recon, config)
            assert res["available"] is False
            assert res["results"] == []

    @pytest.mark.asyncio
    async def test_parses_jsonl_output_correctly(self, tmp_path):
        recon = tmp_path / "recon.txt"
        recon.write_text("api.example.com\nwww.example.com\n")
        config = ReconConfig(target="example.com")

        sample_jsonl = "\n".join([
            json.dumps({
                "url": "https://api.example.com",
                "input": "api.example.com",
                "status_code": 200,
                "title": "API Gateway",
                "webserver": "nginx",
                "tech": ["nginx", "Express"],
            }),
            json.dumps({
                "url": "https://www.example.com",
                "final_url": "https://www.example.com/login",
                "input": "www.example.com",
                "status_code": 302,
                "title": "Welcome",
                "webserver": "cloudflare",
                "tech": ["Cloudflare"],
            }),
        ])

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(sample_jsonl.encode("utf-8"), b""))

        with patch("reconyx.modules.httpx_probe.find_projectdiscovery_httpx", return_value="/usr/bin/httpx"), \
             patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            res = await probe_subdomains(recon, config)

            assert res["available"] is True
            assert len(res["results"]) == 2
            assert "https://api.example.com" in res["live_urls"]
            assert "https://www.example.com" in res["live_urls"]
            assert "api.example.com" in res["live_hosts"]
            assert "www.example.com" in res["live_hosts"]
            assert res["results"][0]["title"] == "API Gateway"
            assert res["results"][0]["status_code"] == 200


class TestHostnameExtraction:
    def test_extract_probe_host_urls_with_ports(self):
        assert extract_probe_host("http://127.0.0.1:8765") == "127.0.0.1"
        assert extract_probe_host("https://sub.example.com:8443") == "sub.example.com"
        assert extract_probe_host("http://[::1]:8080") == "::1"
        assert extract_probe_host("https://admin.example.com:443/login?q=1") == "admin.example.com"
        assert extract_probe_host("http://example.com:80") == "example.com"

    def test_extract_probe_host_ipv4_and_ipv6(self):
        # IPv4
        assert extract_probe_host("127.0.0.1") == "127.0.0.1"
        assert extract_probe_host("192.168.1.1:8080") == "192.168.1.1"
        assert extract_probe_host("http://10.0.0.1:8000/dashboard") == "10.0.0.1"
        assert extract_probe_host("8.8.8.8") == "8.8.8.8"

        # IPv6
        assert extract_probe_host("::1") == "::1"
        assert extract_probe_host("[::1]") == "::1"
        assert extract_probe_host("[::1]:8080") == "::1"
        assert extract_probe_host("http://[::1]:8080") == "::1"
        assert extract_probe_host("2001:db8::1") == "2001:db8::1"
        assert extract_probe_host("[2001:db8::1]:8080") == "2001:db8::1"
        assert extract_probe_host("http://[2001:db8::1]:8080/path") == "2001:db8::1"

    def test_extract_probe_host_standard_subdomains(self):
        assert extract_probe_host("sub.example.com") == "sub.example.com"
        assert extract_probe_host("api.v1.example.com") == "api.v1.example.com"
        assert extract_probe_host("https://admin.example.com") == "admin.example.com"
        assert extract_probe_host("sub.example.com:8080") == "sub.example.com"
        assert extract_probe_host("//sub.example.com/api") == "sub.example.com"

    def test_extract_probe_host_empty_and_invalid(self):
        assert extract_probe_host("") == ""
        assert extract_probe_host("   ") == ""
        assert extract_probe_host(None) == ""


class TestHttpxSubprocessReliability:
    @pytest.mark.asyncio
    async def test_successful_httpx_execution_with_ip_and_port(self, tmp_path):
        recon = tmp_path / "recon.txt"
        recon.write_text("127.0.0.1:8765\n")
        config = ReconConfig(target="127.0.0.1")

        sample_json = json.dumps({
            "url": "http://127.0.0.1:8765",
            "input": "http://127.0.0.1:8765",
            "host": "127.0.0.1",
            "port": "8765",
            "status_code": 200,
            "title": "Local Test Server",
        })

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(sample_json.encode("utf-8"), b""))
        mock_proc.returncode = 0

        with patch("reconyx.modules.httpx_probe.find_projectdiscovery_httpx", return_value="/usr/bin/httpx"), \
             patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            res = await probe_subdomains(recon, config)

            assert res["available"] is True
            assert res["timed_out"] is False
            assert res["failed"] is False
            assert res["live_urls"] == ["http://127.0.0.1:8765"]
            assert res["live_hosts"] == ["127.0.0.1"]

    @pytest.mark.asyncio
    async def test_hung_subprocess_timeout_and_process_cleanup(self, tmp_path):
        recon = tmp_path / "recon.txt"
        recon.write_text("api.example.com\n")
        config = ReconConfig(target="example.com", probe_max_time=1)

        mock_proc = MagicMock()
        mock_stdout = asyncio.StreamReader()
        mock_stderr = asyncio.StreamReader()
        mock_proc.stdout = mock_stdout
        mock_proc.stderr = mock_stderr

        async def hung_wait():
            await asyncio.sleep(5.0)

        mock_proc.wait = AsyncMock(side_effect=hung_wait)
        mock_proc.returncode = None

        mock_terminate = AsyncMock()

        with patch("reconyx.modules.httpx_probe.find_projectdiscovery_httpx", return_value="/usr/bin/httpx"), \
             patch("asyncio.create_subprocess_exec", return_value=mock_proc), \
             patch("reconyx.modules.httpx_probe._terminate_process", new=mock_terminate):
            res = await probe_subdomains(recon, config, timeout=0.05)

            assert res["available"] is True
            assert res["timed_out"] is True
            assert mock_terminate.called

    @pytest.mark.asyncio
    async def test_subprocess_cancellation_and_cleanup(self, tmp_path):
        recon = tmp_path / "recon.txt"
        recon.write_text("api.example.com\n")
        config = ReconConfig(target="example.com")

        mock_proc = MagicMock()
        mock_stdout = asyncio.StreamReader()
        mock_stderr = asyncio.StreamReader()
        mock_proc.stdout = mock_stdout
        mock_proc.stderr = mock_stderr

        async def hung_wait():
            await asyncio.sleep(5.0)

        mock_proc.wait = AsyncMock(side_effect=hung_wait)
        mock_terminate = AsyncMock()

        with patch("reconyx.modules.httpx_probe.find_projectdiscovery_httpx", return_value="/usr/bin/httpx"), \
             patch("asyncio.create_subprocess_exec", return_value=mock_proc), \
             patch("reconyx.modules.httpx_probe._terminate_process", new=mock_terminate):
            task = asyncio.create_task(probe_subdomains(recon, config, timeout=10))
            await asyncio.sleep(0.02)
            task.cancel()

            with pytest.raises(asyncio.CancelledError):
                await task

            assert mock_terminate.called

    @pytest.mark.asyncio
    async def test_partial_jsonl_output_preservation_on_timeout(self, tmp_path):
        recon = tmp_path / "recon.txt"
        recon.write_text("127.0.0.1:8765\nhung.example.com\n")
        config = ReconConfig(target="example.com", probe_max_time=1)

        mock_proc = MagicMock()
        mock_stdout = asyncio.StreamReader()
        mock_stderr = asyncio.StreamReader()
        line = json.dumps({
            "url": "http://127.0.0.1:8765",
            "input": "http://127.0.0.1:8765",
            "status_code": 200,
            "title": "Local Service",
        }) + "\n"
        mock_stdout.feed_data(line.encode("utf-8"))

        mock_proc.stdout = mock_stdout
        mock_proc.stderr = mock_stderr

        async def hung_wait():
            await asyncio.sleep(5.0)

        mock_proc.wait = AsyncMock(side_effect=hung_wait)
        mock_proc.returncode = None
        mock_terminate = AsyncMock()

        with patch("reconyx.modules.httpx_probe.find_projectdiscovery_httpx", return_value="/usr/bin/httpx"), \
             patch("asyncio.create_subprocess_exec", return_value=mock_proc), \
             patch("reconyx.modules.httpx_probe._terminate_process", new=mock_terminate):
            res = await probe_subdomains(recon, config, timeout=0.05)

            assert res["available"] is True
            assert res["timed_out"] is True
            assert res["live_urls"] == ["http://127.0.0.1:8765"]
            assert res["live_hosts"] == ["127.0.0.1"]
            assert len(res["json_lines"]) == 1
            assert mock_terminate.called

    @pytest.mark.asyncio
    async def test_httpx_non_zero_exit_marked_as_failed(self, tmp_path):
        recon = tmp_path / "recon.txt"
        recon.write_text("api.example.com\n")
        config = ReconConfig(target="example.com")

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b"fatal error: flag parsing failed"))
        mock_proc.returncode = 1

        with patch("reconyx.modules.httpx_probe.find_projectdiscovery_httpx", return_value="/usr/bin/httpx"), \
             patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            res = await probe_subdomains(recon, config)

            assert res["available"] is True
            assert res["failed"] is True
            assert res["timed_out"] is False


class TestPipelineHttpxIntegration:
    def test_pipeline_output_compatibility_live_hosts_and_live_txt(self, tmp_path):
        out = OutputManager(tmp_path, "example.com")
        urls = ["http://127.0.0.1:8765", "https://sub.example.com:8443"]
        hosts = ["127.0.0.1", "sub.example.com"]

        out.save_live_urls(urls)
        out.save_live_hosts(hosts)

        live_file = out.path("live.txt")
        live_hosts_file = out.path("live_hosts.txt")

        assert live_file.exists()
        assert live_hosts_file.exists()

        live_lines = live_file.read_text().splitlines()
        hosts_lines = live_hosts_file.read_text().splitlines()

        assert "http://127.0.0.1:8765" in live_lines
        assert "127.0.0.1" in hosts_lines
        assert "http://127.0.0.1:8765" not in hosts_lines

    @pytest.mark.asyncio
    async def test_pipeline_httpx_authorization_safeguard(self, tmp_path):
        config = ReconConfig(
            target="example.com",
            output_base=str(tmp_path),
            probe_authorised=False,
            sources={"crtsh": False},
        )
        engine = ReconEngine(config)

        with patch.object(engine, "_run_sources", return_value={"crtsh": ["api.example.com"]}), \
             patch("reconyx.engine.probe_subdomains") as mock_probe:
            summary = await engine.run()
            assert not mock_probe.called
            assert summary["live_count"] == 0
