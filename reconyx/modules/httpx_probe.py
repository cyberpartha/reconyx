"""
RECONYX Module: ProjectDiscovery HTTPX Integration
Probes discovered subdomains for live HTTP/HTTPS services.
Distinguishes ProjectDiscovery HTTPX from Python httpx CLI.
"""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
import json
import logging
import os
import shutil
import subprocess
import sys
import urllib.parse
from pathlib import Path
from typing import TYPE_CHECKING, Any

from reconyx.utils import _terminate_process, extract_domain, normalize_domain

if TYPE_CHECKING:
    from reconyx.config import ReconConfig

logger = logging.getLogger("reconyx.httpx")


def extract_probe_host(val: str) -> str:
    """
    Extract the clean hostname (domain, subdomain, IPv4, or IPv6) from a URL or host string.
    Removes scheme (http/https), port numbers, path, and bracket enclosures.
    Examples:
      - 'http://127.0.0.1:8765'        -> '127.0.0.1'
      - 'https://sub.example.com:8443'  -> 'sub.example.com'
      - 'sub.example.com:8080'          -> 'sub.example.com'
      - 'sub.example.com'               -> 'sub.example.com'
      - 'http://[::1]:8765'             -> '::1'
      - '[::1]:8080'                    -> '::1'
      - '::1'                           -> '::1'
      - '[2001:db8::1]:8080'            -> '2001:db8::1'
      - '2001:db8::1'                   -> '2001:db8::1'
    """
    if not val or not isinstance(val, str):
        return ""
    val = val.strip()
    if not val:
        return ""

    # 1. Bare IP address (IPv4 or IPv6)
    try:
        return str(ipaddress.ip_address(val))
    except ValueError:
        pass

    # 2. IPv6 wrapped in brackets without port, e.g. '[::1]'
    if val.startswith("[") and val.endswith("]"):
        try:
            return str(ipaddress.ip_address(val[1:-1]))
        except ValueError:
            pass

    # 3. URL with scheme, e.g. 'http://127.0.0.1:8765' or 'https://sub.example.com:8443/path'
    if "://" in val:
        try:
            parsed = urllib.parse.urlsplit(val)
            if parsed.hostname:
                return parsed.hostname.strip("[]")
        except Exception:
            pass

    # 4. Netloc without scheme, e.g. '127.0.0.1:8765' or '[::1]:8765' or 'sub.example.com:8080' or '//sub.example.com/api'
    try:
        netloc_val = val if val.startswith("//") else ("//" + val)
        parsed = urllib.parse.urlsplit(netloc_val)
        if parsed.hostname:
            return parsed.hostname.strip("[]")
    except Exception:
        pass

    # 5. Fallback stripping: remove path, queries, fragments
    bare = val.split("/")[0].split("?")[0].split("#")[0].strip()
    if ":" in bare and not bare.startswith("["):
        parts = bare.rsplit(":", 1)
        if parts[1].isdigit():
            bare = parts[0]
    return bare.strip("[]")


def is_projectdiscovery_httpx(executable_path: str) -> bool:
    """
    Verify if the given binary is ProjectDiscovery HTTPX and not Python HTTPX CLI.
    Checks -version or -h for ProjectDiscovery signatures and expected flags.
    """
    if not os.path.isfile(executable_path) and not shutil.which(executable_path):
        return False

    # 1. Test -version
    try:
        res = subprocess.run(
            [executable_path, "-version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        combined = (res.stdout + res.stderr).lower()
        if "projectdiscovery" in combined:
            return True
        if "httpx" in combined and res.returncode == 0:
            if "unrecognized argument" not in combined and "next generation http" not in combined:
                return True
    except Exception:
        pass

    # 2. Test -h / -help for ProjectDiscovery specific flags
    try:
        res = subprocess.run(
            [executable_path, "-h"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        combined = (res.stdout + res.stderr).lower()
        # ProjectDiscovery HTTPX contains -title, -tech-detect, -status-code
        if "-title" in combined and ("-tech-detect" in combined or "-status-code" in combined or "projectdiscovery" in combined):
            return True
    except Exception:
        pass

    return False


def find_projectdiscovery_httpx() -> str | None:
    """
    Locate ProjectDiscovery HTTPX executable.
    Checks 'httpx', 'httpx-toolkit', as well as standard Kali/WSL/Go paths.
    """
    names = ["httpx", "httpx-toolkit"]
    home = Path.home()

    # 1. Check shutil.which for each name directly
    for name in names:
        p = shutil.which(name)
        if p and is_projectdiscovery_httpx(p):
            return p

    # 2. Check standard Unix / Kali / WSL2 and Windows locations
    candidate_paths: list[str] = []
    for name in names:
        candidate_paths.extend([
            f"/usr/bin/{name}",
            f"/usr/local/bin/{name}",
            f"/bin/{name}",
            str(home / "go" / "bin" / name),
            str(home / ".local" / "bin" / name),
            str(home / ".cargo" / "bin" / name),
        ])
    if sys.platform == "win32":
        for name in names:
            candidate_paths.extend([
                f"{name}.exe",
                str(home / "go" / "bin" / f"{name}.exe"),
            ])

    for path in candidate_paths:
        if os.path.isfile(path) and (sys.platform == "win32" or os.access(path, os.X_OK)):
            if is_projectdiscovery_httpx(path):
                return path

    return None


async def probe_subdomains(
    recon_file: Path | str,
    config: "ReconConfig",
    timeout: int | float | None = None,
) -> dict[str, Any]:
    """
    Run ProjectDiscovery HTTPX against discovered subdomains in recon_file.

    Returns a dict with:
      - available: bool (whether PD HTTPX was found)
      - results: list of structured dicts
      - live_urls: list of responsive URLs
      - live_hosts: list of unique hostnames corresponding to live services
      - json_lines: list of raw JSON strings from HTTPX output
      - timed_out: bool (whether overall execution deadline was exceeded)
      - failed: bool (whether an error occurred during execution)
      - error: optional error message string
    """
    recon_path = Path(recon_file)
    if not recon_path.exists() or recon_path.stat().st_size == 0:
        return {
            "available": True,
            "results": [],
            "live_urls": [],
            "live_hosts": [],
            "json_lines": [],
            "timed_out": False,
            "failed": False,
            "error": None,
        }

    httpx_bin = find_projectdiscovery_httpx()
    if not httpx_bin:
        logger.warning(
            "ProjectDiscovery HTTPX not found (checked 'httpx' and 'httpx-toolkit'). "
            "Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest "
            "or: sudo apt install httpx-toolkit"
        )
        return {
            "available": False,
            "results": [],
            "live_urls": [],
            "live_hosts": [],
            "json_lines": [],
            "timed_out": False,
            "failed": False,
            "error": "Binary not found",
        }

    logger.info("Using ProjectDiscovery HTTPX executable: %s", httpx_bin)

    cmd = [
        httpx_bin,
        "-l", str(recon_path),
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-follow-redirects",
        "-json",
        "-threads", str(getattr(config, "probe_threads", 50)),
        "-timeout", str(getattr(config, "probe_timeout", 10)),
    ]
    rate_limit = getattr(config, "probe_rate_limit", 150)
    if rate_limit and rate_limit > 0:
        cmd.extend(["-rate-limit", str(rate_limit)])

    overall_timeout = timeout if timeout is not None else getattr(config, "probe_max_time", 120)
    if overall_timeout <= 0:
        overall_timeout = 120

    results: list[dict[str, Any]] = []
    live_urls: list[str] = []
    live_hosts_set: set[str] = set()
    json_lines: list[str] = []
    timed_out = False
    failed = False
    error_msg: str | None = None

    def _process_json_entry(line_str: str) -> None:
        try:
            data = json.loads(line_str)
        except json.JSONDecodeError:
            return

        json_lines.append(line_str)

        url = data.get("url") or data.get("input") or ""
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}" if url else ""

        final_url = data.get("final_url") or data.get("location") or url
        status_code = data.get("status_code") or data.get("status-code") or data.get("status", 0)
        title = data.get("title", "")
        server = data.get("webserver") or data.get("server", "")
        tech = data.get("tech") or data.get("technologies") or []
        if isinstance(tech, str):
            tech = [tech]

        raw_host_candidate = data.get("input") or data.get("url") or data.get("host") or ""
        host = extract_probe_host(raw_host_candidate)
        if not host and (data.get("url") or data.get("host")):
            host = extract_probe_host(data.get("url") or "") or extract_probe_host(data.get("host") or "")
        host = normalize_domain(host) if host else ""

        if url and url not in live_urls:
            live_urls.append(url)
        if host:
            live_hosts_set.add(host)

        results.append({
            "url": url,
            "final_url": final_url,
            "host": host,
            "status_code": status_code,
            "title": title,
            "server": server,
            "technologies": tech,
            "raw": data,
        })

    kwargs: dict[str, Any] = {
        "stdout": asyncio.subprocess.PIPE,
        "stderr": asyncio.subprocess.PIPE,
    }
    if sys.platform != "win32":
        kwargs["start_new_session"] = True

    try:
        proc = await asyncio.create_subprocess_exec(*cmd, **kwargs)

        is_stream = isinstance(getattr(proc, "stdout", None), asyncio.StreamReader) or (
            hasattr(getattr(proc, "stdout", None), "readline") and
            inspect.iscoroutinefunction(proc.stdout.readline)
        )

        if is_stream:
            stderr_chunks: list[bytes] = []

            async def _read_stdout():
                if proc.stdout is None:
                    return
                while True:
                    line_bytes = await proc.stdout.readline()
                    if not line_bytes:
                        break
                    line_str = line_bytes.decode(errors="replace").strip()
                    if line_str:
                        _process_json_entry(line_str)

            async def _read_stderr():
                if proc.stderr is None:
                    return
                while True:
                    chunk = await proc.stderr.read(4096)
                    if not chunk:
                        break
                    stderr_chunks.append(chunk)

            stdout_task = asyncio.create_task(_read_stdout())
            stderr_task = asyncio.create_task(_read_stderr())

            try:
                await asyncio.wait_for(proc.wait(), timeout=overall_timeout)
                await asyncio.gather(stdout_task, stderr_task)
            except asyncio.TimeoutError:
                timed_out = True
                stdout_task.cancel()
                stderr_task.cancel()
                await _terminate_process(proc)
                logger.warning(
                    "HTTPX subprocess timed out after %ds (preserved %d partial live findings)",
                    overall_timeout,
                    len(live_urls),
                )
            except asyncio.CancelledError:
                stdout_task.cancel()
                stderr_task.cancel()
                await _terminate_process(proc)
                raise

            if proc.returncode is not None and proc.returncode != 0 and not timed_out:
                failed = True
                err_text = b"".join(stderr_chunks).decode(errors="replace").strip()
                error_msg = err_text or f"HTTPX exited with code {proc.returncode}"
                logger.warning("HTTPX error (code %s): %s", proc.returncode, error_msg)
        else:
            # Fallback for mocked objects without StreamReader
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=overall_timeout)
                if stderr:
                    err_msg = stderr.decode(errors="replace").strip() if isinstance(stderr, bytes) else str(stderr).strip()
                    if err_msg:
                        logger.debug("HTTPX stderr: %s", err_msg)
                raw_output = stdout.decode(errors="replace") if isinstance(stdout, bytes) else str(stdout)
                for line in raw_output.splitlines():
                    line_str = line.strip()
                    if line_str:
                        _process_json_entry(line_str)
                if getattr(proc, "returncode", 0) not in (0, None):
                    failed = True
                    error_msg = f"HTTPX exited with code {proc.returncode}"
            except asyncio.TimeoutError:
                await _terminate_process(proc)
                timed_out = True
                logger.warning("HTTPX subprocess timed out after %ds", overall_timeout)
            except asyncio.CancelledError:
                await _terminate_process(proc)
                raise

    except Exception as exc:
        logger.error("Error executing HTTPX: %s", exc)
        failed = True
        error_msg = str(exc)

    return {
        "available": True,
        "results": results,
        "live_urls": sorted(live_urls),
        "live_hosts": sorted(live_hosts_set),
        "json_lines": json_lines,
        "timed_out": timed_out,
        "failed": failed,
        "error": error_msg,
    }
