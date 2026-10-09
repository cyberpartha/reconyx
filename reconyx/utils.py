"""
RECONYX Utility Functions
Shared helpers for domain normalisation, subprocess execution,
async HTTP, deduplication, and logging setup.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import signal
import subprocess
import sys
import time
import unicodedata
from contextlib import asynccontextmanager
from typing import AsyncIterator, Iterable
from urllib.parse import urlparse

import aiohttp

logger = logging.getLogger("reconyx")


class ReconyxError(Exception):
    """Base exception for RECONYX framework errors."""
    pass


class NetworkError(ReconyxError):
    """Raised on network failures (connection dropped, DNS error, TCP reset, etc.)."""
    pass


class HttpError(ReconyxError):
    """Raised on non-transient HTTP error response status (e.g. 403, 500, retry exhaustion)."""
    pass

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging(level: str = "INFO", log_file: str = "") -> None:
    """Configure the reconyx logger with RichHandler on the shared console and optional file logging."""
    from rich.logging import RichHandler
    from reconyx.console import get_console

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    shared_console = get_console()

    # Determine console log level:
    # If user sets DEBUG, console displays DEBUG.
    # In standard INFO mode, background source tasks already report discovery
    # via print_status(). Filtering console logging to WARNING prevents duplicate
    # lines from corrupting active Rich progress bars.
    if numeric_level <= logging.DEBUG:
        console_level = logging.DEBUG
    elif numeric_level == logging.INFO:
        console_level = logging.WARNING
    else:
        console_level = numeric_level

    handlers: list[logging.Handler] = [
        RichHandler(
            console=shared_console,
            show_time=False,
            show_level=True,
            show_path=(numeric_level <= logging.DEBUG),
            markup=True,
        )
    ]
    handlers[0].setLevel(console_level)

    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(numeric_level)
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        fh.setFormatter(formatter)
        handlers.append(fh)

    # Configure reconyx logger without duplicate handlers
    reconyx_logger = logging.getLogger("reconyx")
    reconyx_logger.setLevel(logging.DEBUG)
    reconyx_logger.handlers.clear()
    for h in handlers:
        reconyx_logger.addHandler(h)
    reconyx_logger.propagate = False

    # Silence noisy third-party loggers
    for noisy in ("urllib3", "asyncio", "aiohttp"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Domain Helpers
# ---------------------------------------------------------------------------

# Valid hostname label pattern (RFC 952 / RFC 1123)
_HOSTNAME_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
    re.IGNORECASE,
)

# Common wildcard prefixes produced by CT logs
_WILDCARD_PREFIXES = {"*", "*."}


def normalize_domain(domain: str) -> str:
    """
    Normalise a raw domain/hostname string:
      - Strip whitespace and leading '*.' wildcard prefix
      - Convert to lowercase ASCII (handle IDN via IDNA encoding)
      - Remove trailing dot
    Returns the normalised hostname or empty string if invalid.
    """
    domain = domain.strip().lower().rstrip(".")

    # Strip wildcard prefix
    if domain.startswith("*."):
        domain = domain[2:]
    elif domain.startswith("*"):
        domain = domain[1:].lstrip(".")

    # Convert IDN / unicode hostnames to ASCII (IDNA)
    try:
        # Only encode if non-ASCII characters present
        if any(ord(c) > 127 for c in domain):
            domain = domain.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return ""

    return domain


def is_valid_domain(domain: str) -> bool:
    """Return True if domain is a syntactically valid hostname."""
    if not domain or len(domain) > 253:
        return False
    return bool(_HOSTNAME_RE.match(domain))


def extract_domain(text: str) -> str:
    """Extract the hostname from a URL or bare domain string."""
    text = text.strip()
    if text.startswith(("http://", "https://", "//")):
        parsed = urlparse(text)
        return parsed.hostname or ""
    return text.split("/")[0].split("?")[0].split("#")[0]


def deduplicate(domains: Iterable[str]) -> list[str]:
    """Remove duplicates while preserving insertion order."""
    seen: set[str] = set()
    result: list[str] = []
    for d in domains:
        if d and d not in seen:
            seen.add(d)
            result.append(d)
    return result


def filter_and_normalize(
    raw: Iterable[str],
    base_domain: str | None = None,
) -> list[str]:
    """
    Full pipeline:
      1. Extract hostname from each entry
      2. Normalise
      3. Validate
      4. Optionally restrict to subdomains of base_domain
      5. Deduplicate
      6. Sort
    """
    results: list[str] = []
    for entry in raw:
        host = extract_domain(entry)
        host = normalize_domain(host)
        if not is_valid_domain(host):
            continue
        if base_domain and not (
            host == base_domain or host.endswith(f".{base_domain}")
        ):
            continue
        results.append(host)
    return sorted(deduplicate(results))


# ---------------------------------------------------------------------------
# Async HTTP Session Factory
# ---------------------------------------------------------------------------

@asynccontextmanager
async def http_session(
    timeout: int = 30,
    headers: dict | None = None,
) -> AsyncIterator[aiohttp.ClientSession]:
    """Context manager that yields a configured aiohttp ClientSession."""
    default_headers = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; RECONYX/1.0; "
            "+https://github.com/CyberPartha/reconyx)"
        ),
    }
    if headers:
        default_headers.update(headers)
    connector = aiohttp.TCPConnector(
        limit=100,
        ssl=False,  # Many CT/API endpoints work over HTTPS; disable strict verify for speed
    )
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(
        headers=default_headers,
        connector=connector,
        timeout=client_timeout,
    ) as session:
        yield session


async def fetch_json(
    session: aiohttp.ClientSession,
    url: str,
    params: dict | None = None,
    retries: int = 3,
    backoff: float = 1.5,
    timeout: float | None = None,
) -> dict | list | None:
    """Fetch a JSON endpoint with retries, exponential backoff, and strict deadline enforcement."""
    deadline = (time.monotonic() + timeout) if (timeout and timeout > 0) else None
    timed_out_count = 0
    last_client_error: Exception | None = None
    last_http_status: int | None = None

    for attempt in range(retries):
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError(f"Request to {url} timed out (deadline of {timeout}s exceeded before attempt {attempt + 1})")

        req_timeout = None
        if deadline is not None:
            remaining = max(0.1, deadline - time.monotonic())
            req_timeout = aiohttp.ClientTimeout(total=remaining)

        try:
            async with session.get(url, params=params, timeout=req_timeout) as resp:
                if resp.status == 200:
                    return await resp.json(content_type=None)
                if resp.status in (429, 503):
                    last_http_status = resp.status
                    wait = backoff ** (attempt + 1)
                    if deadline is not None and (time.monotonic() + wait) >= deadline:
                        raise TimeoutError(f"Request to {url} timed out waiting for retry ({timeout}s deadline exceeded)")
                    logger.warning("Rate limited by %s (HTTP %d) — waiting %.1fs", url, resp.status, wait)
                    await asyncio.sleep(wait)
                    continue
                last_http_status = resp.status
                logger.debug("HTTP %s from %s", resp.status, url)
                return None
        except asyncio.TimeoutError:
            timed_out_count += 1
            logger.warning("Timeout fetching %s (attempt %d)", url, attempt + 1)
        except aiohttp.ClientError as exc:
            last_client_error = exc
            logger.warning("Client error fetching %s: %s", url, exc)

        if attempt < retries - 1:
            sleep_time = backoff ** attempt
            if deadline is not None and (time.monotonic() + sleep_time) >= deadline:
                raise TimeoutError(f"Request to {url} timed out during retry backoff ({timeout}s deadline exceeded)")
            await asyncio.sleep(sleep_time)

    if timed_out_count == retries:
        raise TimeoutError(f"Request to {url} timed out after {retries} attempts")
    if last_client_error is not None:
        raise NetworkError(f"Network error connecting to {url}: {last_client_error}")
    if last_http_status is not None and last_http_status in (429, 503):
        raise HttpError(f"HTTP {last_http_status} rate limit exhausted for {url} after {retries} attempts")
    return None


async def fetch_text(
    session: aiohttp.ClientSession,
    url: str,
    params: dict | None = None,
    retries: int = 3,
    backoff: float = 1.5,
    timeout: float | None = None,
) -> str | None:
    """Fetch a plain-text endpoint with retries, exponential backoff, and strict deadline enforcement."""
    deadline = (time.monotonic() + timeout) if (timeout and timeout > 0) else None
    timed_out_count = 0
    last_client_error: Exception | None = None
    last_http_status: int | None = None

    for attempt in range(retries):
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError(f"Request to {url} timed out (deadline of {timeout}s exceeded before attempt {attempt + 1})")

        req_timeout = None
        if deadline is not None:
            remaining = max(0.1, deadline - time.monotonic())
            req_timeout = aiohttp.ClientTimeout(total=remaining)

        try:
            async with session.get(url, params=params, timeout=req_timeout) as resp:
                if resp.status == 200:
                    return await resp.text()
                if resp.status in (429, 503):
                    last_http_status = resp.status
                    wait = backoff ** (attempt + 1)
                    if deadline is not None and (time.monotonic() + wait) >= deadline:
                        raise TimeoutError(f"Request to {url} timed out waiting for retry ({timeout}s deadline exceeded)")
                    logger.warning("Rate limited by %s (HTTP %d) — waiting %.1fs", url, resp.status, wait)
                    await asyncio.sleep(wait)
                    continue
                last_http_status = resp.status
                logger.debug("HTTP %s from %s", resp.status, url)
                return None
        except asyncio.TimeoutError:
            timed_out_count += 1
            logger.warning("Timeout fetching %s (attempt %d)", url, attempt + 1)
        except aiohttp.ClientError as exc:
            last_client_error = exc
            logger.warning("Client error fetching %s: %s", url, exc)

        if attempt < retries - 1:
            sleep_time = backoff ** attempt
            if deadline is not None and (time.monotonic() + sleep_time) >= deadline:
                raise TimeoutError(f"Request to {url} timed out during retry backoff ({timeout}s deadline exceeded)")
            await asyncio.sleep(sleep_time)

    if timed_out_count == retries:
        raise TimeoutError(f"Request to {url} timed out after {retries} attempts")
    if last_client_error is not None:
        raise NetworkError(f"Network error connecting to {url}: {last_client_error}")
    if last_http_status is not None and last_http_status in (429, 503):
        raise HttpError(f"HTTP {last_http_status} rate limit exhausted for {url} after {retries} attempts")
    return None


# ---------------------------------------------------------------------------
# Subprocess / External Tool Helpers
# ---------------------------------------------------------------------------

import shutil
import os
from pathlib import Path


def find_tool(name: str) -> str | None:
    """
    Locate an external binary using shutil.which and standard tool paths.
    Returns the resolved executable path or None if not installed.
    """
    # 1. Standard PATH lookup
    found = shutil.which(name)
    if found:
        return found

    # 2. Check standard Kali / Linux / WSL2 locations
    candidates = [
        f"/usr/bin/{name}",
        f"/usr/local/bin/{name}",
        f"/bin/{name}",
        str(Path.home() / "go" / "bin" / name),
        str(Path.home() / ".local" / "bin" / name),
        str(Path.home() / ".cargo" / "bin" / name),
    ]
    if sys.platform == "win32":
        candidates.extend([
            f"{name}.exe",
            str(Path.home() / "go" / "bin" / f"{name}.exe"),
        ])

    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    return None


def tool_available(name: str) -> bool:
    """Return True if an external binary is available on PATH or known locations."""
    return find_tool(name) is not None


async def _terminate_process(proc: asyncio.subprocess.Process) -> None:
    """Safely terminate a subprocess and its process group to avoid orphans/zombies."""
    if proc.returncode is not None:
        return
    try:
        if sys.platform != "win32":
            try:
                pgid = os.getpgid(proc.pid)
                sig = getattr(signal, "SIGKILL", signal.SIGTERM)
                os.killpg(pgid, sig)
            except (ProcessLookupError, OSError):
                proc.kill()
        else:
            proc.kill()
        await proc.wait()
    except (ProcessLookupError, OSError):
        pass


async def run_tool(
    cmd: list[str],
    timeout: int = 30,
) -> str:
    """
    Run an external command asynchronously, returning its stdout.
    Safely terminates the process group on timeout or cancellation.
    Raises TimeoutError on deadline expiry, RuntimeError on error.
    """
    exe = find_tool(cmd[0]) or cmd[0]
    exec_cmd = [exe] + list(cmd[1:])

    kwargs: dict = {
        "stdout": asyncio.subprocess.PIPE,
        "stderr": asyncio.subprocess.PIPE,
    }
    if sys.platform != "win32":
        kwargs["start_new_session"] = True

    try:
        proc = await asyncio.create_subprocess_exec(*exec_cmd, **kwargs)
    except FileNotFoundError:
        raise RuntimeError(f"Tool {cmd[0]} not found on PATH")

    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        if proc.returncode != 0:
            logger.debug(
                "Tool %s exited %s: %s", cmd[0], proc.returncode,
                stderr.decode(errors="replace").strip()
            )
        return stdout.decode(errors="replace").strip()
    except asyncio.TimeoutError:
        await _terminate_process(proc)
        raise TimeoutError(f"Tool {cmd[0]} timed out after {timeout}s")
    except asyncio.CancelledError:
        await _terminate_process(proc)
        raise


class PartialResultError(Exception):
    """Raised when an external tool or source produces partial findings before timeout or error."""

    def __init__(self, subdomains: list[str] | None = None, message: str = "") -> None:
        super().__init__(message or (f"{len(subdomains or [])} partial results preserved"))
        self.subdomains = subdomains or []

    @property
    def partial_results(self) -> list[str]:
        return self.subdomains


async def run_tool_with_partial(
    cmd: list[str],
    timeout: int = 30,
) -> tuple[str, bool]:
    """
    Run an external command asynchronously, capturing stdout line-by-line.
    If timeout expires, terminates the process group and returns (stdout_str, True).
    If completed normally, returns (stdout_str, False).
    """
    exe = find_tool(cmd[0]) or cmd[0]
    exec_cmd = [exe] + list(cmd[1:])

    kwargs: dict = {
        "stdout": asyncio.subprocess.PIPE,
        "stderr": asyncio.subprocess.PIPE,
    }
    if sys.platform != "win32":
        kwargs["start_new_session"] = True

    try:
        proc = await asyncio.create_subprocess_exec(*exec_cmd, **kwargs)
    except FileNotFoundError:
        raise RuntimeError(f"Tool {cmd[0]} not found on PATH")

    collected: list[bytes] = []

    async def _read_stream():
        if proc.stdout is None:
            return
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            collected.append(line)

    reader_task = asyncio.create_task(_read_stream())
    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout)
        await reader_task
        out_str = b"".join(collected).decode(errors="replace").strip()
        return out_str, False
    except asyncio.TimeoutError:
        reader_task.cancel()
        await _terminate_process(proc)
        out_str = b"".join(collected).decode(errors="replace").strip()
        return out_str, True
    except asyncio.CancelledError:
        reader_task.cancel()
        await _terminate_process(proc)
        raise



# ---------------------------------------------------------------------------
# Miscellaneous
# ---------------------------------------------------------------------------

def clean_domain_list(raw_lines: str) -> list[str]:
    """Split a multiline string into individual non-empty lines."""
    return [line.strip() for line in raw_lines.splitlines() if line.strip()]


def safe_int(value: object, default: int = 0) -> int:
    """Safely convert a value to int, returning default on failure."""
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
