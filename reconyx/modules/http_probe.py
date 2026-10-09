"""
RECONYX Module: HTTP Probe
Performs active HTTP/HTTPS probing against discovered subdomains.
Collects status codes, titles, redirects, and web server info.

IMPORTANT: Only runs after explicit user authorisation.
Uses httpx (Python) for probing — does NOT require the httpx Go binary.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import aiohttp

if TYPE_CHECKING:
    from reconyx.config import ReconConfig

logger = logging.getLogger("reconyx.probe")

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_SERVER_RE = re.compile(r"^Server:\s*(.+)$", re.IGNORECASE | re.MULTILINE)


@dataclass
class ProbeResult:
    host: str
    url: str
    status: int = 0
    title: str = ""
    server: str = ""
    redirect_url: str = ""
    content_length: int = 0
    error: str = ""
    technologies: list[str] = field(default_factory=list)


async def _probe_single(
    session: aiohttp.ClientSession,
    host: str,
    timeout: int,
    follow_redirects: bool,
) -> ProbeResult | None:
    """Probe a single host over HTTPS then HTTP."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        result = ProbeResult(host=host, url=url)
        try:
            async with session.get(
                url,
                allow_redirects=follow_redirects,
                timeout=aiohttp.ClientTimeout(total=timeout),
                ssl=False,
            ) as resp:
                result.status = resp.status
                result.server = resp.headers.get("Server", "")
                result.content_length = int(resp.headers.get("Content-Length", 0) or 0)

                if resp.history:
                    result.redirect_url = str(resp.url)

                # Extract title from HTML
                body = ""
                try:
                    body = await resp.text(errors="replace")
                except Exception:
                    pass

                if body:
                    m = _TITLE_RE.search(body[:4096])
                    if m:
                        result.title = m.group(1).strip()[:200]

                # Basic tech fingerprinting from headers
                x_powered = resp.headers.get("X-Powered-By", "")
                if x_powered:
                    result.technologies.append(x_powered)
                via = resp.headers.get("Via", "")
                if via:
                    result.technologies.append(f"Via:{via}")

                return result

        except asyncio.TimeoutError:
            result.error = f"Timeout ({timeout}s)"
        except aiohttp.ClientConnectorError:
            result.error = "Connection refused"
        except aiohttp.ClientError as exc:
            result.error = str(exc)[:120]

    return None  # Both schemes failed — host is unreachable


async def probe_hosts(
    hosts: list[str],
    config: "ReconConfig",
) -> list[dict]:
    """
    Probe all hosts concurrently.
    Returns a list of ProbeResult dicts for reachable hosts only.
    """
    semaphore = asyncio.Semaphore(config.probe_threads)
    results: list[ProbeResult] = []

    connector = aiohttp.TCPConnector(limit=config.probe_threads, ssl=False)
    async with aiohttp.ClientSession(
        connector=connector,
        headers={"User-Agent": "RECONYX/1.0 (+https://github.com/CyberPartha/reconyx)"},
    ) as session:

        async def bounded_probe(host: str) -> None:
            async with semaphore:
                result = await _probe_single(
                    session, host,
                    config.probe_timeout,
                    config.probe_follow_redirects,
                )
                if result and result.status > 0:
                    results.append(result)
                await asyncio.sleep(0.05)

        tasks = [bounded_probe(h) for h in hosts]
        await asyncio.gather(*tasks, return_exceptions=True)

    logger.info("HTTP probe → %d/%d hosts reachable", len(results), len(hosts))
    return [
        {
            "host":          r.host,
            "url":           r.url,
            "status":        r.status,
            "title":         r.title,
            "server":        r.server,
            "redirect_url":  r.redirect_url,
            "content_length": r.content_length,
            "technologies":  r.technologies,
        }
        for r in sorted(results, key=lambda x: x.host)
    ]
