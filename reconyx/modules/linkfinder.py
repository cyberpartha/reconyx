"""
RECONYX Module: LinkFinder (JavaScript endpoint extractor)
Extracts API endpoints and paths from JavaScript files.
Pure Python implementation — does not require the original linkfinder.py tool.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import TYPE_CHECKING

from reconyx.utils import fetch_text, http_session

if TYPE_CHECKING:
    from reconyx.config import ReconConfig

logger = logging.getLogger("reconyx.linkfinder")

# Patterns for extracting endpoints from JavaScript
_ENDPOINT_PATTERNS = [
    # REST-style paths
    re.compile(r"""(?:["'`])(/(?:api|v\d+|auth|admin|graphql|rest|rpc)[^"'`\s<>]{1,200})(?:["'`])"""),
    # Generic paths starting with /
    re.compile(r"""(?:["'`])(/[a-zA-Z0-9_\-./]{3,150})(?:["'`])"""),
    # Full URLs
    re.compile(r"""(?:["'`])(https?://[^\s"'`<>]{10,300})(?:["'`])"""),
    # Fetch/axios/XHR calls
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["'`]([^"'`]+)"""),
]

_JS_LINK_RE = re.compile(
    r"""<script[^>]+src=["']([^"']+\.js[^"']*)["']""",
    re.IGNORECASE,
)


async def _extract_from_js(
    session,
    js_url: str,
    base_url: str,
    timeout: int,
) -> list[str]:
    """Fetch a JS file and extract endpoint paths."""
    content = await fetch_text(session, js_url)
    if not content:
        return []
    endpoints: set[str] = set()
    for pattern in _ENDPOINT_PATTERNS:
        for match in pattern.finditer(content):
            ep = match.group(1).strip()
            if ep and len(ep) > 2:
                endpoints.add(ep)
    return sorted(endpoints)


async def extract_endpoints(
    live_hosts: list[str],
    config: "ReconConfig",
) -> list[str]:
    """
    For each live host, fetch the main page, discover JS files,
    then extract all endpoints from those JS files.
    """
    all_endpoints: set[str] = set()
    semaphore = asyncio.Semaphore(10)

    async with http_session(timeout=config.timeout) as session:
        async def process_host(host: str) -> None:
            async with semaphore:
                base_url = f"https://{host}"
                html = await fetch_text(session, base_url)
                if not html:
                    base_url = f"http://{host}"
                    html = await fetch_text(session, base_url)
                if not html:
                    return

                # Discover JS files
                js_urls: list[str] = []
                for match in _JS_LINK_RE.finditer(html):
                    src = match.group(1).strip()
                    if src.startswith("http"):
                        js_urls.append(src)
                    elif src.startswith("/"):
                        js_urls.append(f"{base_url}{src}")
                    else:
                        js_urls.append(f"{base_url}/{src}")

                # Limit to first 10 JS files per host
                for js_url in js_urls[:10]:
                    eps = await _extract_from_js(session, js_url, base_url, config.timeout)
                    all_endpoints.update(eps)

        tasks = [process_host(h) for h in live_hosts]
        await asyncio.gather(*tasks, return_exceptions=True)

    result = sorted(all_endpoints)
    logger.info("LinkFinder → %d endpoints extracted", len(result))
    return result
