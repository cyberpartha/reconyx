"""
RECONYX Source: HackerTarget
Free passive DNS lookup via hackertarget.com API.
Rate-limited to a small number of free queries per day.
No authentication required for the free tier.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from reconyx.utils import fetch_text, filter_and_normalize, http_session

if TYPE_CHECKING:
    from reconyx.config import ReconConfig

logger = logging.getLogger("reconyx.sources.hackertarget")

SOURCE_NAME = "HackerTarget"
_API_URL = "https://api.hackertarget.com/hostsearch/"


async def enumerate(target: str, config: "ReconConfig") -> list[str]:
    """
    Query HackerTarget host search API.
    Returns 'hostname,ip' lines — we extract only the hostname.
    Raises RuntimeError on API limit or connection failures.
    """
    results: list[str] = []

    async with http_session(timeout=config.timeout) as session:
        text = await fetch_text(
            session,
            _API_URL,
            params={"q": target},
            retries=config.retries,
        )
        if text is None:
            raise RuntimeError("HackerTarget API request failed (network error or timeout)")

        if "API count exceeded" in text or "error" in text.lower():
            logger.warning("HackerTarget: API limit reached or error — %s", text.strip())
            raise RuntimeError(f"HackerTarget rate limit or error: {text.strip()}")

        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            hostname = parts[0].strip()
            if hostname:
                results.append(hostname)

    normalised = filter_and_normalize(results, base_domain=target)
    logger.info("HackerTarget → %d subdomains discovered", len(normalised))
    return normalised
