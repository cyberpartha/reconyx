"""
RECONYX Source: VirusTotal
Queries VirusTotal's subdomain enumeration API.
Requires a free or paid VirusTotal API key.
Set: RECONYX_VT_KEY or VT_API_KEY environment variable.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from reconyx.utils import fetch_json, filter_and_normalize, http_session

if TYPE_CHECKING:
    from reconyx.config import ReconConfig

logger = logging.getLogger("reconyx.sources.virustotal")

SOURCE_NAME = "VirusTotal"
_BASE_URL = "https://www.virustotal.com/api/v3/domains/{domain}/subdomains"


async def enumerate(target: str, config: "ReconConfig") -> list[str]:
    """
    Query VirusTotal API v3 for subdomains.
    Paginates through all available results automatically.
    Requires a valid API key in config.api_keys['virustotal'].
    """
    api_key = config.api_keys.get("virustotal", "").strip()
    if not api_key:
        logger.warning("VirusTotal: No API key configured — skipping source")
        return []

    headers = {"x-apikey": api_key}
    results: list[str] = []
    url = _BASE_URL.format(domain=target)
    limit = 40  # VirusTotal max per page

    async with http_session(timeout=config.timeout, headers=headers) as session:
        while url:
            data = await fetch_json(
                session,
                url,
                params={"limit": limit},
                retries=config.retries,
            )
            if not data or not isinstance(data, dict):
                break

            for item in data.get("data", []):
                subdomain = item.get("id", "").strip()
                if subdomain:
                    results.append(subdomain)

            # Follow pagination cursor
            links = data.get("links", {})
            url = links.get("next", "")
            if url:
                await asyncio.sleep(config.rate_limit_delay)

    normalised = filter_and_normalize(results, base_domain=target)
    logger.info("VirusTotal → %d subdomains discovered", len(normalised))
    return normalised
