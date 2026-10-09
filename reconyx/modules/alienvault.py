"""
RECONYX Source: AlienVault OTX
Queries the OTX passive DNS and URL data for subdomains.
No authentication required for basic queries.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from reconyx.utils import fetch_json, filter_and_normalize, http_session

if TYPE_CHECKING:
    from reconyx.config import ReconConfig

logger = logging.getLogger("reconyx.sources.alienvault")

SOURCE_NAME = "AlienVault OTX"
_BASE_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
_URL_LIST = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"


async def enumerate(target: str, config: "ReconConfig") -> list[str]:
    """
    Query AlienVault OTX passive DNS and URL list endpoints.
    Extracts hostnames from both data sets.
    Raises RuntimeError on total connection failure.
    """
    results: list[str] = []
    success_count = 0

    async with http_session(timeout=config.timeout) as session:
        # 1. Passive DNS
        pdns_url = _BASE_URL.format(domain=target)
        data = await fetch_json(session, pdns_url, retries=config.retries)
        if data is not None:
            success_count += 1
            if isinstance(data, dict):
                for record in data.get("passive_dns", []):
                    hostname = record.get("hostname", "").strip()
                    if hostname:
                        results.append(hostname)

        # 2. URL list — extract hostnames from URLs
        url_list_url = _URL_LIST.format(domain=target)
        url_data = await fetch_json(session, url_list_url, retries=config.retries)
        if url_data is not None:
            success_count += 1
            if isinstance(url_data, dict):
                for entry in url_data.get("url_list", []):
                    url = entry.get("url", "").strip()
                    if url:
                        results.append(url)

    if success_count == 0:
        raise RuntimeError("AlienVault OTX API connection failed or timed out")

    normalised = filter_and_normalize(results, base_domain=target)
    logger.info("AlienVault OTX → %d subdomains discovered", len(normalised))
    return normalised
