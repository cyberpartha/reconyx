"""
RECONYX Source: Wayback Machine CDX API
Queries the Internet Archive CDX API to extract historical subdomains.
No authentication required.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from reconyx.utils import NetworkError, fetch_text, filter_and_normalize, http_session

if TYPE_CHECKING:
    from reconyx.config import ReconConfig

logger = logging.getLogger("reconyx.sources.wayback")

SOURCE_NAME = "Wayback Machine"
_CDX_URL = "http://web.archive.org/cdx/search/cdx"


async def enumerate(target: str, config: "ReconConfig") -> list[str]:
    """
    Query the Wayback Machine CDX API for all URLs matching *target*.
    Extract hostnames from the URL column.
    Raises NetworkError on connection/API failures, TimeoutError on deadline expiry.
    """
    params = {
        "url":        f"*.{target}/*",
        "output":     "text",
        "fl":         "original",
        "collapse":   "urlkey",
        "limit":      "50000",
        "fastLatest": "true",
    }

    results: list[str] = []

    async with http_session(timeout=config.timeout) as session:
        text = await fetch_text(
            session,
            _CDX_URL,
            params=params,
            retries=config.retries,
            timeout=config.timeout,
        )
        if text is None:
            raise NetworkError("Wayback Machine CDX API request failed: no response data received")

        for line in text.splitlines():
            line = line.strip()
            if line:
                results.append(line)

    normalised = filter_and_normalize(results, base_domain=target)
    logger.info("Wayback Machine → %d subdomains discovered", len(normalised))
    return normalised
