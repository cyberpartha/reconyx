"""
RECONYX Source: Common Crawl
Queries the Common Crawl Index API for subdomains.
No authentication required.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from reconyx.utils import NetworkError, fetch_json, fetch_text, filter_and_normalize, http_session

if TYPE_CHECKING:
    from reconyx.config import ReconConfig

logger = logging.getLogger("reconyx.sources.commoncrawl")

SOURCE_NAME = "Common Crawl"
_CC_INDEX_URL = "https://index.commoncrawl.org/collinfo.json"
_CC_SEARCH_URL = "https://index.commoncrawl.org/{index}/cdx/search/cdx"


async def _get_latest_index(session, timeout: int) -> str | None:
    """Fetch the most recent Common Crawl index identifier."""
    data = await fetch_json(session, _CC_INDEX_URL)
    if data and isinstance(data, list) and len(data) > 0:
        return data[0].get("id", "")
    return None


async def enumerate(target: str, config: "ReconConfig") -> list[str]:
    """
    Query the latest Common Crawl index for URLs matching *target*.
    Extract and normalise all subdomains found.
    Raises RuntimeError on connection or API failures.
    """
    results: list[str] = []

    async with http_session(timeout=config.timeout) as session:
        index_id = await _get_latest_index(session, config.timeout)
        if not index_id:
            logger.warning("Common Crawl: could not retrieve index list")
            raise RuntimeError("Common Crawl connection failed: index list unavailable")

        url = _CC_SEARCH_URL.format(index=index_id)
        params = {
            "url":      f"*.{target}",
            "output":   "json",
            "fl":       "url",
            "collapse": "urlkey",
            "limit":    "10000",
        }
        text = await fetch_text(
            session, url, params=params, retries=config.retries, timeout=config.timeout
        )
        if text is None:
            raise NetworkError("Common Crawl API request failed: no response data received")

        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                u = entry.get("url", "")
                if u:
                    results.append(u)
            except (json.JSONDecodeError, AttributeError):
                results.append(line)

    normalised = filter_and_normalize(results, base_domain=target)
    logger.info("Common Crawl → %d subdomains discovered", len(normalised))
    return normalised
