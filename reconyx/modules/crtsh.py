"""
RECONYX Source: crt.sh
Certificate Transparency log aggregator.
Uses the JSON API — no authentication required.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from reconyx.utils import fetch_json, filter_and_normalize, http_session

if TYPE_CHECKING:
    from reconyx.config import ReconConfig

logger = logging.getLogger("reconyx.sources.crtsh")

SOURCE_NAME = "crt.sh"
_BASE_URL = "https://crt.sh/"


async def enumerate(target: str, config: "ReconConfig") -> list[str]:
    """
    Query crt.sh for all certificates issued to *target* and its subdomains.
    Returns a deduplicated, normalised list of discovered hostnames.
    Raises RuntimeError on total connection failure.
    """
    results: list[str] = []
    success_responses = 0

    async with http_session(timeout=config.timeout) as session:
        queries = [f"%.{target}", target]

        for query in queries:
            params = {"q": query, "output": "json"}
            data = await fetch_json(
                session, _BASE_URL, params=params, retries=config.retries
            )

            if data is not None:
                success_responses += 1

            if data and isinstance(data, list):
                for entry in data:
                    name_value: str = entry.get("name_value", "")
                    common_name: str = entry.get("common_name", "")
                    for name in (name_value + "\n" + common_name).splitlines():
                        name = name.strip()
                        if name:
                            results.append(name)

            await asyncio.sleep(config.rate_limit_delay)

    if success_responses == 0:
        raise RuntimeError("crt.sh API connection failed or timed out")

    normalised = filter_and_normalize(results, base_domain=target)
    logger.info("crt.sh → %d subdomains discovered", len(normalised))
    return normalised
