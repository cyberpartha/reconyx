"""
RECONYX Source: SecurityTrails
Queries the SecurityTrails subdomain history API.
Requires a SecurityTrails API key.
Set: RECONYX_ST_KEY or ST_API_KEY environment variable.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from reconyx.utils import fetch_json, filter_and_normalize, http_session

if TYPE_CHECKING:
    from reconyx.config import ReconConfig

logger = logging.getLogger("reconyx.sources.securitytrails")

SOURCE_NAME = "SecurityTrails"
_SUBDOMAINS_URL = "https://api.securitytrails.com/v1/domain/{domain}/subdomains"


async def enumerate(target: str, config: "ReconConfig") -> list[str]:
    """
    Query SecurityTrails API for subdomains of the target domain.
    Requires a valid API key in config.api_keys['securitytrails'].
    """
    api_key = config.api_keys.get("securitytrails", "").strip()
    if not api_key:
        logger.warning("SecurityTrails: No API key configured — skipping source")
        return []

    headers = {"APIKEY": api_key}
    url = _SUBDOMAINS_URL.format(domain=target)
    results: list[str] = []

    async with http_session(timeout=config.timeout, headers=headers) as session:
        params = {"children_only": "false", "include_inactive": "true"}
        data = await fetch_json(session, url, params=params, retries=config.retries)

        if not data or not isinstance(data, dict):
            return []

        subdomains = data.get("subdomains", [])
        for sub in subdomains:
            if sub:
                full = f"{sub.strip()}.{target}"
                results.append(full)

        logger.debug(
            "SecurityTrails: %d subdomains in API response", len(subdomains)
        )

    normalised = filter_and_normalize(results, base_domain=target)
    logger.info("SecurityTrails → %d subdomains discovered", len(normalised))
    return normalised
