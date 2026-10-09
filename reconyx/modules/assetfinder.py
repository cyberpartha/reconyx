"""
RECONYX Source: Assetfinder (adapter)
Runs the Assetfinder binary when available.
Install: go install github.com/tomnomnom/assetfinder@latest
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from reconyx.utils import (
    PartialResultError,
    filter_and_normalize,
    run_tool_with_partial,
    tool_available,
)

if TYPE_CHECKING:
    from reconyx.config import ReconConfig

logger = logging.getLogger("reconyx.sources.assetfinder")

SOURCE_NAME = "Assetfinder"
TOOL_NAME   = "assetfinder"


async def enumerate(target: str, config: "ReconConfig") -> list[str]:
    """
    Run Assetfinder and collect discovered subdomains.
    Returns empty list if the tool is not installed.
    Captures stdout line-by-line and preserves partial findings on timeout.
    """
    if not tool_available(TOOL_NAME):
        logger.warning(
            "Assetfinder not found on PATH. "
            "Install: go install github.com/tomnomnom/assetfinder@latest"
        )
        return []

    timeout = config.timeout
    cmd = [TOOL_NAME, "--subs-only", target]
    try:
        output, timed_out = await run_tool_with_partial(cmd, timeout=timeout)
    except RuntimeError as exc:
        logger.warning("Assetfinder error: %s", exc)
        return []

    raw = output.splitlines() if output else []
    normalised = filter_and_normalize(raw, base_domain=target)

    if timed_out:
        if normalised:
            logger.info(
                "Assetfinder timed out after %ds but preserved %d partial findings",
                timeout, len(normalised),
            )
            raise PartialResultError(
                normalised,
                f"Assetfinder timed out after {timeout}s ({len(normalised)} partial findings preserved)",
            )
        logger.warning("Assetfinder timed out after %ds with 0 findings", timeout)
        raise TimeoutError(f"Assetfinder timed out after {timeout}s")

    logger.info("Assetfinder → %d subdomains discovered", len(normalised))
    return normalised
