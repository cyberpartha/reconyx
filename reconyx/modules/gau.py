"""
RECONYX Source: GAU (GetAllUrls) adapter
Runs the GAU binary when available to fetch historical URLs.
Subdomains are extracted from the collected URLs.
Install: go install github.com/lc/gau/v2/cmd/gau@latest
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

logger = logging.getLogger("reconyx.sources.gau")

SOURCE_NAME = "GAU"
TOOL_NAME   = "gau"


async def enumerate(target: str, config: "ReconConfig") -> list[str]:
    """
    Run GAU (GetAllUrls) to collect historical URLs, then extract subdomains.
    Uses configurable timeout and preserves valid partial output on timeout.
    """
    if not tool_available(TOOL_NAME):
        logger.warning(
            "GAU not found on PATH or known locations. "
            "Install: go install github.com/lc/gau/v2/cmd/gau@latest"
        )
        return []

    timeout = getattr(config, "gau_timeout", getattr(config, "timeout", 45))
    cmd = [
        TOOL_NAME,
        "--subs",
        "--threads", "5",
        target,
    ]

    try:
        output, timed_out = await run_tool_with_partial(cmd, timeout=timeout)
    except PartialResultError:
        raise
    except Exception as exc:
        logger.warning("GAU execution error: %s", exc)
        raise RuntimeError(f"GAU execution failed: {exc}") from exc

    raw = output.splitlines() if output else []
    normalised = filter_and_normalize(raw, base_domain=target)

    if timed_out:
        if normalised:
            logger.info("GAU timed out after %ds but preserved %d partial findings", timeout, len(normalised))
            raise PartialResultError(normalised, f"timed out after {timeout}s (partial findings preserved)")
        logger.warning("GAU timed out after %ds with 0 findings", timeout)
        raise TimeoutError(f"timed out after {timeout}s")

    logger.info("GAU → %d subdomains discovered", len(normalised))
    return normalised
