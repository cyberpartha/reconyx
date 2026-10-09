"""
RECONYX Source: Subfinder (Go tool adapter)
Runs the Subfinder binary as a subprocess when available.
Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
"""

from __future__ import annotations

import asyncio
import logging
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from reconyx.utils import (
    PartialResultError,
    filter_and_normalize,
    run_tool,
    tool_available,
)

if TYPE_CHECKING:
    from reconyx.config import ReconConfig

logger = logging.getLogger("reconyx.sources.subfinder")

SOURCE_NAME = "Subfinder"
TOOL_NAME   = "subfinder"


async def enumerate(target: str, config: "ReconConfig") -> list[str]:
    """
    Run Subfinder in silent mode and collect discovered subdomains.
    Returns empty list if the tool is not installed.
    Preserves partial findings and cleans up temporary files on timeout.
    """
    if not tool_available(TOOL_NAME):
        logger.warning(
            "Subfinder not found on PATH. "
            "Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        )
        return []

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="reconyx_sf_"
    ) as tf:
        out_file = tf.name

    timeout = config.timeout
    cmd = [
        TOOL_NAME,
        "-d", target,
        "-silent",
        "-o", out_file,
        "-timeout", str(timeout),
    ]

    timed_out = False
    try:
        await run_tool(cmd, timeout=timeout)
    except (TimeoutError, asyncio.TimeoutError):
        timed_out = True
    except RuntimeError as exc:
        logger.warning("Subfinder error: %s", exc)
        return []

    out_path = Path(out_file)
    raw: list[str] = []
    if out_path.exists():
        try:
            raw = out_path.read_text(encoding="utf-8").splitlines()
        finally:
            out_path.unlink(missing_ok=True)

    normalised = filter_and_normalize(raw, base_domain=target)

    if timed_out:
        if normalised:
            logger.info(
                "Subfinder timed out after %ds but preserved %d partial findings",
                timeout, len(normalised),
            )
            raise PartialResultError(
                normalised,
                f"Subfinder timed out after {timeout}s ({len(normalised)} partial findings preserved)",
            )
        logger.warning("Subfinder timed out after %ds with 0 findings", timeout)
        raise TimeoutError(f"Subfinder timed out after {timeout}s")

    logger.info("Subfinder → %d subdomains discovered", len(normalised))
    return normalised
