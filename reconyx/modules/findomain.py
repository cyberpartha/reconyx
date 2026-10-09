"""
RECONYX Source: Findomain (adapter)
Runs the Findomain binary when available.
Install: https://github.com/Findomain/Findomain
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

logger = logging.getLogger("reconyx.sources.findomain")

SOURCE_NAME = "Findomain"
TOOL_NAME   = "findomain"


async def enumerate(target: str, config: "ReconConfig") -> list[str]:
    """
    Run Findomain in quiet mode and collect discovered subdomains.
    Returns empty list if the tool is not installed.
    Preserves partial findings and cleans up temporary files on timeout.
    """
    if not tool_available(TOOL_NAME):
        logger.warning(
            "Findomain not found on PATH or known locations. "
            "Install: https://github.com/Findomain/Findomain"
        )
        return []

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="reconyx_fd_"
    ) as tf:
        out_file = tf.name

    cmd = [
        TOOL_NAME,
        "-t", target,
        "-u", out_file,
        "-q",
    ]

    timeout = config.timeout
    timed_out = False
    try:
        await run_tool(cmd, timeout=timeout)
    except (TimeoutError, asyncio.TimeoutError):
        timed_out = True
    except RuntimeError as exc:
        logger.warning("Findomain error: %s", exc)
        return []

    out_path = Path(out_file)
    raw: list[str] = []
    if out_path.exists():
        try:
            raw = out_path.read_text(encoding="utf-8").splitlines()
        finally:
            try:
                out_path.unlink()
            except OSError:
                pass

    normalised = filter_and_normalize(raw, base_domain=target)

    if timed_out:
        if normalised:
            logger.info(
                "Findomain timed out after %ds but preserved %d partial findings",
                timeout, len(normalised),
            )
            raise PartialResultError(
                normalised,
                f"Findomain timed out after {timeout}s ({len(normalised)} partial findings preserved)",
            )
        logger.warning("Findomain timed out after %ds with 0 findings", timeout)
        raise TimeoutError(f"Findomain timed out after {timeout}s")

    logger.info("Findomain → %d subdomains discovered", len(normalised))
    return normalised
