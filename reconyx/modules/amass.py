"""
RECONYX Source: OWASP Amass (adapter)
Runs the Amass binary in passive mode when available.
Install: go install -v github.com/owasp-amass/amass/v4/...@master
"""

from __future__ import annotations

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

logger = logging.getLogger("reconyx.sources.amass")

SOURCE_NAME = "OWASP Amass"
TOOL_NAME   = "amass"


async def enumerate(target: str, config: "ReconConfig") -> list[str]:
    """
    Run Amass in passive enum mode and collect subdomains.
    Returns empty list if not installed. Preserves partial findings on timeout.
    """
    if not tool_available(TOOL_NAME):
        logger.warning(
            "Amass not found on PATH or known locations. "
            "Install: go install -v github.com/owasp-amass/amass/v4/...@master"
        )
        return []

    timeout = getattr(config, "amass_timeout", 300)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="reconyx_amass_"
    ) as tf:
        out_file = tf.name

    cmd = [
        TOOL_NAME, "enum",
        "-passive",
        "-d", target,
        "-o", out_file,
    ]

    timed_out = False
    try:
        await run_tool(cmd, timeout=timeout)
    except (TimeoutError, Exception) as exc:
        if isinstance(exc, TimeoutError) or "timed out" in str(exc).lower():
            timed_out = True
        else:
            logger.warning("Amass execution error: %s", exc)
            raise RuntimeError(f"Amass failed: {exc}") from exc

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
            logger.info("Amass timed out after %ds but preserved %d partial findings", timeout, len(normalised))
            raise PartialResultError(normalised, f"timed out after {timeout}s (partial findings preserved)")
        logger.warning("Amass timed out after %ds with 0 findings", timeout)
        raise TimeoutError(f"timed out after {timeout}s")

    logger.info("Amass → %d subdomains discovered", len(normalised))
    return normalised
