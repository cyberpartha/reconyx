"""
RECONYX Diff Module
Compares current scan results against a previous scan to detect
newly discovered subdomains, known subdomains, and missing ones.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

logger = logging.getLogger("reconyx.diff")


class DiffResult(NamedTuple):
    new: list[str]           # In current scan, not in previous
    known: list[str]         # In both scans
    missing: list[str]       # In previous scan, not in current (NOT necessarily offline)
    previous_count: int
    current_count: int


def compute_diff(
    current: list[str],
    previous: list[str],
) -> DiffResult:
    """
    Compute the difference between two subdomain lists.

    Note: ``missing`` subdomains may be offline, out of scope, or simply
    not discovered by passive sources this run. Do NOT label them offline.
    """
    current_set  = set(current)
    previous_set = set(previous)

    new     = sorted(current_set - previous_set)
    known   = sorted(current_set & previous_set)
    missing = sorted(previous_set - current_set)

    logger.info(
        "Diff — new: %d, known: %d, missing from latest scan: %d",
        len(new), len(known), len(missing),
    )
    return DiffResult(
        new=new,
        known=known,
        missing=missing,
        previous_count=len(previous),
        current_count=len(current),
    )


def build_diff_report(
    target: str,
    diff: DiffResult,
    scan_id: str | None = None,
) -> dict:
    """Build a serialisable diff report dictionary."""
    return {
        "target": target,
        "scan_id": scan_id or datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "statistics": {
            "previous_count": diff.previous_count,
            "current_count": diff.current_count,
            "new_count": len(diff.new),
            "known_count": len(diff.known),
            "missing_from_latest_scan": len(diff.missing),
        },
        "new_subdomains": diff.new,
        "known_subdomains": diff.known,
        "missing_from_latest_scan": diff.missing,
        "note": (
            "missing_from_latest_scan does not imply the subdomain is offline. "
            "It may not have been discovered by passive sources this run."
        ),
    }
