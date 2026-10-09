"""
RECONYX Output Module
Handles creation of the output directory tree, writing result files:
  - recon.txt
  - live.txt
  - live_hosts.txt
  - httpx_results.jsonl
  - scan_summary.json
Protects against overwriting existing valid results with empty files.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("reconyx.output")


class OutputManager:
    """Creates and manages all output files for a single scan run."""

    def __init__(self, base_dir: str | Path, target: str) -> None:
        self.target = target
        self.base = Path(base_dir) / target
        self.base.mkdir(parents=True, exist_ok=True)
        logger.debug("Output directory: %s", self.base)

    # ------------------------------------------------------------------
    # File helpers
    # ------------------------------------------------------------------

    def path(self, filename: str) -> Path:
        return self.base / filename

    def write_lines(
        self,
        filename: str,
        lines: list[str],
        *,
        overwrite: bool = True,
        protect_non_empty: bool = False,
    ) -> Path:
        """
        Write a sorted, deduplicated list of lines to a file (one per line).
        If protect_non_empty is True and existing file has data but lines is empty,
        preserves existing file and emits a warning.
        """
        dest = self.path(filename)
        if protect_non_empty and dest.exists() and not lines:
            existing_lines = self.read_lines(filename)
            if existing_lines:
                logger.warning(
                    "[!] Safety alert: %s already has %d findings, but current scan yielded 0. "
                    "Preserving previous file to avoid data loss.",
                    dest.name,
                    len(existing_lines),
                )
                return dest

        mode = "w" if overwrite else "a"
        with dest.open(mode, encoding="utf-8") as fh:
            unique_sorted = sorted(set(l.strip() for l in lines if l.strip()))
            fh.write("\n".join(unique_sorted))
            if unique_sorted:
                fh.write("\n")
        logger.debug("Written %d lines → %s", len(unique_sorted), dest)
        return dest

    def write_json(self, filename: str, data: Any, *, overwrite: bool = True) -> Path:
        """Write a JSON-serialisable object to a file."""
        dest = self.path(filename)
        mode = "w" if overwrite else "x"
        with dest.open(mode, encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        logger.debug("Written JSON → %s", dest)
        return dest

    def write_jsonl(self, filename: str, lines: list[str | dict], *, overwrite: bool = True) -> Path:
        """Write JSON Lines (one JSON per line)."""
        dest = self.path(filename)
        mode = "w" if overwrite else "a"
        with dest.open(mode, encoding="utf-8") as fh:
            for item in lines:
                if isinstance(item, str):
                    fh.write(item.strip() + "\n")
                else:
                    fh.write(json.dumps(item, default=str) + "\n")
        logger.debug("Written %d JSONL lines → %s", len(lines), dest)
        return dest

    def read_lines(self, filename: str) -> list[str]:
        """Read a line-delimited text file; returns empty list if missing."""
        dest = self.path(filename)
        if not dest.exists():
            return []
        with dest.open("r", encoding="utf-8") as fh:
            return [l.strip() for l in fh if l.strip()]

    def read_json(self, filename: str) -> Any:
        """Read a JSON file; returns None if missing or invalid."""
        dest = self.path(filename)
        if not dest.exists():
            return None
        try:
            with dest.open("r", encoding="utf-8") as fh:
                return json.load(fh)
        except json.JSONDecodeError as exc:
            logger.warning("Failed to parse %s: %s", dest, exc)
            return None

    # ------------------------------------------------------------------
    # High-level write methods (v2.0 specifications)
    # ------------------------------------------------------------------

    def save_subdomains(self, subdomains: list[str]) -> Path:
        """
        Save the final normalised, in-scope subdomain list to recon.txt.
        Never overwrites previous non-empty recon.txt with empty file without warning.
        """
        return self.write_lines("recon.txt", subdomains, protect_non_empty=True)

    def save_new_subdomains(self, new_subs: list[str]) -> Path:
        """Save newly discovered subdomains to new_subdomains.txt."""
        return self.write_lines("new_subdomains.txt", new_subs)

    def save_live_urls(self, urls: list[str]) -> Path:
        """Save all responsive HTTP/HTTPS URLs to live.txt (one URL per line)."""
        return self.write_lines("live.txt", urls)

    def save_live_hosts(self, hosts: list[str | dict]) -> Path:
        """
        Save unique hostnames corresponding to responsive services to live_hosts.txt.
        Accepts list of hostnames or list of dicts with 'host'.
        """
        hostnames: list[str] = []
        for h in hosts:
            if isinstance(h, str):
                hostnames.append(h)
            elif isinstance(h, dict) and "host" in h:
                hostnames.append(h["host"])
        return self.write_lines("live_hosts.txt", hostnames)

    def save_httpx_jsonl(self, json_lines: list[str | dict]) -> Path:
        """Save structured HTTPX probe results to httpx_results.jsonl."""
        return self.write_jsonl("httpx_results.jsonl", json_lines)

    def save_sources(self, sources_data: dict) -> Path:
        """Save per-source enumeration statistics."""
        return self.write_json("sources.json", sources_data)

    def save_diff(self, diff_data: dict) -> Path:
        """Save comparison diff metadata."""
        return self.write_json("diff.json", diff_data)

    def save_scan_summary(self, summary: dict) -> Path:
        """Save scan metadata to scan_summary.json and summary.json."""
        self.write_json("summary.json", summary)
        return self.write_json("scan_summary.json", summary)

    def save_summary(self, summary: dict) -> Path:
        """Backwards compatibility alias for save_scan_summary."""
        return self.save_scan_summary(summary)

    def save_technologies(self, tech: dict) -> Path:
        return self.write_json("technologies.json", tech)

    def save_urls(self, urls: list[str]) -> Path:
        return self.write_lines("urls.txt", urls)

    def save_endpoints(self, endpoints: list[str]) -> Path:
        return self.write_lines("endpoints.txt", endpoints)

    # ------------------------------------------------------------------
    # History / versioning
    # ------------------------------------------------------------------

    def archive_previous(self, filename: str) -> Path | None:
        """
        Rename an existing results file to a timestamped backup.
        Returns the backup path, or None if no file existed.
        """
        dest = self.path(filename)
        if not dest.exists():
            return None
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = self.path(f"{dest.stem}.{ts}{dest.suffix}")
        dest.rename(backup)
        logger.info("Archived %s → %s", dest.name, backup.name)
        return backup

    def previous_subdomains(self) -> list[str]:
        """Load subdomains from the most recent recon.txt."""
        return self.read_lines("recon.txt")

    # ------------------------------------------------------------------
    # Repr
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return f"OutputManager(base={self.base!r})"


def build_scan_summary(
    target: str,
    total_raw: int,
    unique: int,
    new: int,
    sources_attempted: int,
    sources_ok: int,
    sources_fail: int,
    per_source_counts: dict,
    failures: dict,
    live_count: int,
    elapsed: str,
    output_dir: str,
    version: str = "2.0.4",
    sources_empty: int = 0,
    sources_timeout: int = 0,
    sources_skipped: int = 0,
    sources_partial: int = 0,
    status_counts: dict | None = None,
    timeouts: dict | None = None,
) -> dict:
    """Construct the comprehensive summary saved to scan_summary.json."""
    if status_counts is None:
        status_counts = {
            "SUCCESS": sources_ok,
            "EMPTY": sources_empty,
            "FAILED": sources_fail,
            "TIMEOUT": sources_timeout,
            "SKIPPED": sources_skipped,
            "PARTIAL": sources_partial,
        }

    return {
        "target": target,
        "version": version,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "elapsed_seconds": elapsed,
        "sources_attempted": sources_attempted,
        "sources_successful": sources_ok,
        "sources_empty": sources_empty,
        "sources_failed": sources_fail,
        "sources_timeout": sources_timeout,
        "sources_skipped": sources_skipped,
        "sources_partial": sources_partial,
        "sources_failed_or_skipped": sources_fail + sources_skipped,
        "status_counts": status_counts,
        "per_source_counts": per_source_counts,
        "failures": failures,
        "timeouts": timeouts or {},
        "total_raw": total_raw,
        "unique_subdomains": unique,
        "new_subdomains": new,
        "live_websites": live_count,
        "output_directory": output_dir,
    }


def build_summary(
    target: str,
    mode: str = "full",
    total_raw: int = 0,
    unique: int = 0,
    new: int = 0,
    sources_ok: int = 0,
    sources_fail: int = 0,
    elapsed: str = "0.0s",
    output_dir: str = "",
    live_count: int = 0,
) -> dict:
    """Backwards-compatible summary generator."""
    return {
        "target": target,
        "version": "2.0.0",
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "total_raw": total_raw,
        "unique": unique,
        "new_subdomains": new,
        "sources_successful": sources_ok,
        "sources_failed": sources_fail,
        "live_websites": live_count,
        "elapsed_seconds": elapsed,
        "output_dir": output_dir,
    }
