"""
RECONYX Reconnaissance Engine
Orchestrates multi-source subdomain discovery, normalization,
ProjectDiscovery HTTPX probing, and result persistence.
"""

from __future__ import annotations

import asyncio
import importlib
import logging
import time
from datetime import datetime, timezone
from typing import Any

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from reconyx.banner import print_phase, print_status
from reconyx.config import ReconConfig
from reconyx.console import get_console
from reconyx.diff import build_diff_report, compute_diff
from reconyx.modules.httpx_probe import probe_subdomains
from reconyx.output import OutputManager, build_scan_summary, build_summary
from reconyx.scope import ScopeManager
from reconyx.utils import filter_and_normalize, setup_logging, tool_available

logger = logging.getLogger("reconyx.engine")
console = get_console()

# Registry: source_name → module path
SOURCE_REGISTRY: dict[str, str] = {
    "crtsh":          "reconyx.modules.crtsh",
    "alienvault":     "reconyx.modules.alienvault",
    "wayback":        "reconyx.modules.wayback",
    "commoncrawl":    "reconyx.modules.commoncrawl",
    "hackertarget":   "reconyx.modules.hackertarget",
    "virustotal":     "reconyx.modules.virustotal",
    "securitytrails": "reconyx.modules.securitytrails",
    "subfinder":      "reconyx.modules.subfinder",
    "amass":          "reconyx.modules.amass",
    "assetfinder":    "reconyx.modules.assetfinder",
    "findomain":      "reconyx.modules.findomain",
    "gau":            "reconyx.modules.gau",
}

# External tool sources and their binary names
TOOL_SOURCES: dict[str, str] = {
    "subfinder":   "subfinder",
    "amass":       "amass",
    "assetfinder": "assetfinder",
    "findomain":   "findomain",
    "gau":         "gau",
}


class ReconEngine:
    """
    Central orchestration engine for RECONYX v2.0.
    Manages source execution, result merging, live HTTP probing, and output generation.
    """

    def __init__(self, config: ReconConfig) -> None:
        self.config = config
        self.output = OutputManager(config.output_base, config.target)
        self.scope  = ScopeManager(
            target         = config.target,
            allowed        = config.scope_allowed,
            excluded       = config.scope_excluded,
            wildcard_scope = config.wildcard_scope,
        )
        setup_logging(config.log_level, config.log_file)
        self._source_stats: dict[str, dict[str, Any]] = {}
        self._failures: dict[str, str] = {}
        self._timeouts: dict[str, str] = {}

    async def run(self) -> dict[str, Any]:
        """Execute the full 4-phase reconnaissance pipeline."""
        t_start = time.perf_counter()
        target  = self.config.target

        print_status(f"Target: [bold cyan]{target}[/bold cyan]", "info")
        print_status(f"Output: [bold]{self.output.base}[/bold]", "info")

        previous_subs = self.output.previous_subdomains()

        # ── Phase 1: Subdomain Enumeration ───────────────────────────
        print_phase(1, 4, "Enumerating subdomains")
        raw_findings = await self._run_sources()

        # ── Phase 2: Normalizing and Deduplicating ────────────────────
        print_phase(2, 4, "Normalizing and deduplicating")
        all_raw: list[str] = []
        for subs in raw_findings.values():
            all_raw.extend(subs)

        print_status(f"Aggregated {len(all_raw)} raw findings from all sources.", "info")
        normalised = filter_and_normalize(all_raw, base_domain=target)
        in_scope = self.scope.filter(normalised)
        print_status(f"Normalized into {len(in_scope)} unique in-scope subdomains.", "success")

        # Save recon.txt immediately so it's available for inspection and HTTPX
        recon_file = self.output.save_subdomains(in_scope)

        diff_result = compute_diff(in_scope, previous_subs)
        diff_report = build_diff_report(target, diff_result)
        if diff_result.new:
            self.output.save_new_subdomains(diff_result.new)
            print_status(f"Identified {len(diff_result.new)} new subdomains since previous scan.", "info")
        self.output.save_diff(diff_report)

        # ── Phase 3: Identifying Live Websites ────────────────────────
        print_phase(3, 4, "Identifying live websites")
        live_urls: list[str] = []
        live_hosts: list[str] = []
        probe_executed = False

        if self.config.no_probe:
            print_status("Active HTTP probing disabled (--no-probe passed).", "info")
            print_status("Skipping live website detection. Subdomains preserved in recon.txt.", "info")
        elif not self.config.probe_authorised:
            print_status(
                "Active HTTP probing skipped: requires explicit authorization.",
                "warning",
            )
            print_status(
                "Pass [bold]--authorised[/bold] or configure 'probe.authorised: true' to probe live websites.",
                "info",
            )
            print_status("All discovered subdomains safely preserved in recon.txt.", "info")
        elif not in_scope:
            print_status("No in-scope subdomains discovered to probe.", "info")
        else:
            print_status("Probing responsive HTTP/HTTPS web services with ProjectDiscovery HTTPX…", "start")
            probe_data = await probe_subdomains(recon_file, self.config)
            if not probe_data["available"]:
                print_status(
                    "ProjectDiscovery HTTPX not detected on system PATH or known paths.",
                    "warning",
                )
                print_status(
                    "Checked: 'httpx', 'httpx-toolkit', /usr/bin/httpx. "
                    "Install with: sudo apt install httpx-toolkit or go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
                    "info",
                )
                print_status("Preserving all discovered subdomains in recon.txt.", "info")
            else:
                probe_executed = True
                live_urls = probe_data["live_urls"]
                live_hosts = probe_data["live_hosts"]
                json_lines = probe_data["json_lines"]
                is_timeout = probe_data.get("timed_out", False)
                is_failed = probe_data.get("failed", False)

                if is_timeout:
                    if live_urls:
                        self.output.save_live_urls(live_urls)
                        self.output.save_live_hosts(live_hosts)
                        self.output.save_httpx_jsonl(json_lines)
                        print_status(
                            f"HTTPX probe timed out (preserved [bold magenta]{len(live_urls)}[/bold magenta] "
                            f"live URLs across [bold magenta]{len(live_hosts)}[/bold magenta] hosts).",
                            "warning",
                        )
                    else:
                        print_status("HTTPX probe timed out (no live services discovered before deadline).", "timeout")
                elif is_failed:
                    if live_urls:
                        self.output.save_live_urls(live_urls)
                        self.output.save_live_hosts(live_hosts)
                        self.output.save_httpx_jsonl(json_lines)
                        print_status(
                            f"HTTPX probe encountered an error (preserved [bold magenta]{len(live_urls)}[/bold magenta] live URLs).",
                            "warning",
                        )
                    else:
                        print_status(f"HTTPX probe failed: {probe_data.get('error', 'Execution error')}", "error")
                else:
                    if live_urls:
                        self.output.save_live_urls(live_urls)
                        self.output.save_live_hosts(live_hosts)
                        self.output.save_httpx_jsonl(json_lines)
                        print_status(
                            f"Discovered [bold green]{len(live_urls)}[/bold green] live URLs across "
                            f"[bold green]{len(live_hosts)}[/bold green] responsive hosts.",
                            "success",
                        )
                    else:
                        print_status("No responsive HTTP/HTTPS web services detected.", "warning")

        # ── Phase 4: Saving Reconnaissance Results ────────────────────
        print_phase(4, 4, "Saving reconnaissance results")
        self.output.save_sources(self._source_stats)

        elapsed = time.perf_counter() - t_start
        elapsed_str = f"{elapsed:.1f}s"

        sources_ok = sum(1 for s in self._source_stats.values() if s.get("status") == "SUCCESS")
        sources_empty = sum(1 for s in self._source_stats.values() if s.get("status") == "EMPTY")
        sources_partial = sum(1 for s in self._source_stats.values() if s.get("status") == "PARTIAL")
        sources_timeout = sum(1 for s in self._source_stats.values() if s.get("status") == "TIMEOUT")
        sources_fail = sum(1 for s in self._source_stats.values() if s.get("status") == "FAILED")
        sources_skipped = sum(1 for s in self._source_stats.values() if s.get("status") == "SKIPPED")

        status_counts = {
            "SUCCESS": sources_ok,
            "EMPTY": sources_empty,
            "PARTIAL": sources_partial,
            "TIMEOUT": sources_timeout,
            "FAILED": sources_fail,
            "SKIPPED": sources_skipped,
        }
        per_source_counts = {k: v.get("count", 0) for k, v in self._source_stats.items()}

        scan_summary = build_scan_summary(
            target             = target,
            total_raw          = len(all_raw),
            unique             = len(in_scope),
            new                = len(diff_result.new),
            sources_attempted  = len(self._source_stats),
            sources_ok         = sources_ok,
            sources_fail       = sources_fail,
            per_source_counts  = per_source_counts,
            failures           = self._failures,
            live_count         = len(live_urls),
            elapsed            = elapsed_str,
            output_dir         = str(self.output.base),
            version            = self.config.version,
            sources_empty      = sources_empty,
            sources_timeout    = sources_timeout,
            sources_skipped    = sources_skipped,
            sources_partial    = sources_partial,
            status_counts      = status_counts,
            timeouts           = self._timeouts,
        )
        self.output.save_scan_summary(scan_summary)

        saved_subs = self.output.read_lines("recon.txt")
        if in_scope:
            print_status(
                f"Saved recon.txt ({len(saved_subs)} subdomains in file; {len(in_scope)} discovered in current scan)",
                "success",
            )
        elif saved_subs:
            print_status(
                f"Preserved recon.txt ({len(saved_subs)} existing subdomains preserved; 0 discovered in current scan)",
                "info",
            )
        else:
            print_status(
                "Saved recon.txt (0 subdomains in file; 0 discovered in current scan)",
                "empty",
            )
        if probe_executed and live_urls:
            print_status(f"Saved live.txt ({len(live_urls)} URLs)", "success")
            print_status(f"Saved live_hosts.txt ({len(live_hosts)} hosts)", "success")
            print_status("Saved httpx_results.jsonl", "success")
        print_status("Saved scan_summary.json", "success")

        return {
            "target": target,
            "total_raw": len(all_raw),
            "unique": len(in_scope),
            "new": len(diff_result.new),
            "sources_attempted": len(self._source_stats),
            "sources_ok": sources_ok,
            "sources_empty": sources_empty,
            "sources_partial": sources_partial,
            "sources_timeout": sources_timeout,
            "sources_fail": sources_fail,
            "sources_skipped": sources_skipped,
            "status_counts": status_counts,
            "live_count": len(live_urls),
            "elapsed": elapsed_str,
            "output_dir": str(self.output.base),
        }

    async def _run_sources(self) -> dict[str, list[str]]:
        """Run all enabled and available sources concurrently."""
        from reconyx.utils import PartialResultError

        # Check if amass is not enabled
        if not self.config.sources.get("amass", False):
            self._source_stats["amass"] = {
                "status": "SKIPPED",
                "count": 0,
                "reason": "Amass — SKIPPED (optional source)",
            }
            print_status("Amass — [dim]SKIPPED (optional source)[/dim]", "skipped")

        enabled = self.config.enabled_sources
        if not enabled:
            logger.warning("No sources enabled in configuration!")
            return {}

        semaphore = asyncio.Semaphore(self.config.concurrency)
        results: dict[str, list[str]] = {}

        # Determine which external tools are installed vs uninstalled
        active_sources: list[str] = []
        for src in enabled:
            if src in TOOL_SOURCES:
                tool_bin = TOOL_SOURCES[src]
                if not tool_available(tool_bin):
                    self._source_stats[src] = {
                        "status": "SKIPPED",
                        "count": 0,
                        "reason": f"Tool '{tool_bin}' not installed",
                    }
                    self._failures[src] = f"Tool '{tool_bin}' not installed"
                    print_status(f"[dim]{src}[/dim] — skipped (tool not installed)", "warning")
                    continue
            # For API key sources, check if required keys are provided
            if src in ("virustotal", "securitytrails"):
                if not self.config.api_keys.get(src):
                    self._source_stats[src] = {
                        "status": "SKIPPED",
                        "count": 0,
                        "reason": f"API key for '{src}' not configured",
                    }
                    self._failures[src] = f"API key for '{src}' not configured"
                    print_status(f"[dim]{src}[/dim] — skipped (no API key configured)", "warning")
                    continue
            active_sources.append(src)

        if not active_sources:
            return {}

        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30, style="cyan", complete_style="green"),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task(
                "[cyan]Running discovery sources…", total=len(active_sources)
            )

            async def run_one(source_name: str) -> None:
                async with semaphore:
                    mod_path = SOURCE_REGISTRY.get(source_name)
                    if not mod_path:
                        self._source_stats[source_name] = {"status": "SKIPPED", "count": 0}
                        progress.advance(task_id)
                        return

                    t0 = time.perf_counter()
                    try:
                        mod = importlib.import_module(mod_path)
                        source_label = getattr(mod, "SOURCE_NAME", source_name)
                        source_timeout = (
                            self.config.amass_timeout if source_name == "amass"
                            else (self.config.gau_timeout if source_name == "gau"
                            else self.config.timeout)
                        )
                        subs: list[str] = await asyncio.wait_for(
                            mod.enumerate(self.config.target, self.config),
                            timeout=source_timeout,
                        )
                        elapsed = time.perf_counter() - t0
                        results[source_name] = subs
                        status_str = "SUCCESS" if subs else "EMPTY"
                        self._source_stats[source_name] = {
                            "status":  status_str,
                            "count":   len(subs),
                            "elapsed": f"{elapsed:.1f}s",
                            "label":   source_label,
                        }
                        if subs:
                            print_status(
                                f"[green]{source_label}[/green] → {len(subs)} subdomains  "
                                f"[dim]({elapsed:.1f}s)[/dim]",
                                "success",
                            )
                        else:
                            print_status(
                                f"[dim cyan]{source_label}[/dim cyan] → 0 subdomains  "
                                f"[dim]({elapsed:.1f}s)[/dim]",
                                "empty",
                            )
                    except PartialResultError as exc:
                        elapsed = time.perf_counter() - t0
                        partial_subs = exc.partial_results
                        results[source_name] = partial_subs
                        self._source_stats[source_name] = {
                            "status":  "PARTIAL",
                            "count":   len(partial_subs),
                            "elapsed": f"{elapsed:.1f}s",
                            "label":   source_name,
                            "warning": str(exc),
                        }
                        print_status(
                            f"[bold magenta]{source_name}[/bold magenta] — partial completion ({len(partial_subs)} findings saved, timeout/interrupted)",
                            "partial",
                        )
                    except (TimeoutError, asyncio.TimeoutError) as exc:
                        elapsed = time.perf_counter() - t0
                        results[source_name] = []
                        self._source_stats[source_name] = {
                            "status":  "TIMEOUT",
                            "count":   0,
                            "elapsed": f"{elapsed:.1f}s",
                            "error":   str(exc),
                            "label":   source_name,
                        }
                        self._timeouts[source_name] = f"Timeout ({elapsed:.1f}s)"
                        print_status(f"[yellow]{source_name}[/yellow] — timed out ({elapsed:.1f}s)", "timeout")
                    except Exception as exc:
                        elapsed = time.perf_counter() - t0
                        logger.warning("Source %s error: %s", source_name, exc)
                        results[source_name] = []
                        self._source_stats[source_name] = {
                            "status":  "FAILED",
                            "count":   0,
                            "elapsed": f"{elapsed:.1f}s",
                            "error":   str(exc),
                            "label":   source_name,
                        }
                        self._failures[source_name] = str(exc)
                        print_status(f"[red]{source_name}[/red] — {exc}", "error")
                    finally:
                        progress.advance(task_id)

            await asyncio.gather(*[run_one(s) for s in active_sources])

        return results
