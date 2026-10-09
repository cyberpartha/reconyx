"""
RECONYX CLI Module
Provides command-line argument parsing and interactive menu interface.
Configured for RECONYX v2.0 full automatic reconnaissance pipeline.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import NoReturn

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich import box

from reconyx import __version__, __author__
from reconyx.banner import print_banner, print_section, print_status, print_summary
from reconyx.config import load_config, ReconConfig, DEFAULTS
from reconyx.console import get_console

console = get_console()


# ---------------------------------------------------------------------------
# Argument Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconyx",
        description="RECONYX — Advanced Bug Bounty Reconnaissance Framework (v2.0.4)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  reconyx -d example.com
  reconyx -d example.com --enable-amass
  reconyx -d example.com --authorised
  reconyx -d example.com --enable-amass --authorised
  reconyx -d example.com --no-probe
  reconyx -d example.com --sources crtsh,subfinder,findomain
  reconyx -d example.com --exclude-sources amass,commoncrawl
  reconyx -d example.com --scope "*.example.com" --output my_results/
  reconyx --version

Disclaimer & Authorisation:
  RECONYX is developed by CyberPartha for educational purposes, cybersecurity training,
  and authorized security research only. Use only on systems/domains that you own or have
  explicit written permission to assess. Unauthorized security testing may violate applicable
  laws and terms. Pass --authorised to confirm explicit written permission for active HTTP probing.
        """,
    )

    parser.add_argument(
        "-d", "--domain",
        metavar="DOMAIN",
        help="Target domain to enumerate (e.g. example.com)",
    )
    parser.add_argument(
        "--enable-amass",
        action="store_true",
        default=False,
        help="Enable OWASP Amass passive enumeration (optional source, excluded by default)",
    )
    parser.add_argument(
        "--sources",
        metavar="src1,src2",
        help="Comma-separated list of sources to use (e.g. crtsh,subfinder,alienvault)",
    )
    parser.add_argument(
        "--exclude-sources",
        metavar="src1,src2",
        help="Comma-separated list of sources to disable",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="DIR",
        default="results",
        help="Output base directory (default: results/)",
    )
    parser.add_argument(
        "--no-probe",
        action="store_true",
        default=False,
        help="Disable active HTTP probing against discovered subdomains",
    )
    parser.add_argument(
        "--authorised", "--yes-i-am-authorised",
        action="store_true",
        default=False,
        dest="authorised",
        help="Confirm explicit authorization for active HTTP probing of web services",
    )
    parser.add_argument(
        "--scope",
        metavar="domain1,domain2",
        help="Allowed scope domains (comma-separated, supports *.domain.com wildcards)",
    )
    parser.add_argument(
        "--exclude-scope",
        metavar="domain1,domain2",
        help="Excluded scope domains (comma-separated)",
    )
    parser.add_argument(
        "--wildcard-scope",
        action="store_true",
        default=False,
        help="Accept all subdomains under the root domain as in-scope",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        metavar="SECONDS",
        help="Request timeout in seconds (default: 30; overrides source-specific defaults)",
    )
    parser.add_argument(
        "--gau-timeout",
        type=int,
        default=None,
        metavar="SECONDS",
        help="Explicit timeout for GAU subprocess in seconds (default: 45)",
    )
    parser.add_argument(
        "--probe-max-time",
        type=int,
        default=None,
        metavar="SECONDS",
        help="Overall execution deadline for HTTPX probe in seconds (default: 120)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=20,
        metavar="N",
        help="Max concurrent source requests (default: 20)",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        help="Path to a custom config.yaml file",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        default=False,
        help="Suppress the visual RECONYX banner and disclaimer",
    )
    parser.add_argument(
        "--no-diff",
        action="store_true",
        default=False,
        help="Skip comparison with previous scan results",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        metavar="LEVEL",
        help="Logging level (DEBUG|INFO|WARNING|ERROR)",
    )
    parser.add_argument(
        "--log-file",
        metavar="PATH",
        default="",
        help="Write logs to this file",
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"RECONYX v{__version__} by {__author__}",
    )

    return parser


# ---------------------------------------------------------------------------
# Config Builder from CLI args
# ---------------------------------------------------------------------------

def build_config_from_args(args: argparse.Namespace) -> ReconConfig:
    """Translate parsed CLI args into a ReconConfig for the full pipeline."""
    # Build sources override map from DEFAULTS
    sources_override: dict[str, bool] = dict(DEFAULTS["sources"])

    # Amass is disabled by default in DEFAULTS; enable if flag passed
    enable_amass = getattr(args, "enable_amass", False)
    if enable_amass:
        sources_override["amass"] = True

    if getattr(args, "sources", None):
        requested = [s.strip().lower() for s in args.sources.split(",") if s.strip()]
        # Disable all known sources first, enable only requested
        for src in DEFAULTS["sources"]:
            sources_override[src] = False
        for src in requested:
            sources_override[src] = True
        # If --enable-amass was also passed, ensure amass is enabled
        if enable_amass:
            sources_override["amass"] = True

    # Explicit exclusions always take precedence (e.g. --exclude-sources amass)
    if getattr(args, "exclude_sources", None):
        for src in args.exclude_sources.split(","):
            s = src.strip().lower()
            if s:
                sources_override[s] = False

    scope_allowed = (
        [s.strip() for s in args.scope.split(",") if s.strip()]
        if getattr(args, "scope", None)
        else []
    )
    scope_excluded = (
        [s.strip() for s in args.exclude_scope.split(",") if s.strip()]
        if getattr(args, "exclude_scope", None)
        else []
    )

    no_probe = getattr(args, "no_probe", False)
    authorised = getattr(args, "authorised", False)

    cli_overrides: dict[str, Any] = {
        "target":         getattr(args, "domain", "") or "",
        "mode":           "full",
        "concurrency":    getattr(args, "concurrency", 20),
        "output_base":    getattr(args, "output", "results"),
        "log_level":      getattr(args, "log_level", "INFO"),
        "log_file":       getattr(args, "log_file", ""),
        "sources":        sources_override,
        "scope": {
            "allowed_domains":  scope_allowed,
            "excluded_domains": scope_excluded,
            "wildcard_scope":   getattr(args, "wildcard_scope", False),
        },
        "probe": {
            "enabled":    not no_probe,
            "authorised": authorised,
        },
        "no_probe":       no_probe,
        "enable_amass":   enable_amass,
    }

    explicit_timeout = getattr(args, "timeout", None)
    if explicit_timeout is not None:
        cli_overrides["timeout"] = explicit_timeout
        # Precedence: Explicit CLI --timeout sets GAU timeout as well,
        # ensuring GAU honors requested deadlines (e.g. 10s or 90s)
        cli_overrides["gau_timeout"] = explicit_timeout

    explicit_gau_timeout = getattr(args, "gau_timeout", None)
    if explicit_gau_timeout is not None:
        cli_overrides["gau_timeout"] = explicit_gau_timeout

    explicit_probe_max_time = getattr(args, "probe_max_time", None)
    if explicit_probe_max_time is not None:
        cli_overrides["probe"]["max_time"] = explicit_probe_max_time
        cli_overrides["probe_max_time"] = explicit_probe_max_time

    return load_config(
        config_path=getattr(args, "config", None),
        cli_overrides=cli_overrides,
    )


# ---------------------------------------------------------------------------
# Interactive Menu
# ---------------------------------------------------------------------------

_MENU_OPTIONS = {
    "1": ("Run Reconnaissance Pipeline (Default)",               "recon"),
    "2": ("Run Reconnaissance Pipeline (+ Amass Included)",      "recon_amass"),
    "3": ("Compare Previous Results",                            "diff"),
    "4": ("View Saved Results",                                  "view"),
    "0": ("Exit",                                                "exit"),
}


def show_interactive_menu() -> None:
    """Display the interactive menu and handle user selection."""
    table = Table(box=box.ROUNDED, border_style="cyan", show_header=False, padding=(0, 2))
    table.add_column("Option", style="bold yellow", justify="center", min_width=8)
    table.add_column("Description", style="white")

    for key, (label, _) in _MENU_OPTIONS.items():
        style = "dim" if key == "0" else ""
        table.add_row(f"[{key}]", f"[{style}]{label}[/{style}]")

    console.print(
        Panel(table, title="[bold cyan]RECONYX v2.0 Menu[/bold cyan]", border_style="cyan")
    )

    choice = Prompt.ask(
        "[bold cyan]Select an option[/bold cyan]",
        choices=list(_MENU_OPTIONS.keys()),
        default="1",
    )
    action = _MENU_OPTIONS[choice][1]

    if action == "exit":
        console.print("[bold yellow]Goodbye! Happy bug bounty hunting. 👋[/bold yellow]")
        sys.exit(0)

    if action == "view":
        _interactive_view_results()
        return

    if action == "diff":
        _interactive_diff()
        return

    # Options 1 & 2: Reconnaissance pipeline
    domain = Prompt.ask("[bold cyan]Enter target domain[/bold cyan]").strip()
    if not domain:
        console.print("[bold red]No domain provided. Exiting.[/bold red]")
        sys.exit(1)

    auth_choice = Prompt.ask(
        "[bold cyan]Are you authorised for active HTTP probing of web services?[/bold cyan] (yes/no)",
        default="no",
    )
    is_authorised = auth_choice.lower() in ("yes", "y")

    class _Args:
        domain = domain
        enable_amass = (action == "recon_amass")
        sources = None
        exclude_sources = None
        no_probe = False
        authorised = is_authorised
        scope = None
        exclude_scope = None
        wildcard_scope = False
        timeout = None
        gau_timeout = None
        concurrency = 20
        output = "results"
        log_level = "INFO"
        log_file = ""
        config = None
        no_banner = True
        no_diff = False

    cfg = build_config_from_args(_Args())
    _run_recon(cfg)


def _interactive_view_results() -> None:
    """Show a summary of previously saved results."""
    from pathlib import Path
    import json

    results_root = Path("results")
    if not results_root.exists():
        console.print("[yellow]No results directory found.[/yellow]")
        return

    targets = [d for d in results_root.iterdir() if d.is_dir()]
    if not targets:
        console.print("[yellow]No previous scan results found.[/yellow]")
        return

    table = Table(
        title="[bold cyan]Previous Reconnaissance Scans[/bold cyan]",
        box=box.SIMPLE_HEAVY,
        border_style="cyan",
    )
    table.add_column("Target",     style="bold white")
    table.add_column("Subdomains", style="bold green",  justify="right")
    table.add_column("Live Hosts", style="bold cyan",   justify="right")
    table.add_column("Last Scan",  style="dim white")

    for target_dir in sorted(targets):
        count = 0
        live_count = 0
        ts = "—"
        recon_file = target_dir / "recon.txt"
        live_file = target_dir / "live_hosts.txt"
        summary_file = target_dir / "scan_summary.json"
        if not summary_file.exists():
            summary_file = target_dir / "summary.json"

        if recon_file.exists():
            count = sum(1 for _ in recon_file.open(encoding="utf-8"))
        if live_file.exists():
            live_count = sum(1 for _ in live_file.open(encoding="utf-8"))
        if summary_file.exists():
            try:
                data = json.loads(summary_file.read_text(encoding="utf-8"))
                ts = data.get("timestamp", "—")[:19].replace("T", " ")
            except Exception:
                pass
        table.add_row(target_dir.name, str(count), str(live_count), ts)

    console.print(table)


def _interactive_diff() -> None:
    """Run diff comparison interactively."""
    domain = Prompt.ask("[bold cyan]Enter target domain to compare[/bold cyan]").strip()
    if not domain:
        return
    from reconyx.output import OutputManager

    out = OutputManager("results", domain)
    prev = out.previous_subdomains()
    if not prev:
        console.print(f"[yellow]No previous scan found for {domain}[/yellow]")
        return

    console.print(f"[green]Found {len(prev)} subdomains from previous scan.[/green]")
    console.print("[yellow]Running a new scan to compare findings…[/yellow]")

    class _Args:
        pass
    args = _Args()
    args.domain = domain  # type: ignore
    args.enable_amass = False
    args.sources = None
    args.exclude_sources = None
    args.no_probe = True
    args.authorised = False
    args.scope = None
    args.exclude_scope = None
    args.wildcard_scope = False
    args.timeout = None
    args.gau_timeout = None
    args.concurrency = 20
    args.output = "results"
    args.log_level = "INFO"
    args.log_file = ""
    args.config = None
    args.no_banner = True
    args.no_diff = False

    cfg = build_config_from_args(args)  # type: ignore
    _run_recon(cfg)


# ---------------------------------------------------------------------------
# Recon Runner
# ---------------------------------------------------------------------------

def _run_recon(config: ReconConfig) -> None:
    """Validate target domain and kick off the async recon engine."""
    from reconyx.utils import is_valid_domain, normalize_domain

    if config.timeout <= 0:
        console.print(
            f"\n[bold red][✗] Invalid timeout: {config.timeout}s[/bold red]\n"
            "    Timeout must be a positive integer greater than 0.\n"
        )
        sys.exit(1)

    if getattr(config, "probe_max_time", 120) <= 0:
        console.print(
            f"\n[bold red][✗] Invalid probe max time: {config.probe_max_time}s[/bold red]\n"
            "    Probe max time must be a positive integer greater than 0.\n"
        )
        sys.exit(1)

    target = normalize_domain(config.target)
    if not target or not is_valid_domain(target):
        console.print(
            f"\n[bold red][✗] Invalid target domain: '{config.target}'[/bold red]\n"
            "    Please provide a valid FQDN (e.g. example.com).\n"
        )
        sys.exit(1)

    config.target = target

    from reconyx.engine import ReconEngine
    engine = ReconEngine(config)

    try:
        stats = asyncio.run(engine.run())
        print_summary(stats)
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Interrupted by user — partial results saved.[/bold yellow]")
        sys.exit(130)
    except Exception as exc:
        console.print(f"\n[bold red][✗] Engine error: {exc}[/bold red]")
        if config.log_level == "DEBUG":
            import traceback
            traceback.print_exc()
        sys.exit(1)


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    """Main CLI entry point for RECONYX."""
    parser = build_parser()
    args   = parser.parse_args(argv)

    if not getattr(args, "no_banner", False):
        print_banner()

    if not args.domain:
        show_interactive_menu()
        return

    config = build_config_from_args(args)
    _run_recon(config)
