"""
RECONYX Banner Module
Renders the professional ASCII art banner, educational disclaimer,
and terminal UI using the Rich library.
"""

from __future__ import annotations

from rich.text import Text
from rich.panel import Panel
from rich.align import Align
from rich.rule import Rule
from rich import box
from rich.table import Table

from reconyx.console import get_console

console = get_console()

# Raw ASCII art for RECONYX — hand-crafted large block font
RECONYX_ASCII = r"""
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗   ██╗██╗  ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗ ██╔╝╚██╗██╔╝
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚████╔╝  ╚███╔╝ 
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║  ╚██╔╝   ██╔██╗ 
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║   ██║   ██╔╝ ██╗
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝
"""

DISCLAIMER_TEXT = (
    "[bold yellow]RECONYX is developed by CyberPartha for educational purposes, "
    "cybersecurity training, and authorized security research only.[/bold yellow]\n\n"
    "[white]• Use this tool only on systems and domains that you own or have explicit permission to assess.\n"
    "• Unauthorized scanning, probing, or security testing may violate applicable laws, service agreements, or bug bounty program rules.\n"
    "• The user is solely responsible for ensuring that all activities are authorized and within the permitted scope.[/white]"
)


def print_banner(version: str = "2.0.4", developer: str = "CyberPartha") -> None:
    """Render the RECONYX banner and educational disclaimer with Rich styling."""
    console.print()

    # Main ASCII art — rendered in cyan bold
    ascii_text = Text(RECONYX_ASCII, style="bold cyan")
    console.print(Align.center(ascii_text))

    # Tagline row
    tagline = Text("  Discover  •  Enumerate  •  Analyze  ", style="bold bright_green")
    console.print(Align.center(tagline))
    console.print()

    # Info table row
    info_table = Table.grid(padding=(0, 4))
    info_table.add_column(justify="center")
    info_table.add_column(justify="center")
    info_table.add_column(justify="center")
    info_table.add_row(
        Text(f"⚡ Version {version}", style="bold yellow"),
        Text("│", style="dim white"),
        Text(f"🔍 by {developer}", style="bold magenta"),
    )
    console.print(Align.center(info_table))
    console.print()

    # Sub-header panel
    sub = (
        "[bold cyan]v2.0 Full Automatic Reconnaissance Pipeline[/bold cyan]\n"
        "[dim]Authorized Security Research Only  ·  Passive & Authorized Probing[/dim]"
    )
    console.print(
        Panel(
            Align.center(sub),
            border_style="cyan",
            box=box.ROUNDED,
            padding=(0, 4),
        )
    )
    console.print()

    # Educational & Authorized-Use Disclaimer
    print_disclaimer()


def print_disclaimer() -> None:
    """Render the concise educational and authorized-use disclaimer panel."""
    console.print(
        Panel(
            DISCLAIMER_TEXT,
            title="[bold red]⚠  DISCLAIMER  ⚠[/bold red]",
            border_style="yellow",
            box=box.ROUNDED,
            padding=(0, 3),
        )
    )
    console.print()


def print_section(title: str, style: str = "bold cyan") -> None:
    """Print a styled section rule."""
    console.print(Rule(f"[{style}]{title}[/{style}]", style="dim cyan"))


def print_phase(current: int, total: int, title: str) -> None:
    """Print a numbered execution phase header."""
    phase_str = f"[{current}/{total}] {title}"
    console.print()
    console.print(f"[bold cyan]{phase_str}[/bold cyan]")
    console.print("─" * len(phase_str), style="dim cyan")


def print_status(message: str, status: str = "info") -> None:
    """Print a status message with appropriate icon and colour."""
    icons = {
        "info":    ("[*]", "bold blue"),
        "success": ("[✓]", "bold green"),
        "empty":   ("[○]", "dim cyan"),
        "warning": ("[!]", "bold yellow"),
        "error":   ("[✗]", "bold red"),
        "timeout": ("[⏱]", "bold yellow"),
        "skipped": ("[⏭]", "dim yellow"),
        "partial": ("[⚡]", "bold magenta"),
        "start":   ("[»]", "bold cyan"),
        "phase":   ("[#]", "bold magenta"),
    }
    icon, colour = icons.get(status, icons["info"])
    console.print(f"[{colour}]{icon}[/{colour}] {message}")


def print_summary(stats: dict) -> None:
    """Render the final summary panel after recon completion."""
    console.print()
    print_section("Reconnaissance Summary")
    console.print()

    table = Table(
        box=box.SIMPLE_HEAVY,
        border_style="cyan",
        show_header=False,
        padding=(0, 2),
    )
    table.add_column("Metric", style="bold white", min_width=32)
    table.add_column("Value",  style="bold bright_green", justify="right")

    target = stats.get("target", "—")
    attempted = str(stats.get("sources_attempted", 0))
    ok_count = str(stats.get("sources_ok", stats.get("sources_successful", 0)))
    empty_count = str(stats.get("sources_empty", 0))
    fail_count = str(stats.get("sources_fail", 0))
    timeout_count = str(stats.get("sources_timeout", 0))
    skipped_count = str(stats.get("sources_skipped", stats.get("sources_failed_or_skipped", 0)))
    partial_count = str(stats.get("sources_partial", 0))

    total_raw = str(stats.get("total_raw", 0))
    unique = str(stats.get("unique", stats.get("unique_subdomains", 0)))
    live = str(stats.get("live_count", stats.get("live_websites", 0)))
    elapsed = stats.get("elapsed", stats.get("elapsed_seconds", "—"))
    out_dir = stats.get("output_dir", stats.get("output_directory", "—"))

    table.add_row("🎯 Target Domain",           target)
    table.add_row("─" * 32,                    "─" * 15)
    table.add_row("📡 Total Sources Configured", attempted)
    table.add_row("✅ Successful (SUCCESS)",     ok_count)
    if stats.get("sources_empty", 0) > 0 or "sources_empty" in stats:
        table.add_row("○  Empty (EMPTY)",          empty_count)
    if stats.get("sources_partial", 0) > 0:
        table.add_row("⚡ Partial (PARTIAL)",     partial_count)
    if stats.get("sources_timeout", 0) > 0:
        table.add_row("⏱  Timed Out (TIMEOUT)",   timeout_count)
    if stats.get("sources_fail", 0) > 0:
        table.add_row("❌ Failed (FAILED)",        fail_count)
    if stats.get("sources_skipped", 0) > 0:
        table.add_row("⏭  Skipped (SKIPPED)",      skipped_count)
    table.add_row("─" * 32,                    "─" * 15)
    table.add_row("📦 Raw Findings",            total_raw)
    table.add_row("🔬 Unique Subdomains",       unique)
    table.add_row("🌐 Live Websites",           live)
    table.add_row("⏱  Total Scan Duration",     elapsed)
    table.add_row("─" * 32,                    "─" * 15)
    table.add_row("📁 Output Directory",        out_dir)

    console.print(Align.center(table))
    console.print()

    unique_num = stats.get("unique", stats.get("unique_subdomains", 0))
    if unique_num > 0:
        console.print(
            Align.center(
                Text(
                    f"✨  Reconnaissance complete — {unique_num} unique subdomains saved to {out_dir}/recon.txt",
                    style="bold bright_green",
                )
            )
        )
    else:
        console.print(
            Align.center(
                Text("⚠  No subdomains discovered. Verify the target domain or network connection.", style="bold yellow")
            )
        )
    console.print()
