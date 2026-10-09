"""
RECONYX Shared Console
Provides a singleton Rich Console instance for coordinated terminal rendering,
progress bars, and logging output without overlapping streams.
"""

from __future__ import annotations

import sys
from rich.console import Console

_CONSOLE: Console | None = None


def get_console() -> Console:
    """Return the shared Rich Console instance for coordinated output."""
    global _CONSOLE
    if _CONSOLE is None:
        _CONSOLE = Console(highlight=False)
    return _CONSOLE


def set_console(console: Console | None) -> None:
    """Set or reset the shared Rich Console instance (useful for testing)."""
    global _CONSOLE
    _CONSOLE = console
