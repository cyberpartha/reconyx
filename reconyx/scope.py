"""
RECONYX Scope Module
Manages target scope validation — allowed domains, excluded domains,
wildcard scope, and active-scan authorisation gating.
"""

from __future__ import annotations

import fnmatch
import logging
import re

logger = logging.getLogger("reconyx.scope")


class ScopeManager:
    """
    Enforces scope rules for discovered subdomains and active probing.

    Rules (applied in order):
      1. If ``excluded`` patterns match  → out of scope
      2. If ``allowed`` patterns match   → in scope
      3. If ``allowed`` is empty         → derived from the primary target
      4. If ``wildcard_scope`` is True   → anything under the base TLD is allowed
    """

    def __init__(
        self,
        target: str,
        allowed: list[str] | None = None,
        excluded: list[str] | None = None,
        wildcard_scope: bool = False,
    ) -> None:
        self.target = target.lower().strip()
        self.allowed: list[str] = [d.lower().strip() for d in (allowed or [])]
        self.excluded: list[str] = [d.lower().strip() for d in (excluded or [])]
        self.wildcard_scope = wildcard_scope

        # Derive the effective allowed patterns if none provided
        if not self.allowed:
            self.allowed = [self.target, f"*.{self.target}"]

    # ------------------------------------------------------------------
    # Public Interface
    # ------------------------------------------------------------------

    def in_scope(self, domain: str) -> bool:
        """Return True if *domain* falls within the configured scope."""
        domain = domain.lower().strip()

        # Check exclusions first
        if self._matches_any(domain, self.excluded):
            logger.debug("Domain excluded from scope: %s", domain)
            return False

        # Wildcard mode — accept anything under the root TLD
        if self.wildcard_scope:
            root = _root_domain(self.target)
            if domain == root or domain.endswith(f".{root}"):
                return True

        # Check allowed patterns
        return self._matches_any(domain, self.allowed)

    def filter(self, domains: list[str]) -> list[str]:
        """Filter a list, returning only in-scope domains."""
        return [d for d in domains if self.in_scope(d)]

    def add_allowed(self, pattern: str) -> None:
        self.allowed.append(pattern.lower().strip())

    def add_excluded(self, pattern: str) -> None:
        self.excluded.append(pattern.lower().strip())

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _matches_any(domain: str, patterns: list[str]) -> bool:
        for pattern in patterns:
            if pattern.startswith("*."):
                # Wildcard: *.example.com matches sub.example.com
                suffix = pattern[2:]
                if domain == suffix or domain.endswith(f".{suffix}"):
                    return True
            elif fnmatch.fnmatch(domain, pattern):
                return True
            elif domain == pattern:
                return True
        return False

    def __repr__(self) -> str:
        return (
            f"ScopeManager(target={self.target!r}, "
            f"allowed={self.allowed!r}, excluded={self.excluded!r})"
        )


# ---------------------------------------------------------------------------
# Active Scan Authorisation Gate
# ---------------------------------------------------------------------------

def confirm_active_scan(target: str, interactive: bool = True) -> bool:
    """
    Prompt the user to confirm they are authorised to perform active probing.
    In non-interactive (CI) mode, raise RuntimeError.
    """
    if not interactive:
        raise RuntimeError(
            "Active scanning requires explicit authorisation. "
            "Run in interactive mode or pass --yes-i-am-authorised."
        )

    warning = (
        f"\n⚠  RECONYX — Active Scan Authorisation Required\n"
        f"   Target : {target}\n"
        f"   Active probing sends real HTTP requests to the target.\n"
        f"   Only proceed if you have written authorisation to test this target.\n"
    )
    print(warning)
    answer = input("   Type 'YES I AM AUTHORISED' to continue: ").strip()
    if answer == "YES I AM AUTHORISED":
        logger.info("Active scan authorised for %s", target)
        return True
    print("   Authorisation not confirmed. Switching to passive mode.\n")
    return False


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _root_domain(domain: str) -> str:
    """
    Best-effort extraction of the registrable (eTLD+1) domain.
    e.g. "sub.example.co.uk" → "example.co.uk"
    Falls back to last two labels for simplicity (no public suffix list).
    """
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain
