"""
RECONYX Module: Technology Fingerprinting
Detects web technologies from HTTP response headers and HTML meta tags.
Lightweight Python-native implementation — does not require Wappalyzer binary.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from reconyx.config import ReconConfig

logger = logging.getLogger("reconyx.technologies")

# Simple signature map: technology name → list of (source, pattern) tuples
# source: "header:<name>" | "body" | "x-powered-by" | "set-cookie"
SIGNATURES: dict[str, list[tuple[str, str]]] = {
    "WordPress":    [("body", r"wp-content/"), ("body", r"/wp-includes/")],
    "Drupal":       [("header:x-generator", r"Drupal"), ("body", r"Drupal\.settings")],
    "Joomla":       [("body", r"/media/jui/"), ("body", r"Joomla!")],
    "Laravel":      [("header:set-cookie", r"laravel_session")],
    "Django":       [("header:set-cookie", r"csrftoken"), ("header:x-frame-options", r"SAMEORIGIN")],
    "Ruby on Rails":  [("header:x-request-id", r"."), ("header:x-runtime", r"\\d+\\.\\d+")],
    "ASP.NET":      [("header:x-aspnet-version", r"."), ("header:x-powered-by", r"ASP\\.NET")],
    "PHP":          [("header:x-powered-by", r"PHP/")],
    "Nginx":        [("header:server", r"nginx")],
    "Apache":       [("header:server", r"Apache")],
    "Cloudflare":   [("header:cf-ray", r"."), ("header:server", r"cloudflare")],
    "React":        [("body", r"__REACT_QUERY_STATE__"), ("body", r"react-root")],
    "Next.js":      [("body", r"__NEXT_DATA__"), ("header:x-powered-by", r"Next\\.js")],
    "Vue.js":       [("body", r"__vue_")],
    "jQuery":       [("body", r"jquery")],
    "Bootstrap":    [("body", r"bootstrap\\.min\\.css")],
    "Shopify":      [("body", r"Shopify\\.theme"), ("header:x-shopify-stage", r".")],
    "Wix":          [("body", r"wixStatic\\.com")],
    "Squarespace":  [("body", r"squarespace\\.com")],
    "Ghost":        [("body", r"ghost-url"), ("header:x-ghost-cache-status", r".")],
}


def fingerprint(headers: dict[str, str], body: str) -> list[str]:
    """
    Detect technologies from HTTP headers and response body.
    Returns a deduplicated list of detected technology names.
    """
    detected: list[str] = []
    body_lower = body.lower()

    for tech, patterns in SIGNATURES.items():
        for source, pattern in patterns:
            matched = False
            if source == "body":
                if re.search(pattern, body_lower, re.IGNORECASE):
                    matched = True
            elif source.startswith("header:"):
                header_name = source[7:]
                header_val = headers.get(header_name, "")
                if header_val and re.search(pattern, header_val, re.IGNORECASE):
                    matched = True
            if matched:
                detected.append(tech)
                break  # One match per technology is enough

    return list(dict.fromkeys(detected))  # deduplicate preserving order


def fingerprint_live_results(live_results: list[dict]) -> dict[str, list[str]]:
    """
    Run technology fingerprinting across all live host results.
    Returns a mapping of host → [technology, ...].
    """
    output: dict[str, list[str]] = {}
    for entry in live_results:
        host = entry.get("host", "")
        # live results store headers as a flat dict in the probe result
        # For now we use the partial data we have
        header_proxy: dict[str, str] = {}
        if entry.get("server"):
            header_proxy["server"] = entry["server"]
        for tech in entry.get("technologies", []):
            if ":" in tech:
                k, v = tech.split(":", 1)
                header_proxy[k.lower()] = v

        # Body not stored in probe result — use header-only fingerprinting
        techs = fingerprint(header_proxy, "")
        if techs:
            output[host] = techs
    return output
