"""
RECONYX Configuration Module
Loads, merges, and validates configuration from config.yaml,
environment variables, and CLI overrides.
"""

from __future__ import annotations

import os
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Default configuration values for RECONYX v2.0.4
DEFAULTS: dict[str, Any] = {
    "version": "2.0.4",
    "developer": "CyberPartha",
    # Networking
    "timeout": 30,
    "retries": 3,
    "concurrency": 20,
    "rate_limit_delay": 0.3,   # seconds between requests to same host
    "amass_timeout": 300,      # timeout for Amass when enabled
    "gau_timeout": 45,         # optimized timeout for GAU subprocess
    # Output
    "output_base": "results",
    "output_file": "recon.txt",
    # Sources enabled by default
    "sources": {
        # Passive data sources
        "crtsh": True,
        "alienvault": True,
        "wayback": True,
        "commoncrawl": True,
        "hackertarget": True,
        # API-key sources (active if key is provided)
        "virustotal": False,
        "securitytrails": False,
        # External CLI tools (auto-detected via shutil.which)
        "subfinder": True,
        "amass": False,        # Optional source (8-10+ mins). Enable with --enable-amass
        "assetfinder": True,
        "findomain": True,
        "gau": True,
    },
    # Optional API keys
    "api_keys": {
        "virustotal": "",
        "securitytrails": "",
    },
    # Scope
    "scope": {
        "allowed_domains": [],    # empty = derived from target
        "excluded_domains": [],
        "wildcard_scope": False,
    },
    # HTTP probe settings (ProjectDiscovery HTTPX)
    "probe": {
        "enabled": True,          # active by default when authorised
        "authorised": False,       # requires explicit authorisation
        "threads": 50,
        "timeout": 10,
        "max_time": 120,          # overall HTTPX subprocess deadline in seconds
        "rate_limit": 150,
        "follow_redirects": True,
    },
    # Logging
    "log_level": "INFO",
    "log_file": "",
    "cache_enabled": False,
    "cache_ttl": 3600,
}

# Path to bundled default config
_DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"


@dataclass
class ReconConfig:
    """Runtime configuration object passed to the engine and modules."""

    target: str = ""
    mode: str = "full"
    timeout: int = 30
    retries: int = 3
    concurrency: int = 20
    rate_limit_delay: float = 0.3
    amass_timeout: int = 300
    gau_timeout: int = 45
    output_base: str = "results"
    output_file: str = "recon.txt"
    sources: dict[str, bool] = field(default_factory=dict)
    api_keys: dict[str, str] = field(default_factory=dict)
    scope_allowed: list[str] = field(default_factory=list)
    scope_excluded: list[str] = field(default_factory=list)
    wildcard_scope: bool = False
    probe_enabled: bool = True
    probe_authorised: bool = False
    probe_threads: int = 50
    probe_timeout: int = 10
    probe_max_time: int = 120
    probe_rate_limit: int = 150
    probe_follow_redirects: bool = True
    no_probe: bool = False
    enable_amass: bool = False
    log_level: str = "INFO"
    log_file: str = ""
    cache_enabled: bool = False
    cache_ttl: int = 3600
    version: str = "2.0.4"
    developer: str = "CyberPartha"
    extra_sources: list[str] = field(default_factory=list)

    @property
    def output_dir(self) -> Path:
        return Path(self.output_base) / self.target

    @property
    def enabled_sources(self) -> list[str]:
        enabled = [k for k, v in self.sources.items() if v]
        # Also enable any explicitly requested extra sources
        for src in self.extra_sources:
            if src not in enabled:
                enabled.append(src)
        return enabled


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base, returning a new dict."""
    result = dict(base)
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def _load_yaml(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
            return data or {}
    except FileNotFoundError:
        return {}
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in {path}: {exc}") from exc


def _load_env_overrides() -> dict:
    """Load API keys and toggles from environment variables."""
    overrides: dict[str, Any] = {"api_keys": {}, "sources": {}}
    mapping = {
        "RECONYX_VT_KEY":  ("api_keys", "virustotal"),
        "RECONYX_ST_KEY":  ("api_keys", "securitytrails"),
        "VT_API_KEY":      ("api_keys", "virustotal"),
        "ST_API_KEY":      ("api_keys", "securitytrails"),
    }
    for env_var, (section, key) in mapping.items():
        val = os.environ.get(env_var, "").strip()
        if val:
            overrides[section][key] = val
            # Auto-enable source when a key is provided
            if section == "api_keys":
                overrides["sources"][key] = True

    # Toggle sources via RECONYX_ENABLE_<SOURCE>=1
    for env_var, value in os.environ.items():
        if env_var.startswith("RECONYX_ENABLE_"):
            source = env_var[len("RECONYX_ENABLE_"):].lower()
            overrides["sources"][source] = value.strip() in ("1", "true", "yes")

    return overrides


def load_config(
    config_path: str | Path | None = None,
    cli_overrides: dict | None = None,
) -> ReconConfig:
    """
    Build a ReconConfig by merging:
      1. Built-in defaults
      2. config.yaml (bundled)
      3. User config.yaml (if provided)
      4. Environment variables
      5. CLI overrides
    """
    merged = dict(DEFAULTS)

    # 2. Load bundled config.yaml
    if _DEFAULT_CONFIG_PATH.exists():
        merged = _deep_merge(merged, _load_yaml(_DEFAULT_CONFIG_PATH))

    # 3. Load user-supplied config file
    if config_path:
        user_cfg = _load_yaml(Path(config_path))
        merged = _deep_merge(merged, user_cfg)

    # 4. Environment overrides
    merged = _deep_merge(merged, _load_env_overrides())

    # 5. CLI overrides
    if cli_overrides:
        merged = _deep_merge(merged, cli_overrides)

    scope_cfg = merged.get("scope", {})
    probe_cfg = merged.get("probe", {})
    api_keys  = merged.get("api_keys", {})
    sources   = merged.get("sources", {})

    return ReconConfig(
        target                 = merged.get("target", ""),
        mode                   = "full",
        timeout                = int(merged.get("timeout", 30)),
        retries                = int(merged.get("retries", 3)),
        concurrency            = int(merged.get("concurrency", 20)),
        rate_limit_delay       = float(merged.get("rate_limit_delay", 0.3)),
        amass_timeout          = int(merged.get("amass_timeout", 300)),
        gau_timeout            = int(merged.get("gau_timeout", 45)),
        output_base            = merged.get("output_base", "results"),
        output_file            = merged.get("output_file", "recon.txt"),
        sources                = sources,
        api_keys               = api_keys,
        scope_allowed          = scope_cfg.get("allowed_domains", []),
        scope_excluded         = scope_cfg.get("excluded_domains", []),
        wildcard_scope         = scope_cfg.get("wildcard_scope", False),
        probe_enabled          = probe_cfg.get("enabled", True),
        probe_authorised       = probe_cfg.get("authorised", False),
        probe_threads          = int(probe_cfg.get("threads", 50)),
        probe_timeout          = int(probe_cfg.get("timeout", 10)),
        probe_max_time         = int(probe_cfg.get("max_time", merged.get("probe_max_time", 120))),
        probe_rate_limit       = int(probe_cfg.get("rate_limit", 150)),
        probe_follow_redirects = probe_cfg.get("follow_redirects", True),
        no_probe               = merged.get("no_probe", False),
        enable_amass           = merged.get("enable_amass", False),
        log_level              = merged.get("log_level", "INFO"),
        log_file               = merged.get("log_file", ""),
        cache_enabled          = merged.get("cache_enabled", False),
        cache_ttl              = int(merged.get("cache_ttl", 3600)),
        version                = merged.get("version", "2.0.4"),
        developer              = merged.get("developer", "CyberPartha"),
        extra_sources          = merged.get("extra_sources", []),
    )
