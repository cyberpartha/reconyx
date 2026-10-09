"""
Tests for RECONYX v2.0 — CLI argument parsing and validation.
"""

from __future__ import annotations

import pytest
from reconyx.cli import build_parser, build_config_from_args


class TestArgumentParser:
    def test_domain_short_flag(self):
        parser = build_parser()
        args = parser.parse_args(["-d", "example.com"])
        assert args.domain == "example.com"

    def test_domain_long_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--domain", "example.com"])
        assert args.domain == "example.com"

    def test_no_args_interactive(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert args.domain is None

    def test_no_quick_flag(self):
        """--quick flag must not exist in v2.0."""
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["-d", "example.com", "--quick"])

    def test_no_deep_flag(self):
        """--deep flag must not exist in v2.0."""
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["-d", "example.com", "--deep"])

    def test_no_full_flag(self):
        """--full flag must not exist in v2.0."""
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["-d", "example.com", "--full"])

    def test_no_probe_flag(self):
        parser = build_parser()
        args = parser.parse_args(["-d", "example.com", "--no-probe"])
        assert args.no_probe is True

    def test_authorised_flag(self):
        parser = build_parser()
        args = parser.parse_args(["-d", "example.com", "--authorised"])
        assert args.authorised is True

    def test_sources_override(self):
        parser = build_parser()
        args = parser.parse_args(["-d", "example.com", "--sources", "crtsh,alienvault"])
        assert args.sources == "crtsh,alienvault"

    def test_exclude_sources(self):
        parser = build_parser()
        args = parser.parse_args(["-d", "example.com", "--exclude-sources", "amass,gau"])
        assert args.exclude_sources == "amass,gau"

    def test_output_dir(self):
        parser = build_parser()
        args = parser.parse_args(["-d", "example.com", "-o", "/tmp/recon"])
        assert args.output == "/tmp/recon"

    def test_timeout(self):
        parser = build_parser()
        args = parser.parse_args(["-d", "example.com", "--timeout", "60"])
        assert args.timeout == 60

    def test_concurrency(self):
        parser = build_parser()
        args = parser.parse_args(["-d", "example.com", "--concurrency", "5"])
        assert args.concurrency == 5


class TestConfigBuilder:
    def _make_args(self, **kwargs):
        class Args:
            domain = "example.com"
            sources = None
            exclude_sources = None
            no_probe = False
            authorised = False
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
        inst = Args()
        for k, v in kwargs.items():
            setattr(inst, k, v)
        return inst

    def test_default_config_runs_all_sources(self):
        args = self._make_args()
        cfg = build_config_from_args(args)
        assert cfg.target == "example.com"
        # All passive sources and external tools enabled by default EXCEPT Amass
        assert cfg.sources.get("crtsh") is True
        assert cfg.sources.get("alienvault") is True
        assert cfg.sources.get("wayback") is True
        assert cfg.sources.get("commoncrawl") is True
        assert cfg.sources.get("subfinder") is True
        assert cfg.sources.get("findomain") is True
        assert cfg.sources.get("amass") is False

    def test_amass_disabled_by_default(self):
        args = self._make_args()
        cfg = build_config_from_args(args)
        assert cfg.sources.get("amass") is False
        assert "amass" not in cfg.enabled_sources

    def test_amass_enabled_with_flag(self):
        args = self._make_args(enable_amass=True)
        cfg = build_config_from_args(args)
        assert cfg.sources.get("amass") is True
        assert "amass" in cfg.enabled_sources

    def test_amass_enabled_via_sources_list(self):
        args = self._make_args(sources="crtsh,amass")
        cfg = build_config_from_args(args)
        assert cfg.sources.get("crtsh") is True
        assert cfg.sources.get("amass") is True
        assert "amass" in cfg.enabled_sources

    def test_exclude_sources_takes_precedence_over_enable_amass(self):
        args = self._make_args(enable_amass=True, exclude_sources="amass")
        cfg = build_config_from_args(args)
        assert cfg.sources.get("amass") is False
        assert "amass" not in cfg.enabled_sources

    def test_source_filter(self):
        args = self._make_args(sources="crtsh,subfinder")
        cfg = build_config_from_args(args)
        assert cfg.sources.get("crtsh") is True
        assert cfg.sources.get("subfinder") is True
        assert cfg.sources.get("alienvault") is False
        assert cfg.sources.get("commoncrawl") is False

    def test_source_exclusion(self):
        args = self._make_args(exclude_sources="amass,gau")
        cfg = build_config_from_args(args)
        assert cfg.sources.get("crtsh") is True
        assert cfg.sources.get("amass") is False
        assert cfg.sources.get("gau") is False

    def test_no_probe_option(self):
        args = self._make_args(no_probe=True)
        cfg = build_config_from_args(args)
        assert cfg.no_probe is True

    def test_authorised_option(self):
        args = self._make_args(authorised=True)
        cfg = build_config_from_args(args)
        assert cfg.probe_authorised is True

    def test_gau_explicit_timeout_90_precedence(self):
        """Explicit --timeout 90 sets both config.timeout and config.gau_timeout to 90."""
        parser = build_parser()
        args = parser.parse_args(["-d", "example.com", "--timeout", "90"])
        cfg = build_config_from_args(args)
        assert cfg.timeout == 90
        assert cfg.gau_timeout == 90

    def test_gau_explicit_timeout_10_precedence(self):
        """Explicit --timeout 10 sets both config.timeout and config.gau_timeout to 10 without clamping."""
        parser = build_parser()
        args = parser.parse_args(["-d", "example.com", "--timeout", "10"])
        cfg = build_config_from_args(args)
        assert cfg.timeout == 10
        assert cfg.gau_timeout == 10

    def test_gau_default_timeout_when_omitted(self):
        """When --timeout is omitted, config.timeout defaults to 30 and gau_timeout defaults to 45."""
        parser = build_parser()
        args = parser.parse_args(["-d", "example.com"])
        cfg = build_config_from_args(args)
        assert cfg.timeout == 30
        assert cfg.gau_timeout == 45

    def test_explicit_gau_timeout_flag(self):
        """Explicit --gau-timeout 45 overrides --timeout 90 specifically for GAU."""
        parser = build_parser()
        args = parser.parse_args(["-d", "example.com", "--timeout", "90", "--gau-timeout", "45"])
        cfg = build_config_from_args(args)
        assert cfg.timeout == 90
        assert cfg.gau_timeout == 45

    def test_gau_custom_config_precedence(self, tmp_path):
        """Custom config YAML sets gau_timeout, overridden if CLI --timeout is explicitly passed."""
        cfg_file = tmp_path / "custom.yaml"
        cfg_file.write_text("gau_timeout: 75\ntimeout: 25\n")

        parser = build_parser()
        # Case A: omitted CLI timeout -> uses custom YAML values
        args_a = parser.parse_args(["-d", "example.com", "--config", str(cfg_file)])
        cfg_a = build_config_from_args(args_a)
        assert cfg_a.timeout == 25
        assert cfg_a.gau_timeout == 75

        # Case B: explicit CLI timeout -> overrides both
        args_b = parser.parse_args(["-d", "example.com", "--config", str(cfg_file), "--timeout", "90"])
        cfg_b = build_config_from_args(args_b)
        assert cfg_b.timeout == 90
        assert cfg_b.gau_timeout == 90

    def test_probe_max_time_flag(self):
        """Explicit --probe-max-time sets config.probe_max_time."""
        parser = build_parser()
        args = parser.parse_args(["-d", "example.com", "--probe-max-time", "150"])
        cfg = build_config_from_args(args)
        assert cfg.probe_max_time == 150

    def test_probe_max_time_default(self):
        """When --probe-max-time is omitted, config.probe_max_time defaults to 120."""
        parser = build_parser()
        args = parser.parse_args(["-d", "example.com"])
        cfg = build_config_from_args(args)
        assert cfg.probe_max_time == 120


class TestDisclaimerAndBanner:
    def test_banner_and_disclaimer_rendering(self):
        from reconyx.banner import print_banner, print_disclaimer
        # Should execute cleanly without error
        print_banner()
        print_disclaimer()

    def test_disclaimer_suppressed_with_no_banner(self):
        parser = build_parser()
        args = parser.parse_args(["-d", "example.com", "--no-banner"])
        assert args.no_banner is True
