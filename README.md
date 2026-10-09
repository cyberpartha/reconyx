# RECONYX v2.0.4

```
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗   ██╗██╗  ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗ ██╔╝╚██╗██╔╝
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚████╔╝  ╚███╔╝
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║  ╚██╔╝   ██╔██╗
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║   ██║   ██╔╝ ██╗
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝
```

**Discover • Enumerate • Analyze**

> Advanced Bug Bounty Reconnaissance Framework — Version 2.0.4  
> by **CyberPartha** · MIT License · Python 3.11+

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Ubuntu%20%7C%20WSL2%20%7C%20Windows-informational)](https://github.com/CyberPartha/reconyx)

---

## Educational and Authorized-Use Disclaimer

> **DISCLAIMER**  
> RECONYX is developed by **CyberPartha** for educational purposes, cybersecurity training, and authorized security research only.  
> 
> Use this tool **only** on systems and domains that you own or have explicit written permission to assess. Unauthorized scanning, probing, or security testing may violate applicable local, national, and international laws, service agreements, or bug bounty program terms.  
> 
> The user is **solely responsible** for ensuring that all reconnaissance and probing activities are fully authorized and strictly within permitted scope. RECONYX and its developer assume no liability for misuse or damage caused by this software.

---

## What's New in v2.0.4: HTTPX Reliability & Performance Update

1. **Clean Hostname Extraction for `live_hosts.txt`**:
   - `live.txt` retains full responsive URLs including ports (e.g., `http://127.0.0.1:8765`).
   - `live_hosts.txt` extracts clean hostnames/IPs without schemes or port numbers (e.g., `127.0.0.1`).
   - Robust parsing supports standard domains, subdomains, IPv4, IPv6 (bracketed and bare), custom ports, and full URLs.

2. **Safe HTTPX Subprocess Execution Deadline**:
   - Configurable overall HTTPX execution deadline (`--probe-max-time SECONDS` or `probe.max_time: 120`).
   - Independent of per-request HTTP timeout (`probe.timeout: 10`).
   - Streamed line-by-line reading prevents stdout/stderr pipe buffer deadlocks.
   - Hung subprocesses and their process groups are cleanly terminated, preventing zombie/orphan processes.
   - Asynchronous cancellation (`asyncio.CancelledError`) safely tears down the HTTPX subprocess group.

3. **Partial JSONL Findings Preservation**:
   - If HTTPX probe times out, valid findings emitted prior to the deadline are preserved in `live.txt`, `live_hosts.txt`, and `httpx_results.jsonl`.
   - Probe failure or timeout conditions are logged and reported with dedicated status indications without misrepresenting failed scans.

---

## What's New in v2.0.3: Focused Timeout & Error Handling Fix

1. **GAU Timeout Precedence**:
   - Explicit `--timeout N` now directly and consistently governs GAU (both engine deadline and subprocess limit) whether set to 10s or 90s.
   - When `--timeout` is omitted, the configured default `gau_timeout` (45s or user YAML) is retained.
   - Optional `--gau-timeout SECONDS` flag is also available for granular per-source control.

2. **Typed Exception Handling & Wayback Error Classification**:
   - Replaced substring matching on `"timeout"` in exception messages with typed exceptions: `TimeoutError`, `NetworkError`, and `HttpError`.
   - Connection drops, server resets, and HTTP errors are accurately classified as **`FAILED`** rather than falsely categorized as `TIMEOUT`.
   - Cumulative deadline budgeting across retries in `fetch_text` and `fetch_json`.

---

## Source Timeout Configuration & Semantics

- `--timeout SECONDS` (default: `30`):
  - Applies **per source independently**. Every discovery source is given up to this duration to complete its tasks.
  - When explicitly provided on the CLI, `--timeout` sets the effective deadline across all passive tools including GAU.
  - When omitted, deep-archive and graph tools maintain their configured defaults: GAU (`gau_timeout: 45s`), OWASP Amass (`amass_timeout: 300s`).
- `--gau-timeout SECONDS` (optional, default: `45`):
  - Explicitly overrides GAU subprocess and engine deadline independently.
- **Known Limitations of External Providers**:
  - Public data endpoints such as `crt.sh`, `web.archive.org`, and `index.commoncrawl.org` are shared public infrastructures. During high traffic or concurrent queries, their servers may rate-limit or hold connections up to their internal socket timeout (typically 60s). RECONYX v2.0.3 safely cuts off stalled connections and preserves all data acquired prior to timeout.

---

## 4-Phase Reconnaissance Pipeline

The default command:

```bash
reconyx -d example.com
```

automatically executes the full reconnaissance pipeline across four synchronized phases:

1. **`[1/4] Enumerating subdomains`**: Runs all fast passive sources (crt.sh, AlienVault OTX, HackerTarget, Wayback Machine, Common Crawl) and auto-detected external tools (`subfinder`, `findomain`, `assetfinder`, `gau`). Amass is skipped unless `--enable-amass` is passed.
2. **`[2/4] Normalizing and deduplicating`**: Cleans hostnames, removes schemes and trailing dots, enforces strict RFC syntax, preserves nested subdomains, applies scope filtering, and computes scan differences.
3. **`[3/4] Identifying live websites`**: Seamlessly integrates ProjectDiscovery HTTPX (distinguished from Python's httpx CLI) to probe responsive HTTP/HTTPS web services when authorized (`--authorised`).
4. **`[4/4] Saving reconnaissance results`**: Saves clean, structured files with overwrite-protection to preserve prior results against empty scans.

---

## 4-Phase Terminal Experience

```
[1/4] Enumerating subdomains
─────────────────────────────
[⏭] Amass — SKIPPED (optional source)
[✓] crt.sh         → 210 subdomains  (3.4s)
[✓] AlienVault OTX → 94 subdomains   (1.8s)
[✓] HackerTarget   → 42 subdomains   (1.2s)
[✓] Subfinder      → 156 subdomains  (2.1s)
[✓] Findomain      → 89 subdomains   (1.5s)
[✓] GAU            → 73 subdomains   (8.2s)

[2/4] Normalizing and deduplicating
───────────────────────────────────
[*] Aggregated 664 raw findings from all sources.
[✓] Normalized into 272 unique in-scope subdomains.

[3/4] Identifying live websites
───────────────────────────────
[»] Probing responsive HTTP/HTTPS web services with ProjectDiscovery HTTPX…
[✓] Discovered 84 live URLs across 71 responsive hosts.

[4/4] Saving reconnaissance results
───────────────────────────────────
[✓] Saved recon.txt (272 subdomains)
[✓] Saved live.txt (84 URLs)
[✓] Saved live_hosts.txt (71 hosts)
[✓] Saved httpx_results.jsonl
[✓] Saved scan_summary.json

┌──────────────────────────────────────────────────┐
│               Reconnaissance Summary             │
│  🎯 Target Domain       example.com              │
│  ──────────────────────────────────              │
│  📡 Total Sources Configured 12                  │
│  ✅ Successful (SUCCESS) 6                       │
│  ⏭  Skipped (SKIPPED)    3                       │
│  ──────────────────────────────────              │
│  📦 Raw Findings        664                      │
│  🔬 Unique Subdomains   272                      │
│  🌐 Live Websites       84                       │
│  ⏱  Total Scan Duration 12.8s                    │
│  ──────────────────────────────────              │
│  📁 Output Directory    results/example.com      │
└──────────────────────────────────────────────────┘
```

---

## Output Files Structure

Results are stored under `results/<target>/`:

| File | Format | Description |
|------|--------|-------------|
| `recon.txt` | Text (1 hostname/line) | All unique, in-scope discovered subdomains (sorted alphabetically) |
| `live.txt` | Text (1 URL/line) | All responsive HTTP and HTTPS URLs discovered by HTTPX (when `--authorised`) |
| `live_hosts.txt` | Text (1 hostname/line) | Unique hostnames corresponding to responsive web services |
| `httpx_results.jsonl` | JSON Lines | Structured HTTPX probe data (status code, title, web server, tech) |
| `scan_summary.json` | JSON | Complete scan metadata, duration, per-source counts, 6-state status metrics, and failures |
| `new_subdomains.txt` | Text (1 hostname/line) | Subdomains discovered for the first time since previous scan |
| `diff.json` | JSON | Diff comparison details against previous scan history |
| `sources.json` | JSON | Performance, status states, and result counts per reconnaissance source |

> **Safety Guarantee**: RECONYX protects your findings. It will **never** overwrite an existing successful `recon.txt` with an empty file after a failed or network-blocked scan.

---

## Installation & Setup

### Kali Linux & WSL2 Setup

1. **Clone and Install RECONYX**:
   ```bash
   git clone https://github.com/CyberPartha/reconyx.git
   cd reconyx
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e .
   ```

2. **Install External Discovery Tools (Optional)**:
   ```bash
   # Subfinder (often pre-installed on Kali at /usr/bin/subfinder)
   sudo apt install subfinder || go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

   # ProjectDiscovery HTTPX (httpx-toolkit in Debian/Kali or go install)
   sudo apt install httpx-toolkit || go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

   # Findomain
   sudo apt install findomain || curl -LO https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip && unzip findomain-linux.zip && sudo mv findomain /usr/bin/

   # lc gau
   go install github.com/lc/gau/v2/cmd/gau@latest

   # OWASP Amass (optional)
   sudo apt install amass || go install -v github.com/owasp-amass/amass/v4/...@master
   ```

RECONYX automatically detects tools present on your system using `shutil.which()`. If a tool is not installed, RECONYX cleanly skips it and continues scanning with all remaining sources.

### Windows (PowerShell)

```powershell
git clone https://github.com/CyberPartha/reconyx.git
cd reconyx
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
python reconyx.py -d example.com
```

---

## Usage Examples

### 1. Default Fast Scan (Passive Pipeline without Amass)
```bash
reconyx -d example.com
```
Executes all passive data sources and installed external tools without slow Amass. If `--authorised` is omitted, active HTTP probing is safely skipped, and subdomains are preserved in `recon.txt`.

### 2. Include OWASP Amass
```bash
reconyx -d example.com --enable-amass
```
Includes Amass in passive enumeration mode with a 300-second timeout.

### 3. Full Pipeline with Authorized Live Website Probing
```bash
reconyx -d example.com --authorised
```
Runs default fast enumeration and executes ProjectDiscovery HTTPX against all discovered subdomains to produce `live.txt`, `live_hosts.txt`, and `httpx_results.jsonl`.

### 4. Enable Both Amass and Live Probing
```bash
reconyx -d example.com --enable-amass --authorised
```

### 5. Explicitly Disable HTTP Probing
```bash
reconyx -d example.com --no-probe
```

### 6. Custom Source Selection
```bash
# Run only specific sources
reconyx -d example.com --sources crtsh,subfinder,findomain

# Exclude specific sources
reconyx -d example.com --exclude-sources amass,commoncrawl
```

### 7. Strict Scope Configuration
```bash
# Allow only wildcards under root domain
reconyx -d example.com --scope "*.example.com" --exclude-scope "internal.example.com,vpn.example.com"
```

### 8. Interactive Menu
Simply run:
```bash
reconyx
```
Provides a clean terminal menu to launch scans, compare previous results with `diff`, or view existing findings.

---

## Running the Test Suite

RECONYX v2.0.4 includes a comprehensive automated unit and integration test suite:

```bash
# Run all tests
pytest -v

# Run with short tracebacks
pytest -v --tb=short
```

---

## Developer

Developed with precision by **CyberPartha**.  
License: MIT
