# WebRaptor

WebRaptor combines eight web security scanners, automatically verifies findings, and generates HTML and JSON reports.

**Only scan systems you own or have permission to test.**

## Install

On **Kali Linux or Parrot OS**, run as your normal user:

```bash
./install.sh
source .venv/bin/activate
python webraptor.py --check-tools
```

The installer requires network access and sudo for system packages. It installs dependencies and Nuclei templates, then checks all eight tools. It does not scan a target.

The installer pins upstream testssl commit `2168273` (stable 3.2), which fixes the TLS 1.3 session-ticket race. Activate `.venv` to use this managed copy.

Requires **Python 3.9+**. For manual setup on Linux or macOS, install the scanner tools in `PATH`, create a virtual environment, and run `pip install -r requirements.txt`. The requirements file installs Python dependencies only.

Validated in a **Kali Rolling ARM64 Docker container**: installation and all eight tool checks passed. Parrot and x86_64 installation remain untested.

## Included tools

| Tool | Purpose |
| --- | --- |
| curl | HTTP headers |
| WhatWeb | Technology detection |
| Nikto | Web server checks |
| Waybackurls | Historical URL discovery |
| Dirsearch | Directory and file discovery |
| Nuclei | Template-based checks |
| testssl.sh | TLS configuration checks |
| sslscan | TLS protocols, ciphers, and certificates |

## Usage

```bash
# Scan a target
python webraptor.py https://example.com

# Select tools
python webraptor.py https://example.com --modules curl,nuclei

# Scan multiple targets, one per line
python webraptor.py --targets-file targets.txt

# Supply authentication through files
python webraptor.py https://example.com --headers-file headers.txt --cookie-file cookies.txt

# Resume a previous run
python webraptor.py --resume results/<target>/<run-id>/data/run.json

# Show all options
python webraptor.py --help
```

Header files contain one `Name: value` per line. Cookie files contain the cookie value only. Resupply credentials when resuming. Resume creates a new run and reuses eligible scanner outputs; verification always runs fresh.

Scanners run simultaneously (up to six; adjust with `--threads`). The compact terminal panel shows only activity each tool provides, update ages, and stale-output warnings after 30 seconds. Raw output stays in redacted evidence/log files. Use `--no-progress` to silence progress or `NO_COLOR=1` to disable colors.

## Reports

Reports and raw evidence are saved under `results/`. Open a target's **`report.html`** for collapsible scanner results, linked URLs, and verified findings. **`data/verification.json`** contains the complete check record. Each target run contains only `report.html`, `data/`, `evidence/`, and `logs/`. Keep them together so evidence links work. Single-target resume information lives in `data/run.json`; no `_runs/` folder is created. Multi-target session reports and resume manifests remain under `results/_runs/<run-id>/`. Existing session manifests still work.

The **22 automatic checks** cover security headers, TLS protocols and ciphers, certificates, and compression indicators. Automatic TLS verification uses sslscan XML and a focused testssl per-cipher JSON probe, even when their standalone modules are excluded. Weak/deprecated suites include CBC mode and static RSA key exchange; these observations do not prove exploitability. Missing or incomplete probes remain inconclusive unless an accepted weak/deprecated suite is observed.

**Verified means observed, not successfully exploited.** Potential and unknown checks remain in JSON; an empty Findings Summary does not prove the target is secure. Reports assign no severity ratings or remediation steps. Review scanner matches and evidence before acting or sharing; secret redaction is not comprehensive.

Exit codes: `0` completed assessment (findings may exist), `1` failed/incomplete checks, `2` invalid input, `130` interrupted.

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -v
```

For native local verification checks, run `tests/local_findings_smoke.py` with the virtual-environment Python. It requires OpenSSL, curl, and sslscan.

Generated reports, environments, caches, and common credential files are excluded by `.gitignore`. Never commit secrets or private target lists.

## License

[MIT License](LICENSE).

