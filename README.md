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
python webraptor.py --resume results/_runs/<run-id>/run.json

# Show all options
python webraptor.py --help
```

Header files contain one `Name: value` per line. Cookie files contain the cookie value only. Resupply credentials when resuming. Resume creates a new run and reuses eligible scanner outputs; verification always runs fresh.

Scanner output streams live with supplied-secret redaction and no added per-line prefixes. Each tool has a clear start and finish message, with colors in interactive terminals. Use `--no-progress` to silence live output. Concurrent tools can interleave output; use `--threads 1` for sequential scanner output. Scanner-side buffering can delay messages; complete output is saved with the reports.

## Reports

Reports and raw evidence are saved under `results/`. Open a target's **`report.html`** for collapsible scanner results, linked URLs, and verified findings. **`data/verification.json`** contains the complete check record. Supporting files are grouped into `evidence/` and `logs/`; each target run has only one top-level HTML report. Batch reports are under `results/_runs/`.

The **22 automatic checks** cover security headers, TLS protocols and ciphers, certificates, and compression indicators. Automatic TLS verification needs sslscan even when its standalone module is excluded.

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
