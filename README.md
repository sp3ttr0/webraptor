# WebRaptor

Web application security scanning with eight tools, automatic finding verification, and HTML/JSON reports.

**Tools:** curl, WhatWeb, Nikto, Waybackurls, Dirsearch, Nuclei, testssl.sh, and sslscan.

## Install

On **Kali Linux or Parrot OS**, run as your normal user:

```bash
./install.sh
source .venv/bin/activate
```

Requires Python 3.9+, network access, and sudo for system packages. The installer installs dependencies and Nuclei templates, includes the upstream testssl session-resumption fix, and runs `--check-tools` for all eight modules. Keep the virtual environment activated.

Installation has been validated on Kali Rolling ARM64; Parrot and x86_64 remain untested. `requirements.txt` contains Python dependencies; external scanners are installed separately by `install.sh`.

## Usage

```bash
# Single target
python webraptor.py https://example.com

# Target list: one URL or domain per line
python webraptor.py -l targets.txt

# Selected modules
python webraptor.py https://example.com --modules curl,nuclei

# Resume a scan
python webraptor.py --resume results/<target>/<run-id>/data/run.json

# Check tools or view options
python webraptor.py --check-tools
python webraptor.py --help
```

Tools run concurrently with a compact progress panel. TLS verification reuses scanner artifacts without duplicate scans. Resume reuses eligible outputs; supply authentication again if needed.

## Reports

Open the target's **`report.html`** under `results/`. Keep its `data/`, `evidence/`, and `logs/` folders together so evidence links work. `data/verification.json` includes all check results; the HTML Findings Summary lists only found and verified findings. HTTP header/content checks follow up to 10 HTTP redirects and require a final GET response of 200; other statuses remain inconclusive. Findings identify the final HTTP URL. Supplied headers are dropped when a redirect changes origin. TLS checks use protocol and certificate evidence. WhatWeb scans the resolved final URL and also requires a reported HTTP 200; other responses retain raw evidence as incomplete results.

Single-target resume information is in `data/run.json`. Multi-target sessions also use `results/_runs/`.

Nuclei saves both regular text output (`nuclei_results.txt`) and JSONL (`nuclei_results.jsonl`). The report displays the regular output as evidence; JSONL retains captured match details for processing.

## Disclaimer

**Only scan systems you own or have permission to test.** Automated results may be incomplete or inaccurate. Verified means observed, not exploited; missing findings do not prove security. Review evidence and remove sensitive information before sharing reports. Never commit secrets or private scan results.

[MIT License](LICENSE).
