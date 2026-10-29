# WebRaptor

WebRaptor runs eight web reconnaissance and security scanners in one workflow, with automatic finding verification, HTML/JSON reports, concurrency limits, timeouts, credential redaction, and resumable runs.

**Use only on systems you own or have explicit permission to assess.**

## Installation

Requires **Python 3.9+**. On **Kali Linux or Parrot OS**, run as your normal user:

```bash
./install.sh
source .venv/bin/activate
python webraptor.py --check-tools
```

The installer uses sudo for apt, installs scanner dependencies and Nuclei templates, creates `.venv`, and verifies all eight modules. It prefers distro packages, with official upstream fallbacks under `.venv`/`.tools`. Downloaded Go archives are SHA256-checked. Network access is required; installation does not scan a target or upgrade the distribution. The installer rejects other operating systems.

For manual setup on Linux or macOS, install the scanners below in `PATH`, then:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python webraptor.py --check-tools
```

`requirements.txt` installs Python dependencies only; external tools are listed in its comments. `--check-tools` checks executable versions and required CLI flags, not scan accuracy or complete runtime readiness. Automatic TLS verification uses **sslscan**, even when its standalone module is excluded.

Validated on **Kali Rolling ARM64 in Docker on 29 Oct 2026**: the installer and all eight `--check-tools` checks passed. Kali’s Dirsearch launcher is wrapped to use its system Python dependencies separately from WebRaptor’s virtual environment. Parrot and x86_64 installation still need native validation.

## Included scanners

| Module | Purpose |
| --- | --- |
| [curl](https://curl.se/) | HTTP HEAD response headers and redirects |
| [whatweb](https://github.com/urbanadventurer/WhatWeb) | Technology fingerprinting |
| [nikto](https://github.com/sullo/nikto) | Web server checks |
| [waybackurls](https://github.com/tomnomnom/waybackurls) | Historical URLs from public archives |
| [dirsearch](https://github.com/maurosoria/dirsearch) | Directory and file discovery |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Template-based checks |
| [testssl](https://github.com/testssl/testssl.sh) | TLS configuration checks; accepts `testssl` or `testssl.sh` |
| [sslscan](https://github.com/rbsec/sslscan) | TLS protocols, ciphers, and certificate details |

## Usage

```bash
# Run all eight scanners and automatic verification
python webraptor.py https://example.com

# Select or exclude scanners
python webraptor.py https://example.com --modules curl,nuclei --tool-timeout 600
python webraptor.py https://example.com --exclude nikto,dirsearch

# TLS on a specific port
python webraptor.py https://example.com:8443 --modules testssl,sslscan

# Multiple targets, one per line; blank lines and # comments are ignored
python webraptor.py --targets-file targets.txt --target-concurrency 2 --threads 3

# Custom scanner inputs
python webraptor.py https://example.com --wordlist paths.txt --nuclei-template templates/
```

Use either a target or `--targets-file` (`-l`). `--exclude` is repeatable and applies after `--modules`. Run `python webraptor.py --help` for every option.

| Option | Default | Purpose |
| --- | --- | --- |
| `--output-dir` | `results` | Report directory |
| `--threads` | `6` | Maximum active scanner processes globally |
| `--target-concurrency` | `1` | Concurrent target workflows |
| `--tool-timeout` | `1800` | Seconds per scanner, excluding queue time |
| `--probe-timeout` | `8` | HTTP probe timeout in seconds |
| `--nuclei-rate` | `20` | Requests/second per Nuclei process |
| `--dirsearch-rate` | `10` | Requests/second per Dirsearch process |
| `--dirsearch-threads` | `10` | Workers per Dirsearch process |
| `--whatweb-wait` | `1` | Seconds between WhatWeb connections |
| `--nikto-pause` | `1` | Seconds between Nikto requests |
| `--no-progress` | Off | Hide live progress |

Rate limits are **per process**, not a global traffic cap. Bare domains try HTTPS then HTTP; explicit URLs keep their scheme unless `--allow-scheme-fallback` is supplied. Any HTTP response, including 4xx/5xx, counts as reachable. TLS checks use the original HTTPS host/port; explicit HTTP targets skip TLS checks. `--insecure` affects the reachability probe and curl, not every scanner. Ctrl+C, SIGTERM, and timeouts terminate scanner process groups and preserve partial output when possible.

## Reports and verification

Each target automatically receives **22 checks** covering:

- Missing security headers: HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP, and COEP.
- Insecure CSP indicators, duplicate security headers, legacy X-Frame-Options/X-XSS-Protection, and compression/BREACH prerequisites.
- Weak TLS ciphers, TLS 1.3 rejection, SSLv2/SSLv3/TLS 1.0/TLS 1.1 acceptance, wildcard certificates, weak certificate signature hashes, and expired certificates.

The HTML report includes target details, collapsible scanner sections, raw output under **Evidence**, and a **Findings Summary** containing only `found` checks with `verified=true`. WhatWeb/Nikto results use tables; Dirsearch lists all recorded response codes, sorted and color-coded, with size and linked URL. Waybackurls lists linked historical URLs. Links open in new tabs. Reports support light/dark themes and use no external assets.

JSON retains all checks, including `potential`, `unknown`, `not_found`, and `not_applicable` results. Evidence records collector/tool provenance, artifact paths, and SHA256 where available. Supplementary scanner output is distinguished from primary verification evidence. WebRaptor assigns no severity ratings or remediation guidance; original scanner data is retained.

**Verified means the observation was evidenced, not that exploitation succeeded.** An empty Findings Summary does not establish a clean assessment. Header checks apply only to the exact URL response. The HTTP collector uses GET without redirects, with a 2 MiB decoded-body limit; it does not execute JavaScript. TLS failures can remain unknown; wildcard checks require certificate validation. CSP indicators and compression alone do not prove an exploitable vulnerability. Scanner matches require review.

```text
results/
├── _runs/<run-id>/           # run.json resume manifest, batch summary/report
└── <target-key>/<run-id>/
    ├── report.html          # Scanner execution summary
    ├── summary.json
    ├── verification.html    # Scanner sections and verified findings
    ├── verification.json   # Complete check record
    ├── scan.log
    └── ...                  # Raw scanner output and verification evidence
```

## Authentication

Prefer files to avoid putting credentials in shell history:

```bash
python webraptor.py https://app.example.com \
  --headers-file headers.txt --cookie-file cookies.txt
```

Header files contain one `Name: value` per line; cookie files contain only the cookie value, such as `session=TOKEN`. Repeatable `-H` and `--cookie` are also supported. HTTP credentials are not sent to Waybackurls or sslscan; testssl headers apply only to its HTTP checks. Authenticated target lists must use one host and port. Automatic login, token refresh, and session validation are not provided.

Known supplied secrets are redacted from saved text, but may be visible in process arguments or temporary output during execution. Binary artifacts and newly discovered secrets are not comprehensively sanitized. Curl follows redirects; custom headers may reach redirect destinations. Review evidence before sharing.

## Resume

```bash
python webraptor.py --resume results/_runs/<run-id>/run.json
# Resupply credentials when needed; the batch directory is also accepted
python webraptor.py --resume results/_runs/<run-id> \
  --headers-file headers.txt --cookie-file cookies.txt
```

Resume creates a **new run**, reusing completed scanner artifacts only when their SHA256 checks match. Incomplete or modified outputs run again; verification always runs fresh. Keep the original directory layout and referenced templates/wordlists. Credentials are not stored in manifests and must be resupplied. Timeouts, concurrency, output location, and a subset of modules can change; other scan settings cannot.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Applicable modules completed and checks reached an assessment, or tool checks passed; findings may still exist |
| `1` | Execution/tool/output error or incomplete verification, including unknown checks |
| `2` | Invalid arguments or input |
| `130` | Ctrl+C or SIGTERM interruption |

## Testing

```bash
# Unit and integration tests using mocks and loopback fixtures
.venv/bin/python -m unittest discover -s tests -v

# Native verification smoke test; requires openssl, curl, and sslscan
.venv/bin/python tests/local_findings_smoke.py
```

The smoke test exercises all 22 checks across five local HTTPS profiles and compares HTML/JSON results. Its temporary CA is never installed in system trust. Add `--serve` to preview saved reports. Real-scanner demos are available under `tests/fixtures/scanner_demo/`; the five-scanner demo includes public archive lookups.

Generated `results/`, `.venv/`, `.tools/`, and Python caches are excluded by `.gitignore`. Keep credentials and private target lists out of version control.

## License

[MIT License](LICENSE). For educational and authorized security assessments only.
