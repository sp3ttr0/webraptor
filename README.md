# webraptor

WebRaptor combines eight web reconnaissance and security modules into a single-target or multi-target workflow. It provides module selection, bounded concurrency, timeouts, credential redaction, resumable runs, live progress, and HTML/JSON reports. The original dinosaur banner is preserved.

## Setup and modules

Requires **Python 3.9+ on Linux or macOS**. Install selected tools and their dependencies using the upstream instructions, and put their executables in `PATH`.

| Module | Purpose / upstream |
| --- | --- |
| `curl` | [HEAD response headers](https://curl.se/) |
| `whatweb` | [Technology fingerprinting](https://github.com/urbanadventurer/WhatWeb) |
| `nikto` | [Web server checks](https://github.com/sullo/nikto) |
| `waybackurls` | [Historical URL discovery](https://github.com/tomnomnom/waybackurls) |
| `dirsearch` | [Directory and file discovery](https://github.com/maurosoria/dirsearch) |
| `nuclei` | [Template-based vulnerability checks](https://github.com/projectdiscovery/nuclei) |
| `testssl` | [TLS checks](https://github.com/testssl/testssl.sh); accepts `testssl` or `testssl.sh`, preferring `testssl` |
| `sslscan` | [TLS protocols and ciphers](https://github.com/rbsec/sslscan) |

From this directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 webraptor.py --check-tools
```

`--check-tools` accepts `--modules`/`--exclude` but no target. It checks executable versions and advertised CLI flags, with a 10-second limit per command, without scanning or creating output directories. Waybackurls reports an executable SHA256 instead of a version. This does not verify runtime dependencies, templates, connectivity, or scan accuracy. Normal scans only check executable presence.

Adapters require compatible CLI versions: notably Dirsearch `--output-formats` and Nikto `-Add-header` for authentication. Unsupported options fail the module with diagnostics.

## Usage

```bash
# All eight modules
python3 webraptor.py https://example.com

# Exclude modules, or select only those needed
python3 webraptor.py https://example.com --exclude nikto,dirsearch
python3 webraptor.py https://example.com --modules curl,nuclei --tool-timeout 600

# TLS checks on a specific port
python3 webraptor.py https://example.com:8443 --modules testssl,sslscan

# Multiple targets; at most two target workflows and three scanner processes
python3 webraptor.py --targets-file targets.txt \
  --target-concurrency 2 --threads 3 --nuclei-rate 10 --dirsearch-rate 5
```

Use either a target or `-l`/`--targets-file`. Files contain one target per line; blank lines and `#` comment lines are ignored. Host casing, default ports, and root paths are normalized for deduplication; distinct paths and queries remain separate. An explicit HTTPS URL takes precedence over a duplicate bare domain.

`--exclude` accepts comma-separated names, is repeatable, and applies after `--modules`. Excluded tools are not required or run. Unknown names and empty final selections are rejected.

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `--modules` | All eight | Comma-separated module names |
| `--exclude` | None | Comma-separated exclusions; repeatable |
| `--check-tools` | Off | Check versions and CLI compatibility without a target |
| `--resume` | None | Previous batch directory or `run.json` |
| `--no-progress` | Off | Silence progress on stderr |
| `--output-dir` | `results` | Base output directory |
| `--threads` | `6` | Global maximum active scanner processes |
| `--target-concurrency` | `1` | Concurrent target workflows |
| `--tool-timeout` | `1800` | Wall-clock seconds per module, excluding queue time |
| `--probe-timeout` | `8` | HTTP probe timeout in seconds |
| `--allow-scheme-fallback` | Off | Allow explicit URLs to try the other HTTP(S) scheme |
| `--insecure` | Off | Disable certificate verification for the probe and curl |
| `--nuclei-template` | Tool default | Custom template file or directory |
| `--wordlist` | Tool default | Dirsearch wordlist file |
| `--nuclei-rate` | `20` | Requests/second per Nuclei process |
| `--dirsearch-rate` | `10` | Requests/second per Dirsearch process |
| `--dirsearch-threads` | `10` | Workers per Dirsearch process |
| `--whatweb-wait` | `1` | Whole seconds between connections; one WhatWeb worker |
| `--nikto-pause` | `1` | Seconds between Nikto requests |
| `-H`, `--header` | None | Repeatable ASCII `Name: value` header |
| `--headers-file` | None | One header per line |
| `--cookie` | None | Cookie header value |
| `--cookie-file` | None | File containing a Cookie header value |

Use `--help` for CLI help. Request-rate controls are **per process, not a global traffic limit**; concurrent rates add together. Waybackurls, testssl, and sslscan manage their own request/connection rates.

## Scan behavior

- **Reachability:** bare domains try HTTPS then HTTP; explicit URLs retain their scheme unless fallback is enabled. The GET probe reads headers only and follows no redirects. Any HTTP response, including 4xx/5xx, counts as reachable—not as successful authentication. Failed probes skip HTTP modules; archive and TLS modules can still run.
- **curl:** runs `curl --head`, disables the default curl configuration, and saves headers without following redirects or fetching a body. HTTP errors such as 403/405 remain useful results; connection errors fail the module. The separate GET probe still runs first.
- **TLS:** checks use the original HTTPS hostname and port (default 443), without paths or queries, even if the probe fails or falls back to HTTP. TLS-only runs skip the probe. Explicit HTTP targets produce `not_applicable`, not a failure or an automatic scan of another port. STARTTLS is not enabled.
- **Certificates and redirects:** `--insecure` affects only the probe and curl. Other tools retain their own TLS handling. WhatWeb and Nuclei receive explicit no-redirect options; Nikto and Dirsearch are invoked without enabling redirects. Tool configuration and custom templates may affect behavior.
- **Progress and interruption:** stderr shows module states, total elapsed time, and active-module elapsed time on changes and every two seconds. Labels omit URL paths/queries. `--no-progress` suppresses these updates; report paths remain on stdout. Timeouts, Ctrl+C, and SIGTERM terminate scanner process groups and retain partial output. SIGKILL or machine failure may prevent final reports.

## Authentication and secrets

Prefer files to keep credentials out of shell history. A header file contains entries such as `Authorization: Bearer YOUR_TOKEN`; a cookie file contains only values such as `session=YOUR_SESSION; csrf=YOUR_TOKEN`.

```bash
python3 webraptor.py https://app.example.com \
  --headers-file headers.txt --cookie-file cookies.txt
```

Headers/cookies reach the probe, curl, WhatWeb, Nikto, Dirsearch, and Nuclei. testssl uses `--reqheader` for HTTP checks, not TLS-handshake authentication. sslscan and Waybackurls receive no HTTP credentials. Duplicate header names and multiline values are rejected; `--cookie` and `--cookie-file` are mutually exclusive. Automatic login, token refresh, and session validation are not provided. Authenticated target lists must use one host and port; other hosts/ports require separate runs.

Supplied header values, bearer tokens, cookie values, and common encoded forms are redacted from saved console logs and textual reports. Command lines are not logged, but scanner process arguments may expose credentials to local inspection. Text artifacts are sanitized after execution, so raw data can exist during a run. Binary artifacts, files outside the run directory, and newly discovered secrets are not comprehensively sanitized. Files use owner-only permissions; review evidence before sharing.

## Resume

Each new run prints its manifest path before scanning:

```bash
python3 webraptor.py --resume results/_runs/<run-id>/run.json
# The batch directory is also accepted; resupply credentials if needed:
python3 webraptor.py --resume results/_runs/<run-id> \
  --headers-file headers.txt --cookie-file cookies.txt --tool-timeout 3600
```

Resume writes a **new run**, copying completed outputs only when their SHA256 checks match. Failed, unfinished, skipped, missing, or modified results run again, including targets that never started. Old results remain intact; reused results retain timestamps and record `reused_from`. Reuse does not revalidate the target, and unfinished modules restart rather than continue scanner-internal checkpoints.

Targets and settings are restored. You may change timeouts, `--threads`, `--target-concurrency`, or `--output-dir`, and select a subset with `--modules`/`--exclude`. Other scan settings cannot change. Keep referenced templates/wordlists available and unchanged; reused modules do not need installed executables.

Manifests store URLs, settings, paths, and header names—not authentication values. Resupply the original header names/cookies; values may be refreshed. Redacted target URLs cannot be resumed automatically. Resume requires this version's `run.json` and the original `_runs/<run-id>` layout with sibling target directories; older runs without manifests are unsupported.

## Output and results

```text
<output-dir>/
├── _runs/<timestamp>-<run-id>/
│   ├── run.json                  # Resume manifest
│   ├── summary.json              # Batch results
│   └── report.html               # Target report links
└── <host>-<target-hash>/<timestamp>-<run-id>/
    ├── summary.json              # Probe, statuses, durations, findings
    ├── report.html
    ├── scan.log
    ├── curl_results.txt
    ├── whatweb_results.txt
    ├── nikto_results.txt
    ├── wayback_results/urls.txt
    ├── dirsearch_results/results.txt
    ├── nuclei_results.jsonl
    ├── testssl_results.txt
    ├── sslscan_results.txt
    ├── <module>_stdout.log        # Modules with separate native artifacts
    └── <module>_stderr.log
```

Only selected modules produce output. Target hashes distinguish schemes, ports, paths, and queries without exposing full URLs in filenames; unique run IDs prevent overwrites.

Module statuses are `completed`, `failed`, `timed_out`, `cancelled`, `skipped`, or `not_applicable`. Nuclei findings include severity, template, location, and completeness: missing/malformed JSONL is never treated as zero findings. Other outputs require manual review and are marked `not parsed`. Scanner matches need validation; successful execution does not guarantee coverage, security, or accepted authentication.

| Exit code | Meaning |
| --- | --- |
| `0` | All applicable modules completed, or all tool checks passed |
| `1` | Missing/incompatible/unverified tool, output error, or incomplete scan |
| `2` | Invalid arguments or input |
| `130` | Ctrl+C or SIGTERM interruption |

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Tests use local dummy scanners, loopback HTTP, and mocks—not external targets. They cover execution, cleanup, concurrency, redaction, reports, normalization, banner preservation, tool checks, progress, and resume. Validate installed scanner compatibility in your authorized environment.

## Responsible use and license

For educational and authorized testing only. Scan only systems you own or have explicit permission to test. Developers are not responsible for misuse or damage. Distributed under the [MIT License](LICENSE).
