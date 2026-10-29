# webraptor

WebRaptor combines eight web reconnaissance and security modules into a single-target or multi-target workflow. It provides module selection, bounded concurrency, timeouts, credential redaction, resumable runs, live progress, and HTML/JSON reports. The original dinosaur banner is preserved.

## Setup and modules

On Kali Linux or Parrot OS, run the automatic installer as your normal user:

```bash
./install.sh
source .venv/bin/activate
python webraptor.py --help
```

The installer uses sudo for apt operations, refreshes package indexes, installs
scanner packages and their runtimes, and creates a local `.venv` for
`requirements.txt`. It prefers distro packages for all scanners. If unavailable,
Dirsearch gets its own `.tools/dirsearch` environment, and Nuclei/waybackurls are
built from their official Go modules into `.venv/bin`. A suitable Go toolchain is
reused; otherwise an official stable Linux archive is downloaded from go.dev,
verified against its published SHA256 and installed under `.tools/go`, without
replacing system Go. The installer also downloads/updates Nuclei templates.

It finishes by running `--check-tools` explicitly for all eight modules and exits
nonzero if installation, template setup or any version/CLI check fails. It does
not run a target scan. Network access and sudo/root access for apt are required.
Reruns reuse local installations and let apt resolve current packages; no full
distribution upgrade or repository change is performed. Fallback binaries are
available after activating `.venv`; keep this checkout in place. macOS and other
distributions are rejected before changes. Install compatible scanner versions
if the final diagnostics report unsupported flags.

Requires **Python 3.9+ on Linux or macOS**. Install selected tools and their dependencies using the upstream instructions, and put their executables in `PATH`.

`requirements.txt` lists both the pip-installable Python dependencies and the
external scanner/runtime/asset checklist. External tools are documented as comments:
`pip install -r requirements.txt` installs the Python layer only. Install scanner
packages through Kali/Parrot's package manager or their official upstream installers;
automatic verification additionally uses sslscan regardless of module selection.

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

## Finding verification

All 22 built-in checks run automatically after the selected scanner modules for each target:

```bash
python3 webraptor.py https://app.example.com
python3 webraptor.py https://app.example.com \
  --headers-file headers.txt --cookie-file cookies.txt
```

Each check has its own function in `verification.py`. Checks cover missing HSTS,
CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP and
COEP; potentially insecure CSP; accepted weak TLS suites; TLS 1.3 rejection;
response compression/BREACH prerequisites;
wildcard certificates; legacy X-Frame-Options and X-XSS-Protection; and duplicate
security headers. Six additional checks cover SSLv2, SSLv3, TLSv1.0 and TLSv1.1
acceptance, weak leaf-certificate signature hashes (MD2/MD4/MD5/SHA-1), and expired
leaf certificates. Protocol failures remain unknown unless a completed scan
reached the server using other protocols. Certificate signature and UTC expiry
observations from sslscan do not imply successful chain or hostname validation.

Results contain a status (`found`, `not_found`, `potential`, `unknown`, or
`not_applicable`), evidence, a `verified` observation flag and limitations.
`verified` establishes the stated observation, **not successful exploitation**.
HTML reports show only checks with `status=found` and `verified=true` in one
Findings Summary section, ordered alphabetically. Potential, unknown, not-found
and not-applicable results are omitted from the HTML list. The HTML omits redundant Status and Verified observation columns. JSON retains every
check and its status/verification flags for auditing, and an empty list does not establish a clean assessment. Each entry includes its
context and `evidence_sources`; assigned risk ratings have been removed
from verification HTML and JSON. Original scanner data remains available as source
artifacts, without interpreting scanner ratings as WebRaptor ratings.

Each listed finding is collapsed by default; select its title (or use the keyboard)
to expand the tool evidence and observation details. Expansion uses native HTML
details controls and does not require JavaScript.
Expand All and Collapse All buttons control every listed finding together when
JavaScript is available; individual findings remain usable without it.

The report design adapts Bident's palette, panels and header layout for WebRaptor.
Verification, target and batch HTML reports include a short amber warning
disclaimer and an accessible sun/moon light/dark toggle. Single-target reports
show target details directly after the disclaimer: URL, host, port, scheme and
the advertised HTTP Server header, HTTP status, timestamps and scope. Missing
Server headers display as Not disclosed; unavailable collection is labeled
Unavailable, and older reports without captured server data show Not recorded. Theme preference is saved locally when browser storage is
available; blocked storage falls back safely. Reports have no external assets or
network dependencies; a CSP hash permits only the fixed theme script, and all
captured values are escaped before insertion into HTML.

Evidence identifies the actual tool or probe, its collection status, artifact path
and SHA256. HTTP checks use `verification_http.json`, captured by WebRaptor's httpx
GET collector; TLS handshakes and validated-certificate checks use
`verification_tls_probes.json` from Python ssl. Protocol/cipher and certificate
signature checks cite endpoint-matched `verification_tls.xml` from sslscan. Selected
curl/testssl/sslscan module outputs are linked as supplementary evidence when
available. Supplementary output is not claimed to independently corroborate a
finding; curl uses HEAD and may follow redirects, while the HTTP collector uses GET
without redirects. Reused scanner evidence is explicitly labeled. Selected HTTP
security headers and relevant TLS metadata are saved; response bodies, cookies and
unrelated response headers are excluded from collector evidence artifacts.
Remediation guidance is omitted from all findings for now.
Wildcard and legacy-header observations are informational and do not automatically
require removal. Guidance follows the
[OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
and [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html);
interpret findings in the application's context.
Missing headers refer only to the exact requested URL's response, including its
HTTP status; header presence does not prove browser enforcement or application-wide
coverage. Known token values and HSTS max-age receive basic validation; HSTS
max-age=0 is reported as disabled. Permissions-Policy currently receives a presence
check, not a full structured-field/browser-feature validation. CSP report-only
does not count as enforcement; meta policies in the captured HTML head are recognized.
Static CSP warnings remain potential because policies intersect and browser behavior
depends on context. Wildcards, repeated CSP policies and legacy headers are
configuration observations, not automatically vulnerabilities. X-Frame-Options
can still protect legacy clients; CSP frame-ancestors is the modern alternative.

The HTTP collector uses GET, preserves duplicate response fields, follows no
redirects, with a 2 MiB decoded-body limit per response and per-request timeouts.
JavaScript-library checking and advisory downloads have been removed; script
references are not fetched. It does not run a browser,
execute JavaScript, follow HTML base URLs, inspect dynamic/inline scripts, or contact
third-party script origins. Raw response bodies and authentication values are not
saved. Cancellation stops collection between bounded requests. TLS checks use the
original HTTPS hostname/port; explicit HTTP targets skip TLS/HSTS checks.
Weak suites are parsed from endpoint-matched sslscan XML; missing/failed scans do
not become clean results. TLS 1.3 uses a version-restricted handshake: a protocol-version
rejection is evidence of rejection from this client, while timeouts and generic
handshake failures are unknown. Wildcard detection requires a normally validated
peer certificate, even when `--insecure` permits HTTP collection.

Compression is reported as a potential BREACH prerequisite; secrets, reflected
attacker input and a usable compression oracle require separate validation.
Each target run includes `verification.json` and `verification.html`, with TLS
evidence alongside them. The main `summary.json` embeds verification results and
`report.html` links to the evidence. Verification status is also shown in progress. Exit code 1 means at least one
check is unknown or an execution/input error occurred; 0 means all checks reached
an assessment, **not that the target has no findings**. Interruption returns 130.
Verification always runs during normal scans, including `--resume`; scanner
outputs may be reused but verification is refreshed against the original target.
Older v1 manifests remain supported; any retired JavaScript-advisory setting is ignored.
Module selection/exclusion applies to the eight scanner modules; automatic
verification independently uses sslscan when available, even if its standalone
module is excluded. Its scanner shares the global `--threads` process budget and
target workflows respect `--target-concurrency`. `--check-tools` remains a local
dependency check and does not run verification. The former `--verify-findings`
option is accepted as a hidden compatibility alias and is no longer needed.
Verification needs Python dependencies from `requirements.txt` and sslscan for protocol/cipher/certificate checks,
and is designed for Linux (including Kali/Parrot) and macOS without platform-specific
paths.

## Scan behavior

- **Reachability:** bare domains try HTTPS then HTTP; explicit URLs retain their scheme unless fallback is enabled. The GET probe reads headers only and follows no redirects. Any HTTP response, including 4xx/5xx, counts as reachable—not as successful authentication. Failed probes skip HTTP modules; archive and TLS modules can still run.
- **curl:** runs `curl --head`, disables the default curl configuration, and follows HTTP(S) redirects such as 301/302/307/308 and saves every response header block, including the final response, without fetching a body. Redirects are capped at 10; loops fail the module while preserving captured headers. HTTP errors such as 403/405 remain useful results; connection errors fail the module. The separate GET probe still runs first. Curl retains its normal cross-host protection for Authorization and Cookie headers; other custom headers may be forwarded, so use credentials only with trusted redirect destinations.
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

For a native end-to-end check of all 22 finding checks and both report formats:

```bash
.venv/bin/python tests/local_findings_smoke.py
```

This requires `openssl`, `curl` and `sslscan`. It creates five temporary loopback
HTTPS profiles with missing/invalid/duplicate headers, compressed responses,
a trusted wildcard certificate, an expired SHA-1
certificate, anonymous ciphers and TLS 1.0/1.1 enabled. It asserts every check's
status/verification flag and compares every HTML result row and evidence field
with JSON. SSLv2/SSLv3 are tested as disabled on these modern fixture servers;
enabled cases have unit coverage. The fixture CA is passed only to the child
process environment, never installed in the system trust store, and private keys
are removed on completion. Saved reports and `validation.json` are retained under
`results/local-validation/<timestamp>/`. Add `--serve` for a loopback report preview.
No external target or advisory download is used.

## Responsible use and license

For educational and authorized testing only. Scan only systems you own or have explicit permission to test. Developers are not responsible for misuse or damage. Distributed under the [MIT License](LICENSE).
