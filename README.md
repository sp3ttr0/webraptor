# webraptor

WebRaptor runs web reconnaissance and security scanners against one target or a deduplicated target list. It manages execution, keeps partial results when a tool fails, and generates JSON and HTML reports. The original dinosaur banner is unchanged.

## Features

- Curl HEAD response headers, WhatWeb fingerprinting, Nikto checks, Wayback URL discovery, Dirsearch content discovery, Nuclei scanning, and TLS checks with testssl and sslscan.
- Choose individual modules; only selected executables are required.
- Per-module wall-clock timeout and cleanup of scanner process groups on timeout, Ctrl+C, or SIGTERM.
- Bounded target and scanner concurrency with separate scanner request-rate controls.
- Unique directories for every run, per-target reports, and a batch index.
- Nuclei JSONL findings with severity, template, and location. Other tools retain their native output for manual review.
- HTTP headers and cookies for authenticated scans through supported modules, with redaction of supplied credentials from saved console logs and summaries.

## Requirements and setup

Python 3.9+ on Linux or macOS. Install the external tools you want to run using their upstream instructions, and make their executables available in `PATH`:

| Module / executable | Upstream |
| --- | --- |
| `curl` | [curl](https://curl.se/) |
| `whatweb` | [WhatWeb](https://github.com/urbanadventurer/WhatWeb) |
| `nikto` | [Nikto](https://github.com/sullo/nikto) |
| `waybackurls` | [Waybackurls](https://github.com/tomnomnom/waybackurls) |
| `dirsearch` | [Dirsearch](https://github.com/maurosoria/dirsearch) |
| `nuclei` | [Nuclei](https://github.com/projectdiscovery/nuclei) |
| `testssl` or `testssl.sh` | [testssl.sh](https://github.com/testssl/testssl.sh) |
| `sslscan` | [sslscan](https://github.com/rbsec/sslscan) |

From this directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 webraptor.py --help
```

The adapters target current upstream CLI options. In particular, Dirsearch must support `--output-formats`, and authenticated Nikto scans require `-Add-header`. Older installations may need updating. Unsupported flags will produce a failed module with diagnostics; the tests do not certify every installed scanner version.

## Usage

Run every module against one target:

```bash
python3 webraptor.py https://example.com
```

Exclude one or two modules from the default set:

```bash
python3 webraptor.py https://example.com --exclude nikto,dirsearch
```

`--exclude` accepts comma-separated names and can be repeated. It is applied after `--modules` when both are provided. Excluded tools are not required or run. Unknown names and selections that leave no modules are rejected.

Capture response headers only:

```bash
python3 webraptor.py https://example.com --modules curl
```

The curl module runs `curl --head` with quiet progress output and visible errors, saves headers to `curl_results.txt`, and uses the shared module timeout, authentication, and redaction controls. It disables the default curl configuration file and does not follow redirects or fetch a response body. HTTP error statuses such as 403 or 405 are retained as useful header results; connection errors fail the module. The workflow still performs its separate GET reachability probe before running HEAD.

Run TLS checks against the target host and port:

```bash
python3 webraptor.py https://example.com:8443 --modules testssl,sslscan
```

Both TLS modules are enabled by default. `testssl` accepts either `testssl` or `testssl.sh` in `PATH`, preferring `testssl`. Results are saved to `testssl_results.txt` and `sslscan_results.txt`, with separate stderr logs and links in the reports. They share the global concurrency and module timeout controls; their raw findings require manual review.

TLS checks use the original HTTPS hostname and port (443 by default), removing paths and queries. They run even when the HTTP probe fails, including certificate-verification failures. TLS-only runs skip the HTTP probe entirely. Explicit HTTP targets are marked `not_applicable` for TLS modules and do not cause a different port to be scanned. This status is not a failure. Supply an HTTPS URL to request TLS checks on a particular port. Bare domains retain their HTTPS TLS endpoint even if the web probe falls back to HTTP. STARTTLS is not enabled.

Run selected modules with a 10-minute timeout per module:

```bash
python3 webraptor.py https://example.com \
  --modules whatweb,nuclei --tool-timeout 600
```

Scan a target file with two concurrent target workflows and at most three active scanner processes across the entire batch:

```bash
python3 webraptor.py --targets-file targets.txt \
  --target-concurrency 2 --threads 3 \
  --modules whatweb,dirsearch,nuclei \
  --nuclei-rate 10 --dirsearch-rate 5
```

Example `targets.txt`:

```text
# Authorized targets, one per line
https://example.com
https://app.example.com:8443/
```

Blank lines and lines starting with `#` are ignored. Host casing, default ports, and an empty root path are normalized before deduplication. Paths and query strings remain distinct. When a bare domain and its explicit HTTPS URL both occur, the explicit scheme policy wins. Provide either the positional target or `--targets-file`, not both.

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `--modules` | All eight | Comma-separated module names |
| `--exclude` | None | Comma-separated modules to omit; repeatable |
| `--output-dir` | `results` | Base results directory |
| `--threads` | `6` | Global maximum active scanner processes |
| `--target-concurrency` | `1` | Maximum concurrent target workflows |
| `--tool-timeout` | `1800` | Wall-clock seconds per running module; queue time excluded |
| `--probe-timeout` | `8` | HTTP probe timeout in seconds |
| `--allow-scheme-fallback` | Off | Permit an explicit HTTP(S) URL to try the other scheme |
| `--insecure` | Off | Disable certificate verification for the reachability probe and curl |
| `--nuclei-template` | Tool default | Custom template file or directory |
| `--wordlist` | Tool default | Dirsearch wordlist file |
| `--nuclei-rate` | `20` | Nuclei requests per second per process |
| `--dirsearch-rate` | `10` | Dirsearch requests per second per process |
| `--dirsearch-threads` | `10` | Workers within each Dirsearch process |
| `--whatweb-wait` | `1` | Whole seconds between WhatWeb connections; one worker |
| `--nikto-pause` | `1` | Seconds between Nikto requests |
| `-H`, `--header` | None | Repeatable `Name: value` header |
| `--headers-file` | None | File of headers, one per line |
| `--cookie` | None | Cookie header value |
| `--cookie-file` | None | File containing the Cookie header value |

Rate limits apply per scanner process. They are **not a global requests-per-second ceiling**: rates from concurrent scanners and targets add together. Waybackurls uses its own archive-service request behavior. It has no wrapper-enforced request-rate limit. testssl and sslscan also manage their own TLS connection rates; HTTP scanner rate options do not limit them.

An explicit URL keeps its scheme unless `--allow-scheme-fallback` is set. A bare domain tries HTTPS and then HTTP. Any HTTP response, including 401, 403, 404, or 500, establishes reachability; it does not prove authentication succeeded. The probe reads only response headers and does not follow redirects. On unreachable targets, HTTP modules are skipped while selected Wayback discovery and TLS checks can still run.

`--insecure` allows the probe and curl to accept self-signed or otherwise invalid certificates. The other external scanners retain their own certificate handling; this flag is not a universal TLS policy override. WhatWeb and Nuclei are explicitly instructed not to follow redirects; Dirsearch and Nikto are invoked without enabling redirect following. Tool configuration and custom templates can affect behavior.

## Authenticated scans

Use a header file to avoid putting secrets in your shell history:

```text
Authorization: Bearer YOUR_TOKEN
X-Api-Key: YOUR_API_KEY
```

A cookie file contains just the value, for example `session=YOUR_SESSION; csrf=YOUR_TOKEN`.

```bash
python3 webraptor.py https://app.example.com \
  --modules whatweb,nikto,dirsearch,nuclei \
  --headers-file headers.txt --cookie-file cookies.txt
```

Headers are forwarded to the probe, curl, WhatWeb, Nikto, Dirsearch, and Nuclei. Cookies are sent as a Cookie header. Duplicate header names and multiline values are rejected. Headers use ASCII values. No automatic login, token refresh, or authenticated-session validation is performed.

testssl receives headers and cookies through `--reqheader` for its HTTP checks; this does not authenticate the TLS handshake. sslscan and Waybackurls never receive HTTP headers or cookies.

Authenticated target files may include multiple paths on one host and port. Different hosts or ports require separate authenticated runs so the same credentials are not silently applied across unrelated targets.

Supplied header values, bearer tokens, cookie values, and common encoded forms are redacted from saved console logs and textual reports. The wrapper never logs scanner command lines. Scanner commands still carry headers in their process arguments, which may be visible to local process inspection. Binary artifacts, screenshots, scanner-managed files outside the run directory, and secrets newly disclosed by the target are not comprehensively sanitized. Textual scanner artifacts are sanitized after the process stops; raw evidence can exist during execution. Run files are created with owner-only permissions. Review evidence before sharing it.

## Output and reporting

```text
<output-dir>/
├── _runs/<timestamp>-<run-id>/
│   ├── summary.json              # Batch results
│   └── report.html               # Links to target reports
└── <host>-<target-hash>/<timestamp>-<run-id>/
    ├── summary.json              # Probe, module statuses, durations, findings
    ├── report.html               # Human-readable target report
    ├── scan.log
    ├── curl_results.txt          # HEAD response headers
    ├── whatweb_results.txt
    ├── nikto_results.txt
    ├── wayback_results/urls.txt
    ├── dirsearch_results/results.txt
    ├── nuclei_results.jsonl
    ├── testssl_results.txt
    ├── sslscan_results.txt
    ├── <module>_stdout.log        # Tools that write separate native artifacts
    └── <module>_stderr.log
```

Only selected modules produce output. The target hash distinguishes schemes, ports, paths, and queries without putting full URLs into filenames. Run identifiers prevent overwrites. Partial results survive ordinary timeouts and handled interruptions; SIGKILL and machine failure cannot guarantee a finalized report.

Reports distinguish `completed`, `failed`, `timed_out`, `cancelled`, `skipped`, and `not_applicable`. Nuclei findings have separate completeness information: a missing or malformed JSONL file is not interpreted as zero findings. Other module outputs are marked `not parsed`, not zero. Nuclei matches require validation before treating them as confirmed vulnerabilities.

A scanner returning exit code zero means that its process completed; it cannot guarantee complete application coverage. HTTP 200 also does not guarantee that supplied authentication was accepted. Consult raw outputs and stderr logs.

| Exit code | Meaning |
| --- | --- |
| `0` | All applicable selected modules completed successfully |
| `1` | Missing tool, output error, or incomplete/failed target workflow |
| `2` | Invalid command-line arguments or input |
| `130` | Ctrl+C or SIGTERM interruption |

## Development and validation

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Tests use local dummy scanner executables, a loopback HTTP server, and HTTP mocks. They cover real subprocess exit codes, stderr capture, timeouts, process-group cleanup, signal handling, batch concurrency, redaction, report generation, URL normalization, and banner preservation. No external targets are scanned. Installed third-party scanner compatibility still needs validation in your authorized testing environment.

Adapter references: [WhatWeb CLI](https://github.com/urbanadventurer/WhatWeb), [Nikto CLI](https://github.com/sullo/nikto), [Dirsearch CLI](https://github.com/maurosoria/dirsearch/blob/master/lib/parse/cmdline.py), [Nuclei CLI](https://github.com/projectdiscovery/nuclei).

## Disclaimer

For educational and authorized security testing only. Use only on systems you own or have explicit permission to test. The developers are not responsible for misuse or damage.

## License

MIT License. See [LICENSE](LICENSE).
