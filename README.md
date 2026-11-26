# WebRaptor

Web application security scanner with automatic finding verification and HTML/JSON reports.

Includes curl, WhatWeb, Nikto, Waybackurls, ffuf, Katana, Nuclei, testssl.sh, and sslscan.

## Installation

On Kali Linux or Parrot OS, run as your normal user:

```bash
git clone https://github.com/sp3ttr0/webraptor.git
cd webraptor
./install.sh
source .venv/bin/activate
```

Requires Python 3.9+, network access, and sudo. The installer installs dependencies and checks all nine tools.

## Usage

```bash
# Scan a target
python webraptor.py https://example.com

# Scan targets from a file, one per line
python webraptor.py -l targets.txt

# Use a custom discovery wordlist
python webraptor.py https://example.com -w wordlist.txt

# Discover JavaScript endpoints and potential exposed secrets
python webraptor.py https://example.com --modules katana

# Resume a previous scan
python webraptor.py --resume results/<target>/<run-id>/data/run.json

# Check tools and view available options
python webraptor.py --check-tools
python webraptor.py --help
```

ffuf uses SecLists `directory-list-2.3-medium.txt` when installed, with Dirb or SecLists `common.txt` as fallbacks.

Katana crawls only the target’s exact origin (scheme, hostname, and port), with redirects disabled. It inspects fetched HTML/JavaScript and other response bodies for provider-specific credentials and sensitive assignments. Candidate exposures display full values and require review; detected values are never used or validated. Discovery is bounded, so missing results do not prove that no endpoints or secrets exist.

If your Katana package lacks required options such as `-mdp`, rerun `./install.sh`. The installer installs a compatible managed build when needed; WebRaptor prefers that build even without activating the virtual environment.

## Flags

| Flag | Description |
| --- | --- |
| `-h`, `--help` | Show help and exit. |
| `-l`, `--targets-file FILE` | Read targets from a file, one per line. |
| `-r`, `--resume PATH` | Resume from a run folder or manifest; resupply authentication if needed. |
| `-ct`, `--check-tools` | Check installed tools without scanning. |
| `-m`, `--modules NAMES` | Run selected tools, separated by commas. Default: all nine. |
| `-x`, `--exclude NAMES` | Skip comma-separated tools; may be repeated. |
| `-nt`, `--nuclei-template PATH` | Use a custom Nuclei template file or directory. |
| `-w`, `--wordlist FILE` | Use a custom ffuf wordlist. |
| `-t`, `--threads COUNT` | Maximum simultaneous scanner processes. Default: `6`. |
| `-tc`, `--target-concurrency COUNT` | Targets scanned simultaneously. Default: `1`. |
| `-tt`, `--tool-timeout SECONDS` | Time limit per scanner; keeps partial output. Default: `1800`. |
| `-pt`, `--probe-timeout SECONDS` | Timeout for reachability, verification, ffuf requests, and TLS probes. Default: `8`. |
| `-nr`, `--nuclei-rate REQUESTS` | Maximum Nuclei requests/second per process. Default: `20`. |
| `-fr`, `--ffuf-rate REQUESTS` | Maximum ffuf requests/second per process. Default: `10`. |
| `-ft`, `--ffuf-threads COUNT` | Request workers per ffuf process. Default: `10`. |
| `-ww`, `--whatweb-wait SECONDS` | Whole seconds between WhatWeb connections. Default: `1`. |
| `-np`, `--nikto-pause SECONDS` | Delay between Nikto requests; accepts decimals. Default: `1`. |
| `-kd`, `--katana-depth COUNT` | Maximum crawl depth. Default: `3`. |
| `-kr`, `--katana-rate REQUESTS` | Maximum Katana requests/second. Default: `10`. |
| `-kl`, `--katana-limit COUNT` | Maximum pages per origin. Default: `100`. |
| `-kt`, `--katana-duration SECONDS` | Maximum crawl duration. Default: `120`. |
| `-sf`, `--allow-scheme-fallback` | Try the other HTTP/HTTPS scheme if an explicit URL is unreachable. |
| `-k`, `--insecure` | Skip certificate validation in HTTP probes, verification, and curl. |
| `-H`, `--header HEADER` | Add a quoted `Name: value` header; may be repeated. |
| `-hf`, `--headers-file FILE` | Read headers from a file, one per line. |
| `-c`, `--cookie VALUE` | Send a quoted cookie value; cannot combine with `--cookie-file`. |
| `-cf`, `--cookie-file FILE` | Read a cookie value from a file, not a browser cookie jar. |
| `-o`, `--output-dir DIR` | Output directory. Default: `results`. |
| `-q`, `--no-progress` | Hide the progress panel; still save reports and logs. |

Module names: `curl`, `whatweb`, `nikto`, `waybackurls`, `ffuf`, `katana`, `nuclei`, `testssl`, `sslscan`.

## Reports

Open `report.html` inside the target's run folder under `results/`. Keep the `data/`, `evidence/`, and `logs/` folders together with the report.

## Disclaimer

Only scan systems you own or have permission to test. Automated findings may be incomplete or false positives; review the evidence before acting. Do not share secrets or private scan results.

## License

[MIT](LICENSE)
