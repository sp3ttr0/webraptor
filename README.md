# WebRaptor

Web application security scanner with automatic finding verification and HTML/JSON reports.

Includes curl, WhatWeb, Nikto, Waybackurls, ffuf, Nuclei, testssl.sh, and sslscan.

## Installation

On Kali Linux or Parrot OS, run as your normal user:

```bash
git clone https://github.com/sp3ttr0/webraptor.git
cd webraptor
./install.sh
source .venv/bin/activate
```

Requires Python 3.9+, network access, and sudo. The installer installs dependencies and checks all eight tools.

## Usage

```bash
# Scan a target
python webraptor.py https://example.com

# Scan targets from a file, one per line
python webraptor.py -l targets.txt

# Use a custom discovery wordlist
python webraptor.py https://example.com -w wordlist.txt

# Resume a previous scan
python webraptor.py --resume results/<target>/<run-id>/data/run.json

# Check tools and view available options
python webraptor.py --check-tools
python webraptor.py --help
```

ffuf uses SecLists `directory-list-2.3-medium.txt` when installed, with Dirb or SecLists `common.txt` as fallbacks.

## Reports

Open `report.html` inside the target's run folder under `results/`. Keep the `data/`, `evidence/`, and `logs/` folders together with the report.

## Disclaimer

Only scan systems you own or have permission to test. Automated findings may be incomplete or false positives; review the evidence before acting. Do not share secrets or private scan results.

## License

[MIT](LICENSE)
