<p align="center">
  <img src="assets/bident-logo.svg" alt="Bident logo" width="160">
</p>

# Bident

Network VAPT Toolkit by **sp3ttr0**. Discovers hosts, scans TCP/UDP ports, runs follow-up checks on confirmed open ports, and generates an HTML report with affected Host:Port lists, copy buttons, and source evidence.

## Setup

Designed for Kali/Parrot-style Debian systems. Clone the repository, enter its folder, then run:

```bash
chmod +x bident.sh
./bident.sh --check-deps
sudo ./bident.sh --install-deps
```

Automatic installation uses configured apt repositories; unavailable packages are skipped.

Core dependencies include Bash, Nmap, screen, sudo, and standard Unix utilities. Optional tools: NetExec, ssh-audit, impacket-rpcdump, rpcclient, ldapsearch, dig, testssl, sslscan, ike-scan, Responder, and Metasploit.

## Usage

Run scans with sudo from your normal account:

```bash
# Scan a scope file; save results in a Git-ignored folder.
sudo ./bident.sh -f scope.txt -o results/

# Scan one host without UDP.
sudo ./bident.sh -t 192.0.2.10 --no-udp

# Scan all ports.
sudo ./bident.sh -f scope.txt -p- -T4

# Resume an existing scan.
sudo ./bident.sh --resume results/
```

| Option | Purpose / default |
|---|---|
| `-f <file>` / `-t <host>` | Scope file or single host |
| `-o <dir>` | Results folder; defaults to `bident_results_<timestamp>` |
| `--resume <dir>` | Resume an existing results folder |
| `-p-` | Scan all TCP/UDP ports |
| `--no-udp` | Skip UDP scans and follow-ups |
| `--no-msf` | Skip Metasploit |
| `--script-timeout T` | Per NSE script instance; **30m**; `0` = unlimited |
| `--tool-timeout N` | External-tool timeout in seconds; disabled by default |
| `--msf-timeout N` | Per Metasploit module process, in seconds; **120** |
| `--msf-threads N` | Metasploit scanner threads; **16** |
| `-T1` … `-T5` | Nmap timing; **-T4** |
| `--responder` | Start Responder on `eth0`; continues after Bident finishes |

Use `./bident.sh --help` for full usage. The SNMP community list is `wordlists/snmp_communities.txt`.

## Scan Behavior

- The UDP base scan uses `-sU` without version detection. UDP NSE output remains in the report evidence and does not populate the Services table. The Services table shows only UDP base-scan information; missing details remain blank.

- NetExec SMB and rpcdump dependencies are checked silently before discovery. Failures are reported and the affected tool is skipped.
- SSL/TLS checks cover **443 and 8443**, after NSE and before Metasploit. testssl is primary, sslscan cross-checks, and SSL/TLS NSE runs only when neither is installed.
- TLS tools have a fixed **30-minute timeout per tool per Host:Port**, requiring GNU `timeout` or `gtimeout`. This is independent of `--tool-timeout`.
- Ghostcat runs only for confirmed open TCP 8009 hosts, requesting `/WEB-INF/web.xml`. Valid deployment XML is copied to `metasploit/loot/` and included as **Apache Tomcat AJP File Read (Ghostcat)**; Python 3 is required for XML validation. Host attribution, retrieved XML, and SHA-256 hashes of the saved file and full log are rechecked when building the report.
- Each Metasploit module runs separately, with complete stdout/stderr captured. Separate processes add console startup time. Verified findings print a success notification; runtime failures and timeouts print **Incomplete** with a log path. Affected Host:Port lists remain in the report.
- Findings require qualifying saved evidence tied to the host and port. Failed or ambiguous checks are excluded from affected lists; this does not independently verify exploitability.
- Credential entries retain their evidence and Host:Port. Unknown endpoints show **Not identified**; enumerated usernames alone do not confirm passwords. Credential copy buttons cover the displayed entries, up to 80.

## Results

```text
report.html              Searchable report, findings, evidence, and copy buttons
summary.json             Machine-readable summary
base_scans/              Nmap base scan outputs
nmap_scripts/            NSE results
tool_results/            External-tool results
metasploit/results/      Per-module Metasploit output
metasploit/msfconsole.log Combined Metasploit console output
logs/                    Execution errors and scan logs
targets_with_open_ports/ Service tables and target lists
```

Verified external-tool findings print **Found and verified** without affected Host:Port lists; completed checks with no verified finding stay silent. Failed external, TLS, and Metasploit checks print **Incomplete** and appear under **Core Artifacts**. Full evidence is retained without truncation. Start time, finish time, and runtime appear in the terminal and report; resumed scans measure the current invocation.

When launched with sudo, results ownership and owner access are restored to the invoking user on completion, cancellation, and ordinary errors. Forced termination or shutdown may still require manual permission repair.

## Tests

Run `bash tests/run.sh` to check findings/credentials, Metasploit, reports/permissions, runtime handling, TLS, and clipboard actions. Tests use synthetic output and mocked tools; they do not run live scans. Requires Bash, Python 3, Node.js, and standard Unix utilities. Each shell suite can also run individually.

## Git Hygiene

Keep source, documentation, `tests/` with synthetic data, and the bundled wordlist in Git. Never commit real scan results, client scope files, credentials, or logs. Standard outputs are ignored; add custom output folders to `.gitignore` and review `git status --short` and `git diff --cached` before committing. Ignore rules do not protect already tracked files.

## Disclaimer

Use only on systems you own or are explicitly authorized to assess. Review findings before acting; automated results can contain false positives. The owner and contributors are not liable for unauthorized or harmful use.

## License

No license is included yet; choose one before publishing.
