#!/usr/bin/env bash
set -euo pipefail

# Each case runs in a subshell to isolate working directories, mocks and state.

# Terminal escape cleanup and evidence
printf 'Running: Terminal escape cleanup and evidence\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/report.sh

test_dir="$(mktemp -d /tmp/bident-report-output.XXXXXX)"
fixture="${test_dir}/tool.txt"
{
  printf '\033[0;36m# general\033[0m\n'
  printf '[0;31m[fail] weak cipher[0m\n'
  printf '\033[32m[+] Login Successful: user:example\033[0m\n'
  printf '\033]8;;https://example.test\033\\link\033]8;;\033\\\n'
  printf '\033]0;tool title\007output\r\n'
  printf '\033[2K<banner> & [warn]\n'
  printf '%s\n' '\x1b[31mred\x1b[0m' '\033[32mgreen\033[0m' '\u001b[36mcyan\u001b[0m'
} > "$fixture"
expected='# general
[fail] weak cipher
[+] Login Successful: user:example
link
output
&lt;banner&gt; &amp; [warn]
red
green
cyan'
actual="$(html_escape_file "$fixture")"
[[ "$actual" == "$expected" ]]
[[ "$(html_escape_text "$(cat "$fixture")")" == "$expected" ]]
[[ "$(html_escape_file_preview "$fixture")" == "$expected" ]]
# Both head/tail preview paths must also use the clean renderer.
printf '\033[31mHEAD\033[0m\n%0200d\n\033[32mTAIL\033[0m\n' 0 > "${test_dir}/large.txt"
actual="$(REPORT_EVIDENCE_MAX_BYTES=100 html_escape_file_preview "${test_dir}/large.txt")"
[[ "$actual" == *HEAD* && "$actual" == *TAIL* && "$actual" != *truncated* ]]
[[ "$actual" != *$'\033'* && "$actual" != *'[31m'* && "$actual" != *'[32m'* ]]
# Report rendering must not modify source evidence.
grep -q $'\033' "$fixture"
printf 'Terminal output report checks passed.\n'
)

# Service-table fields
printf 'Running: Service-table fields\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/ports.sh
source lib/report.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-services.XXXXXX")"
cd "$fixture_dir"
mkdir -p "$SCAN_DIR"
printf 'Host: 10.104.244.47 (host.example)\tPorts: 137/open/udp//netbios-ns//Microsoft Windows netbios-ns (workgroup: CORP)/\tIgnored State: open|filtered (999)\n' > "$SCAN_DIR/udp.gnmap"
printf 'Host: 10.104.244.48 ()\tPorts: 137/open|filtered/udp//netbios-ns///\tIgnored State: closed (999)\n' >> "$SCAN_DIR/udp.gnmap"
generate_services_report
python3 - <<'PYTEST'
from pathlib import Path
rows=Path('targets_with_open_ports/services.tsv').read_text().splitlines()
assert len(rows)==2
assert rows[1].split('\t')==['10.104.244.47','udp','137','netbios-ns','Microsoft Windows netbios-ns (workgroup: CORP)','10.104.244.47:137']
PYTEST
generate_html_report
grep -Fq '<td>10.104.244.47:137</td>' report.html || exit 1
! grep -Fq '<td>Ignored State:' report.html || exit 1
printf 'Service table field checks passed.\n'
)

# UDP base-scan table isolation
printf 'Running: UDP base-scan table isolation\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/ports.sh
source lib/report.sh
python3 - "$BIDENT_ROOT/lib/workflow.sh" <<'PYWORKFLOW'
from pathlib import Path
import sys,re
s=Path(sys.argv[1]).read_text()
command=re.search(r'"[^"\n]*nmap -n -sU [^"\n]*',s).group()
assert '-sV' not in command and '-sUV' not in command
final=s.index("  print_section 'Report Generation'")
assert s.index('  generate_services_report',final)<s.index('  generate_html_report',final)
PYWORKFLOW
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-udp-services.XXXXXX")"
cd "$fixture_dir"
mkdir -p "$SCAN_DIR" "$NSE_DIR"
for host in 1 2 3; do
 printf 'Host: 192.0.2.%s ()\tPorts: 53/open/udp//domain///, 123/open/udp//ntp///, 137/open/udp//netbios-ns///, 161/open/udp//snmp///, 623/open/udp//asf-rmcp///\n' "$host" >> "$SCAN_DIR/udp.gnmap"
done
printf 'Host: 192.0.2.1 ()\tPorts: 53/open/tcp//domain//TCP DNS version/\n' > "$SCAN_DIR/syn.gnmap"
cat > "$NSE_DIR/udp.txt" <<'DATA'
Nmap scan report for node.example (192.0.2.1)
53/udp open domain
| dns-nsid:
|   id.server: identifier-not-version
|_  bind.version: BIND 9.18.24
123/udp open ntp
| ntp-info:
|   version: ntpd 4.2.8p15
|_  system: Linux
137/udp open netbios-ns
161/udp open snmp
|  snmp-sysdescr: Linux appliance 5.15 <vendor>
|_   System uptime: 1 day
623/udp open asf-rmcp
| ipmi-version:
|_  Version: IPMI-2.0
Host script results:
|_nbstat: NetBIOS name: NODE01, NetBIOS user: <unknown>, NetBIOS MAC: 00:11:22:33:44:55
Nmap scan report for 192.0.2.2
53/tcp open domain
| dns-nsid:
|_ bind.version: MUST-NOT-LEAK-FROM-TCP
123/udp closed ntp
| ntp-info:
|_ version: MUST-NOT-LEAK-FROM-CLOSED-PORT
161/udp open snmp
| snmp-sysdescr: PARTIAL-MUST-NOT-APPEAR
|_ ERROR: Script execution failed
623/udp open|filtered asf-rmcp
| ipmi-version:
|_ Version: MUST-NOT-LEAK-FROM-AMBIGUOUS-PORT
Nmap scan report for 192.0.2.3
53/udp open domain
| dns-nsid:
|_ bind.version: unknown
Host script results:
|_nbstat: NetBIOS name: MUST-NOT-INFER-PORT, NetBIOS user: <unknown>
Nmap scan report for 192.0.2.99
53/udp open domain
| dns-nsid:
|_ bind.version: OUTSIDE-BASE-SCAN
DATA
generate_services_report
generate_html_report
python3 - <<'PYTEST'
from pathlib import Path
import csv
rows=list(csv.DictReader(Path('targets_with_open_ports/services.tsv').open(),delimiter='\t'))
lookup={(r['target'],r['protocol'],r['port']):r for r in rows}
assert lookup['192.0.2.1','tcp','53']['info']=='TCP DNS version'
for r in rows:
 if r['protocol']=='udp': assert r['info']=='',r
 assert r['target']!='192.0.2.99'
s=Path('report.html').read_text()
assert 'Evidence: nmap_scripts/udp.txt:' not in s
assert '<td>Not identified</td>' not in s
PYTEST
# Removing an NSE result must not retain stale enrichment.
: > "$NSE_DIR/udp.txt"
generate_services_report
[[ "$(awk -F '\t' 'NR>1 && $2=="udp" && $5!="" {n++} END {print n+0}' targets_with_open_ports/services.tsv)" == 0 ]] || exit 1
printf 'UDP service table isolation checks passed.\n'
)

# Results permissions, copy and compression
printf 'Running: Results permissions, copy and compression\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
repo_root="$PWD"
source lib/config.sh
source lib/utils.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-permissions.XXXXXX")"
RESULTS_DIR="$fixture_dir/results with spaces"
BIDENT_DROP_PRIVILEGES=true
BIDENT_RUN_USER="$(id -un)"
mkdir -p "$RESULTS_DIR"/{logs,base_scans,nmap_scripts,tool_results,metasploit/results}
for file in report.html summary.json logs/private.log base_scans/syn.nmap nmap_scripts/s_ftp.txt tool_results/ssh-audit_results.txt metasploit/results/rdp_scanner_tcp_3389.txt; do
 printf 'saved evidence\n' > "$RESULTS_DIR/$file"
 chmod 400 "$RESULTS_DIR/$file"
done
printf 'outside\n' > "$fixture_dir/outside.txt"
chmod 400 "$fixture_dir/outside.txt"
ln -s "$fixture_dir/outside.txt" "$RESULTS_DIR/logs/outside-link"
chmod 500 "$RESULTS_DIR/metasploit/results"
# Record ownership operations without needing root in the tests.
chown() { printf '%s\n' "$*" >> "$fixture_dir/chown.calls"; }
allow_unprivileged_output_writes
python3 - "$RESULTS_DIR" "$fixture_dir/outside.txt" <<'PYTEST'
from pathlib import Path
import stat,sys
root=Path(sys.argv[1])
for p in [root,*root.rglob('*')]:
    if p.is_symlink(): continue
    mode=stat.S_IMODE(p.stat().st_mode)
    assert mode & (0o700 if p.is_dir() else 0o600)==(0o700 if p.is_dir() else 0o600), str(p)
    if p.is_file(): assert not mode & 0o077, str(p)
assert stat.S_IMODE(Path(sys.argv[2]).stat().st_mode)==0o400
import shutil, tarfile
shutil.copytree(root, root.parent/'copied-results', symlinks=True)
with tarfile.open(root.parent/'results.tar.gz','w:gz') as archive:
    archive.add(root,arcname='results')
PYTEST
# Cleanup also runs on an unexpected exit and keeps the original exit status.
export RESULTS_DIR BIDENT_RUN_USER
bash -c 'source "$1/lib/config.sh"; source "$1/lib/utils.sh"; BIDENT_DROP_PRIVILEGES=true; BIDENT_RUN_USER="$(id -un)"; chown() { :; }; chmod 400 "$RESULTS_DIR/logs/private.log"; trap '\''finalize_results_on_exit "$?"'\'' EXIT; exit 7' test "$repo_root" && status=0 || status=$?
[[ "$status" == 7 && -w "$RESULTS_DIR/logs/private.log" ]] || exit 1
# Cancel/error cleanup stops only scanner sessions owned by this invocation.
BIDENT_OWNED_SCANS=(syn udp)
screen_session_exists() { return 0; }
screen() { printf '%s\n' "$*" >> "$fixture_dir/stopped.calls"; }
finalize_results_on_exit 130
grep -q 'syn -X quit' "$fixture_dir/stopped.calls" || exit 1
grep -q 'udp -X quit' "$fixture_dir/stopped.calls" || exit 1
! grep -q responder "$fixture_dir/stopped.calls" || exit 1
printf 'Whole-results permission checks passed.\n'
)

# Consistent expanders, shared review notices, full evidence and scan summary.
printf 'Running: Report presentation consistency\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/ports.sh
source lib/checks.sh
source lib/report.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-report-layout.XXXXXX")"
cd "$fixture_dir"
mkdir -p "$TOOL_DIR" "$NSE_DIR"
append_command_header "$TOOL_DIR/s_rpcclient_135.txt" rpcclient -U '' -N -c enumprivs 192.0.2.1
printf 'SeBackupPrivilege\n' >> "$TOOL_DIR/s_rpcclient_135.txt"
printf 'Nmap scan report for 192.0.2.1\n21/tcp open ftp\n| root:root - Valid credentials\n' > "$NSE_DIR/s_ftp.txt"
generate_html_report
python3 - <<'PYTEST'
from pathlib import Path
import re
s=Path('report.html').read_text()
assert 'aria-label="1 findings">1</span>' in s
assert 'aria-label="1 credentials">1</span>' in s
assert 'finding-severity' not in s
assert 'port-chevron' not in s
assert '<summary>Evidence</summary>' not in s
assert '<summary>Full Evidence' in s
assert '<span class="badge">' not in s
assert s.index('id="findingsSummary"') < s.index('id="expandAll"') < s.index('<section class="report-section" data-credential-copy')
assert 'Review each finding and its full evidence carefully' in s
assert 'Review each entry, its Host:Port' in s
summary=re.search(r'<section class="notice" aria-label="Scan details">(.*?)</section>',s,re.S).group(1)
for text in ['Scan Details','Start Time','Finish Time','Run Time','Scoped Hosts','Live Hosts','Total Ports Open']: assert text in summary
footer=re.search(r'\.report-footer \{(.*?)\}',s,re.S).group(1)
assert 'text-align: center' in footer and 'justify-content: center' in footer
assert 'details[open] > summary::after { content: "−"; }' in s
PYTEST
printf 'Report presentation checks passed.\n'
)

# Bulk disclosure controls affect only nested Findings Summary sections.
printf 'Running: Expand/collapse all report sections\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
node <<'JSTEST'
const fs = require('node:fs');
const assert = require('node:assert/strict');
const source=fs.readFileSync('lib/report.sh','utf8');
const script=source.split('// REPORT_TOGGLES_START')[1].split('// REPORT_TOGGLES_END')[0];
const sections=[{open:false},{open:true},{open:false},{open:false}];
const credentials=[{open:false},{open:false}];
const controls={expandAll:{},collapseAll:{},reportToggleStatus:{textContent:''},expandCredentials:{},collapseCredentials:{},credentialToggleStatus:{textContent:''}};
const document={querySelectorAll(selector){if(selector==='[data-credential-copy] details') return credentials; assert.equal(selector,'#findingsSummary details');return sections},getElementById(id){return controls[id]}};
for(const id of ['expandAll','collapseAll','expandCredentials','collapseCredentials']) controls[id].addEventListener=(event,handler)=>{assert.equal(event,'click');controls[id].click=handler};
new Function('document',script)(document);
controls.expandAll.click(); assert(sections.every(section=>section.open));
assert(credentials.every(section=>!section.open));
controls.expandCredentials.click(); assert(credentials.every(section=>section.open));
controls.collapseCredentials.click(); assert(credentials.every(section=>!section.open));
assert(sections.every(section=>section.open));
assert.equal(controls.reportToggleStatus.textContent,'Expanded 4 sections.');
controls.collapseAll.click(); assert(sections.every(section=>!section.open));
assert.equal(controls.reportToggleStatus.textContent,'Collapsed 4 sections.');
assert(!source.includes('name="open-port"'));
assert(!source.includes("document.querySelectorAll('details.port-card[open]')"));
console.log('Expand/collapse all checks passed.');
JSTEST
)
