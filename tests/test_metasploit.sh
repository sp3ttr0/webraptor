#!/usr/bin/env bash
set -euo pipefail

# Each case runs in a subshell to isolate working directories, mocks and state.

# FTP evidence sources
printf 'Running: FTP evidence sources\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/report.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-ftp-sources.XXXXXX")"
cd "$fixture_dir"
mkdir -p "$NSE_DIR" "$MSF_RESULT_DIR"
cat > "$NSE_DIR/s_ftp.txt" <<'DATA'
Nmap scan report for ftp.example (10.104.244.232)
21/tcp open ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_ -rw-r--r-- 1 ftp ftp 12 Jan 1 2026 welcome.txt
| ftp-brute: ERROR: Script execution failed
Nmap scan report for 192.0.2.2
2121/tcp open ftp
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
Nmap scan report for 192.0.2.3
21/tcp open ftp
| ftp-anon: Anonymous FTP login denied (FTP code 530)
Nmap scan report for 192.0.2.4
21/tcp closed ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
Nmap scan report for 192.0.2.5
21/tcp open ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_ ERROR: Script execution failed
Nmap scan report for 192.0.2.6
Host script results:
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
DATA
[[ "$(ftp_anonymous_nse_lines "$NSE_DIR/s_ftp.txt" endpoints)" == $'10.104.244.232:21\n192.0.2.2:2121' ]] || exit 1
append_findings_summary_section nse-only.html
grep -Fq '<strong>FTP Anonymous Enabled</strong>' nse-only.html || exit 1
grep -Fq '<td>10.104.244.232:21</td>' nse-only.html || exit 1
grep -Fq 'nmap_scripts/s_ftp.txt:3' nse-only.html || exit 1
cat > "$MSF_RESULT_DIR/ftp_anonymous_tcp_21.txt" <<'DATA'
[+] 10.104.244.232:21 - Anonymous READ access allowed
[+] 192.0.2.7:21 - Anonymous READ access allowed
DATA
append_findings_summary_section combined.html
python3 - <<'PYTEST'
from pathlib import Path
import re
s=Path('combined.html').read_text()
assert s.count('<strong>FTP Anonymous Enabled</strong>')==1
assert '3 affected host(s)' in s
table=re.search(r'<div data-affected-targets>.*?</tbody></table>',s,re.S).group()
assert table.count('<td>10.104.244.232:21</td>')==1
for host in ['10.104.244.232:21','192.0.2.2:2121','192.0.2.7:21']:assert f'<td>{host}</td>' in table
for host in ['192.0.2.3:21','192.0.2.4:21','192.0.2.5:21','192.0.2.6:21']:assert host not in table
assert 'Anonymous FTP login allowed (FTP code 230)' in s
assert 'Anonymous READ access allowed' in s
PYTEST
printf 'FTP Nmap/Metasploit source checks passed.\n'
)

# Metasploit findings and failed artifacts
printf 'Running: Metasploit findings and failed artifacts\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/report.sh
test_dir="$(mktemp -d /tmp/bident-msf-findings.XXXXXX)"
cd "$test_dir"
mkdir -p "$MSF_RESULT_DIR"
module_file() {
  local slug="$1" proto=tcp port
  case "$slug" in
    ftp_anonymous) port=21 ;;
    smtp_relay) port=25 ;;
    smb_ms17_010) port=445 ;;
    rdp_scanner|cve_2019_0708_bluekeep) port=3389 ;;
    vnc_none_auth) port=5900 ;;
    snmp_*) proto=udp; port=161 ;;
  esac
  printf '%s/%s_%s_%s.txt' "$MSF_RESULT_DIR" "$slug" "$proto" "$port"
}

# A command/path, stack trace, or generic completion message cannot establish
# any of the ten findings, even when it contains each finding keyword.
for slug in ftp_anonymous smtp_relay smb_ms17_010 rdp_scanner cve_2019_0708_bluekeep vnc_none_auth snmp_login snmp_enum snmp_enumusers snmp_enumshares; do
  file="$(module_file "$slug")"
  cat > "$file" <<EOF
resource (metasploit/rdp.rc)> use auxiliary/scanner/rdp/${slug}
resource (metasploit/rdp.rc)> set username detected_rdp_protocol
RHOSTS => file:/client/open_relay_vulnerable_community_public_users.txt
[-] Auxiliary failed: NameError uninitialized constant Net::NTLM
[-] Call stack:
[-] /usr/share/metasploit-framework/lib/msf/core/exploit/remote/rdp.rb:206
[*] Auxiliary module execution completed
EOF
  [[ -z "$(msf_finding_lines "$file")" ]]
  [[ -n "$(msf_failure_lines "$file")" ]]
done
append_findings_summary_section rejected.html
! grep -Fq '<li>' rejected.html || exit 1
append_msf_failed_artifacts failed.html
grep -Fq 'Metasploit Failed / Incomplete Checks' failed.html || exit 1
grep -Fq 'uninitialized constant Net::NTLM' failed.html || exit 1
! grep -Fq $'\033' failed.html || exit 1

# Retain module-specific successes, including ordinary status-level RDP
# messages and multiline SNMP share enumeration.
while IFS='|' read -r slug evidence; do
  file="$(module_file "$slug")"
  : > "$file"
  if [[ "$slug" == snmp_enum ]]; then printf 'Host IP : 192.0.2.1\n' >> "$file"; fi
  printf '\033[32m%s\033[0m\n' "$evidence" >> "$file"
  [[ -n "$(msf_finding_lines "$file")" ]] || {
    printf 'Missed success: %s\n' "$slug" >&2; exit 1;
  }
done <<'EOF'
ftp_anonymous|[+] 192.0.2.1:21 - Anonymous READ access allowed
smtp_relay|[+] 192.0.2.1:25 - Potential open SMTP relay detected: MAIL FROM -> RCPT TO
smb_ms17_010|[+] 192.0.2.1:445 - Host is likely VULNERABLE to MS17-010!
rdp_scanner|[*] Detected RDP on 192.0.2.1:3389 (name:LAB)
cve_2019_0708_bluekeep|[+] 192.0.2.1:3389 - The target is vulnerable. The target attempted cleanup.
vnc_none_auth|[+] 192.0.2.1:5900 - VNC server security types includes None, free access!
snmp_login|[+] 192.0.2.1:161 - Login Successful: public
snmp_enum|  Hostname : laboratory
snmp_enumusers|[+] 192.0.2.1:161 Found 2 users: alice, bob
EOF
printf '[+] 192.0.2.1\n\tPUBLIC - C:\\Public (0)\n' > "$MSF_RESULT_DIR/snmp_enumshares_udp_161.txt"
[[ -n "$(msf_finding_lines "$MSF_RESULT_DIR/snmp_enumshares_udp_161.txt")" ]] || exit 1

# Errors on another target must not hide a real success in a shared spool.
printf '[-] Auxiliary failed: NameError uninitialized constant Net::NTLM\n' >> "$MSF_RESULT_DIR/rdp_scanner_tcp_3389.txt"
append_findings_summary_section positive.html
[[ "$(grep -c '<li>' positive.html)" -eq 10 ]] || exit 1
# Complete logs intentionally retain failures; they must not be promoted evidence.
python3 - <<'PYTEST'
from pathlib import Path
import re
s=Path('positive.html').read_text()
assert 'NameError' in s
promoted=re.sub(r'<details class="artifact"><summary>Full Evidence.*?</pre></details>', '', s, flags=re.S)
assert 'NameError' not in promoted
PYTEST
append_msf_failed_artifacts mixed-failed.html
grep -Fq 'NameError' mixed-failed.html || exit 1

# Negative and informational results are not findings or execution failures.
printf '[*] 192.0.2.1 does not appear vulnerable to MS17-010\n' > "$MSF_RESULT_DIR/smb_ms17_010_tcp_445.txt"
[[ -z "$(msf_finding_lines "$MSF_RESULT_DIR/smb_ms17_010_tcp_445.txt")" ]] || exit 1
printf '[*] VNC server protocol version: 3.8\n' > "$MSF_RESULT_DIR/vnc_none_auth_tcp_5900.txt"
[[ -z "$(msf_finding_lines "$MSF_RESULT_DIR/vnc_none_auth_tcp_5900.txt")" ]] || exit 1
printf '[-] 192.0.2.1:161 - LOGIN FAILED: public\n' > "$MSF_RESULT_DIR/snmp_login_udp_161.txt"
[[ -z "$(msf_finding_lines "$MSF_RESULT_DIR/snmp_login_udp_161.txt")" ]] || exit 1
[[ -z "$(msf_failure_lines "$MSF_RESULT_DIR/snmp_login_udp_161.txt")" ]] || exit 1

printf 'tcp/3389\t143\n' > "$MSF_DIR/run_status.tsv"
append_msf_failed_artifacts process-failed.html
grep -Fq 'exit 143' process-failed.html || exit 1
generate_html_report
core_line="$(grep -n '<summary>Core Artifacts</summary>' report.html | cut -d: -f1)"
failed_line="$(grep -n '<summary>Metasploit Failed / Incomplete Checks</summary>' report.html | cut -d: -f1)"
[[ "$failed_line" -gt "$core_line" ]] || exit 1
# Core Artifacts embeds actual module output and console output, including
# modules that have no positive finding. Command scripts are separate.
printf '\033[31mConsole execution detail\033[0m\n' > "$MSF_DIR/msfconsole.log"
append_msf_output_artifacts actual-output.html
grep -Fq 'Full Metasploit Console Output' actual-output.html || exit 1
grep -Fq '<pre>Console execution detail' actual-output.html || exit 1
grep -Fq 'does not appear vulnerable to MS17-010' actual-output.html || exit 1
! grep -Fq $'\033' actual-output.html || exit 1
MSF_RESULT_DIR=missing-results append_msf_output_artifacts missing-output.html
grep -Fq 'No per-module result files were saved' missing-output.html || exit 1
grep -Fq 'Console execution detail' missing-output.html || exit 1
# Real Metasploit RDP output prefixes the result with a peer before the
# repeated "Detected RDP on" endpoint. Both NLA settings are discoveries.
cat > "$MSF_RESULT_DIR/rdp_scanner_tcp_3389.txt" <<'RDPFORMAT'
[*] 192.0.2.20:3389 - Detected RDP on 192.0.2.20:3389 (name:SERVER01) (domain:LAB) (os_version:6.3.9600) (Requires NLA: No)
[*] 192.0.2.21:3389 - Detected RDP on 192.0.2.21:3389 (name:SERVER02) (domain:LAB) (os_version:10.0.17763) (Requires NLA: Yes)
[*] Scanned 2 of 2 hosts (100% complete)
[*] Auxiliary module execution completed
RDPFORMAT
[[ "$(msf_finding_lines "$MSF_RESULT_DIR/rdp_scanner_tcp_3389.txt" endpoints)" == $'192.0.2.20:3389\n192.0.2.21:3389' ]] || exit 1
append_findings_summary_section rdp-format.html
grep -Fq '<strong>Remote Desktop Protocol Detection</strong>' rdp-format.html || exit 1
grep -Fq '<td>192.0.2.20:3389</td>' rdp-format.html || exit 1
grep -Fq '<td>192.0.2.21:3389</td>' rdp-format.html || exit 1
grep -Fq 'rdp_scanner_tcp_3389.txt:1' rdp-format.html || exit 1
printf 'Metasploit finding checks passed.\n'
)

# All-module output capture
printf 'Running: All-module output capture\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/metasploit.sh
source lib/report.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-msf-capture.XXXXXX")"
mkdir -p "$fixture_dir/path with spaces"
cd "$fixture_dir/path with spaces"
mkdir -p bin targets_with_open_ports
cat > targets_with_open_ports/open_ports_all.tsv <<'DATA'
target	protocol	port
192.0.2.1	tcp	21
192.0.2.1	tcp	25
192.0.2.1	tcp	445
192.0.2.1	tcp	3389
192.0.2.1	tcp	5900
192.0.2.1	udp	137
192.0.2.1	udp	161
DATA
# Turn literal tabs into the TSV delimiter without shell interpretation.
python3 - <<'PYTEST'
from pathlib import Path
p=Path('targets_with_open_ports/open_ports_all.tsv'); p.write_text(p.read_text().replace('\\t','\t'))
PYTEST
cat > bin/msfconsole <<'MOCK'
#!/bin/bash
while [[ $# -gt 0 ]]; do
 if [[ "$1" == -r ]]; then rc_file="$2"; shift 2; else shift; fi
done
module=$(awk '/^use / {print $2}' "$rc_file")
[[ "$(awk '/^use / {n++} END {print n+0}' "$rc_file")" == 1 ]] || exit 98
if [[ "${MOCK_MSF_FAIL:-false}" == true && "$module" == */snmp_enumshares ]]; then
 printf '[-] Auxiliary failed: NameError broken dependency\n' >&2
 exit 1
fi
case "$module" in
 */ftp/anonymous) printf '[+] 192.0.2.1:21 - Anonymous READ access allowed\n' ;;
 */smtp/smtp_relay) printf '[+] 192.0.2.1:25 - Potential open SMTP relay detected\n' ;;
 */smb/smb_ms17_010) printf '[+] 192.0.2.1:445 - Host is likely VULNERABLE to MS17-010!\n' ;;
 */rdp/rdp_scanner) printf '[*] 192.0.2.1:3389 - Detected RDP on 192.0.2.1:3389 (name:LAB) (Requires NLA: No)\n' ;;
 */rdp/cve_2019_0708_bluekeep) printf '[+] 192.0.2.1:3389 - The target is vulnerable.\n' ;;
 */vnc/vnc_none_auth) printf '[+] 192.0.2.1:5900 - VNC server security types includes None, free access!\n' ;;
 */netbios/nbname) printf '[+] 192.0.2.1 [LAB] OS:Windows Names:(LAB) Mac:00:11:22:33:44:55\n' ;;
 */snmp/snmp_login) printf '[+] 192.0.2.1:161 - Login Successful: public\n' ;;
 */snmp/snmp_enum) printf 'Host IP : 192.0.2.1\n Hostname : LAB\n' ;;
 */snmp/snmp_enumusers) printf '[+] 192.0.2.1:161 Found 1 users: alice\n' ;;
 */snmp/snmp_enumshares) printf '[+] 192.0.2.1\n\tPUBLIC - C:\\Public (0)\n' ;;
 *) exit 97 ;;
esac
printf '[*] Auxiliary module execution completed\n'
MOCK
chmod +x bin/msfconsole
export PATH="$PWD/bin:$PATH"
MSF_TIMEOUT=0
print_progress_bar() { :; }
run_msf_auxiliary_checks > terminal.txt
[[ "$(find "$MSF_RESULT_DIR" -name '*.txt' | wc -l | tr -d ' ')" == 11 ]] || exit 1
for file in "$MSF_RESULT_DIR"/*.txt; do
 [[ -n "$(msf_finding_lines "$file" endpoints)" ]] || { printf 'Missing finding: %s\n' "$file" >&2; exit 1; }
 grep -Fq 'Bident Metasploit process exit: 0' "$file" || exit 1
done
append_findings_summary_section all-findings.html
[[ "$(grep -c '<li><details' all-findings.html)" == 11 ]] || exit 1
# Scope, port and repeated RDP endpoint must all agree.
printf '192.0.2.1\n' > "$MSF_DIR/targets_tcp_3389.txt"
printf '%s\n' '[*] 192.0.2.2:3389 - Detected RDP on 192.0.2.2:3389 (name:OTHER)' '[*] 192.0.2.1:3390 - Detected RDP on 192.0.2.1:3390 (name:WRONGPORT)' '[*] 192.0.2.1:3389 - Detected RDP on 192.0.2.2:3389 (name:MISMATCH)' > "$MSF_RESULT_DIR/rdp_scanner_tcp_3389.txt"
[[ -z "$(msf_finding_lines "$MSF_RESULT_DIR/rdp_scanner_tcp_3389.txt" endpoints)" ]] || exit 1
export MOCK_MSF_FAIL=true
run_msf_auxiliary_checks >> terminal.txt
append_findings_summary_section partial-findings.html
[[ "$(grep -c '<li><details' partial-findings.html)" == 10 ]] || exit 1
append_msf_failed_artifacts errors.html
grep -q 'broken dependency' errors.html || exit 1
grep -q 'broken dependency' "$MSF_RESULT_DIR/snmp_enumshares_udp_161.txt" || exit 1
grep -q 'broken dependency' "$MSF_DIR/msfconsole.log" || exit 1
printf 'All-module Metasploit capture checks passed.\n'
)

# NetBIOS findings
printf 'Running: NetBIOS findings\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/metasploit.sh
source lib/report.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-netbios.XXXXXX")"
cd "$fixture_dir"
mkdir -p "$MSF_RESULT_DIR"
printf 'target\tprotocol\tport\n192.0.2.1\tudp\t137\n192.0.2.2\ttcp\t137\n192.0.2.3\tudp\t138\n' > open.tsv
msf_write_targets_file open.tsv udp 137 targets.txt
[[ "$(cat targets.txt)" == 192.0.2.1 ]] || exit 1
msf_add_port_modules netbios.rc udp 137 targets.txt
grep -Fq 'use auxiliary/scanner/netbios/nbname' netbios.rc || exit 1
grep -Fq 'set RPORT 137' netbios.rc || exit 1
msf_add_port_modules tcp.rc tcp 137 targets.txt
[[ ! -s tcp.rc ]] || exit 1
cat > "$MSF_RESULT_DIR/nbname_udp_137.txt" <<'DATA'
[*] Sending NetBIOS requests to 192.0.2.1->192.0.2.9 (9 hosts)
[+] 192.0.2.1 [SERVER01] OS:Windows Names:(SERVER01, CORP) Mac:00:11:22:33:44:55
[-] 192.0.2.2 Auxiliary failed: NameError
[*] Auxiliary module execution completed
DATA
[[ "$(msf_finding_lines "$MSF_RESULT_DIR/nbname_udp_137.txt" endpoints)" == 192.0.2.1:137 ]] || exit 1
append_findings_summary_section report.html
grep -Fq '<strong>NetBIOS Information Disclosure</strong>' report.html || exit 1
grep -Fq '<td>192.0.2.1:137</td>' report.html || exit 1
grep -Fq 'nbname_udp_137.txt:2' report.html || exit 1
[[ "$(default_result_label nbname_udp_137.txt)" == 'NetBIOS Information Disclosure' ]] || exit 1
printf 'NetBIOS Metasploit checks passed.\n'
)

# Ghostcat: do not trust saved-loot messages without a valid deployment XML.
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/report.sh
source lib/metasploit.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-ghostcat.XXXXXX")"
trap 'rm -rf "$fixture_dir"' EXIT
cd "$fixture_dir"
mkdir -p "$MSF_RESULT_DIR"
printf '192.0.2.1\n192.0.2.2\n' > "$MSF_DIR/targets_tcp_8009.txt"
printf '<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"><display-name>Fixture</display-name></web-app>\n' > 192.0.2.1_good.xml
printf '<html>Error</html>\n' > 192.0.2.2_error.xml
result="$MSF_RESULT_DIR/tomcat_ghostcat_tcp_8009.txt"
{
  printf 'RHOST => 192.0.2.1\n'
  cat 192.0.2.1_good.xml
  printf '[+] File contents save to: %s/192.0.2.1_good.xml\n' "$PWD"
  printf 'RHOST => 192.0.2.2\n[-] Unable to read file, target may not be vulnerable.\n'
  printf '[+] File contents save to: %s/192.0.2.1_good.xml\n' "$PWD"
  printf 'RHOST => 192.0.2.99\n[+] File contents save to: %s/192.0.2.1_good.xml\n' "$PWD"
  printf 'RHOST => 192.0.2.2\n[+] File contents save to: %s/192.0.2.2_error.xml\n' "$PWD"
} > "$result"
notification="$(msf_collect_ghostcat_loot "$result" "$MSF_DIR/targets_tcp_8009.txt")"
[[ "$notification" == *'Ghostcat): Found and verified.'* ]] || exit 1
[[ "$notification" == *"Saved file: $MSF_DIR/loot/ghostcat_192.0.2.1_8009_web.xml"* ]] || exit 1
[[ "$notification" != *'192.0.2.1:8009'* && "$notification" != *'192.0.2.2:8009'* ]] || exit 1

[[ "$(msf_finding_lines "$result" endpoints)" == '192.0.2.1:8009' ]] || exit 1
cmp 192.0.2.1_good.xml "$MSF_DIR/loot/ghostcat_192.0.2.1_8009_web.xml"
[[ ! -e "$MSF_DIR/loot/ghostcat_192.0.2.2_8009_web.xml" ]] || exit 1
# Saved file tampering, missing loot, and changed evidence cannot promote hosts.
cp "$result" original.txt
printf '\n[+] 192.0.2.2:8009 - Ghostcat file read verified; saved file: fake\n' >> "$result"
[[ -z "$(msf_finding_lines "$result" endpoints)" ]] || exit 1
cp original.txt "$result"
printf '<web-app><display-name>Changed</display-name></web-app>' > "$MSF_DIR/loot/ghostcat_192.0.2.1_8009_web.xml"
[[ -z "$(msf_finding_lines "$result" endpoints)" ]] || exit 1
cp 192.0.2.1_good.xml "$MSF_DIR/loot/ghostcat_192.0.2.1_8009_web.xml"
rm "$MSF_DIR/loot/ghostcat_192.0.2.1_8009_web.xml"
[[ -z "$(msf_finding_lines "$result" endpoints)" ]] || exit 1
msf_collect_ghostcat_loot "$result" "$MSF_DIR/targets_tcp_8009.txt"
[[ "$(msf_finding_lines "$result" endpoints)" == '192.0.2.1:8009' ]] || exit 1
# A valid XML file belonging to a different host is still not valid evidence.
cp 192.0.2.1_good.xml 192.0.2.2_wrong.xml
printf 'RHOST => 192.0.2.1\n' > "$result"
cat 192.0.2.1_good.xml >> "$result"
printf '[+] File contents save to: %s/192.0.2.2_wrong.xml\n' "$PWD" >> "$result"
msf_collect_ghostcat_loot "$result" "$MSF_DIR/targets_tcp_8009.txt"
[[ -z "$(msf_finding_lines "$result" endpoints)" ]] || exit 1
# Even a save message followed by an error in the same host block is rejected.
printf 'RHOST => 192.0.2.1\n' > "$result"
cat 192.0.2.1_good.xml >> "$result"
printf '[+] File contents save to: %s/192.0.2.1_good.xml\n[-] Auxiliary failed: parsing error\n' "$PWD" >> "$result"
notification="$(msf_collect_ghostcat_loot "$result" "$MSF_DIR/targets_tcp_8009.txt")"
[[ -z "$notification" ]] || exit 1
[[ -z "$(msf_finding_lines "$result" endpoints)" ]] || exit 1
msf_add_port_modules ghostcat.rc tcp 8009 "$MSF_DIR/targets_tcp_8009.txt"
grep -Fq 'use auxiliary/admin/http/tomcat_ghostcat' ghostcat.rc
grep -Fq 'set FILENAME /WEB-INF/web.xml' ghostcat.rc
[[ "$(grep -c '^run$' ghostcat.rc)" == 2 ]] || exit 1
msf_add_port_modules wrong.rc udp 8009 "$MSF_DIR/targets_tcp_8009.txt"
[[ ! -s wrong.rc ]] || exit 1
printf 'Ghostcat validation and loot checks passed.\n'
)

# Notifications share report validation and never print affected endpoints.
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/metasploit.sh
source lib/report.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-msf-notify.XXXXXX")"
trap 'rm -rf "$fixture_dir"' EXIT
cd "$fixture_dir"
mkdir -p "$MSF_RESULT_DIR"
printf '192.0.2.1\n' > "$MSF_DIR/targets_tcp_3389.txt"
file="$MSF_RESULT_DIR/rdp_scanner_tcp_3389.txt"
printf '[*] 192.0.2.1:3389 - Detected RDP on 192.0.2.1:3389 (Requires NLA: Yes)\n' > "$file"
output="$(msf_notify_result "$file" 0)"
[[ "$output" == *'Remote Desktop Protocol Detection: Found and verified.'* ]] || exit 1
[[ "$output" != *'192.0.2.1'* ]] || exit 1
printf '[-] Auxiliary failed: NameError uninitialized constant Net::NTLM\n' >> "$file"
output="$(msf_notify_result "$file" 0)"
[[ "$output" == *'Found and verified.'* && "$output" == *'Incomplete: module or connection error.'* ]] || exit 1
printf '[*] Auxiliary module execution completed\n' > "$file"
[[ -z "$(msf_notify_result "$file" 0)" ]] || exit 1
[[ "$(msf_notify_result "$file" 143)" == *'Incomplete: check timed out.'* ]] || exit 1
[[ "$(msf_notify_result "$file" 1)" == *'Incomplete: process exited with status 1.'* ]] || exit 1
printf '[*] 192.0.2.99:3389 - Detected RDP on 192.0.2.99:3389\n' > "$file"
[[ -z "$(msf_notify_result "$file" 0)" ]] || exit 1
printf 'Metasploit terminal notification checks passed.\n'
)
