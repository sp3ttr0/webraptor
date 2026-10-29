#!/usr/bin/env bash
set -euo pipefail

# Each case runs in a subshell to isolate working directories, mocks and state.

# Credential extraction
printf 'Running: Credential extraction\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/report.sh

assert_count() {
  local expected="$1" actual
  actual="$(credential_candidate_lines /dev/stdin | awk 'END {print NR + 0}')"
  [[ "$actual" -eq "$expected" ]] || {
    printf 'Expected %s candidates, got %s\n' "$expected" "$actual" >&2
    exit 1
  }
}

assert_count 0 <<'EOF'
# Nmap scan initiated as: nmap --script-args username=sa,password=example
sudo /usr/bin/nmap --script-args username=sa
Command: curl https://example.test/?username=admin&password=test
https://example.test/?user=admin&token=example
| NTLM domain: WORKGROUP
| NTLM authentication supported for domain users
| username: <unknown>
| password: [redacted]
| password: ********
| password:
| token: null
| account: disabled
[-] Login failed: username=admin password=test
| Anonymous login denied
| Anonymous access disabled
| No valid credentials: found
| username: admin (incorrect password)
| Valid credentials not found
Usage: username=example
Example: password=example
| password policy: minimum length 8
EOF

assert_count 8 <<'EOF'
| mysql-users:
|   debian-sys-maint
|   guest
|_  rootx
| mysql-info:
|   Protocol: 10
|_  Version: 5.0.51a
| username: discovered-user
| password: discovered-password
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
[+] Login Successful: admin:example
| hash: abc123def456
EOF

# Explicit NSE credential pairs must work for every username, without a list
# of privileged/common names. Failed attempts and bare pairs stay excluded.
assert_count 11 <<'EOFPAIRS'
| root:root - Valid credentials
| netadmin:netadmin - Valid credentials
| guest:guest - Valid credentials
| user:user - Valid credentials
| web:web - Valid credentials
| sysadmin:sysadmin - Valid credentials
| administrator:administrator - Valid credentials
| webadmin:webadmin - Valid credentials
| admin:admin - Valid credentials
|_ test:test - Valid credentials
| custom-account:custom-password - Valid credentials
EOFPAIRS
assert_count 0 <<'EOFNEGATIVE'
| root:root
| root:root - Invalid credentials
| guest:guest - No valid credentials
| root:root - Valid credentials not found
Example: root:root - Valid credentials
Command: root:root - Valid credentials
| root:[redacted] - Valid credentials
EOFNEGATIVE
fixture="$(mktemp "${TMPDIR:-/tmp}/bident-valid-pairs.XXXXXX")"
printf 'Nmap scan report for 192.0.2.10\n21/tcp open ftp\n' > "$fixture"
for name in root netadmin guest user web sysadmin administrator webadmin admin test; do
  printf '| %s:%s - Valid credentials\n' "$name" "$name" >> "$fixture"
  [[ "$(credential_display_value "| $name:$name - Valid credentials")" == "$name:$name - Valid credentials" ]] || exit 1
done
credential_candidate_lines "$fixture" > "${fixture}.rows"
[[ "$(awk -F '\034' '$4 == "192.0.2.10:21" {n++} END {print n+0}' "${fixture}.rows")" == 10 ]] || exit 1
assert_count 0 <<'EOFBOUNDARY'
[-] username: admin
[-] 192.0.2.1:21 - root:root - Valid credentials
| username: admin - Not valid credentials
| root:******** - Valid credentials
| http-title: Login Successful
| banner: Authentication Successful
resource (test.rc)> set USERNAME login successful
Command: echo root:root - Valid credentials
EOFBOUNDARY
assert_count 2 <<'EOFSUCCESS'
[+] 192.0.2.10:21 - root:root - Valid credentials
[+] 192.0.2.11:161 - Login Successful: public
EOFSUCCESS
printf 'Credential extraction checks passed.\n'
)

# Credential Host:Port and evidence
printf 'Running: Credential Host:Port and evidence\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/report.sh
test_dir="$(mktemp -d /tmp/bident-credential-endpoints.XXXXXX)"
cd "$test_dir"
mkdir -p "$NSE_DIR" "$MSF_RESULT_DIR"
cat > "$NSE_DIR/db_mysql.txt" <<'EOF'
# Nmap scan initiated as: nmap --script-args username=wrong,password=wrong
Nmap scan report for db.example (192.0.2.10)
3306/tcp open mysql
| mysql-users:
|   alice
|_  root
Nmap scan report for 192.0.2.11
| username: unattributed
2222/tcp open ssh
| username: bob
| password: spaces & <symbols>!
Host script results:
| username: host-only
Command: nmap -iL targets.txt --script-args user=wrong
| username: no-target
EOF
printf '[+] 192.0.2.12:161 - Login Successful: public (Access level: read-only)\n[-] 192.0.2.13:161 - LOGIN FAILED: private\n' > "$MSF_RESULT_DIR/snmp_login_udp_161.txt"
credential_candidate_lines "$NSE_DIR/db_mysql.txt" > rows.txt
expected=$'username: alice\t192.0.2.10:3306\nusername: root\t192.0.2.10:3306'
actual="$(awk -F '\034' '$3 ~ /^username:/ {print $3 "\t" $4}' rows.txt)"
[[ "$actual" == "$expected" ]] || exit 1
[[ "$(awk -F '\034' '$2 ~ /username: bob/ {print $4}' rows.txt)" == '192.0.2.11:2222' ]] || exit 1
[[ -z "$(awk -F '\034' '$2 ~ /unattributed|host-only|no-target/ {print $4}' rows.txt | tr -d '\n')" ]] || exit 1
append_credential_summary_section report.html
grep -Fq 'Copy Credentials' report.html || exit 1
grep -Fq 'Copy Hosts' report.html || exit 1
grep -Fq 'data-verified="true">192.0.2.10:3306' report.html || exit 1
grep -Fq 'data-verified="true">192.0.2.12:161' report.html || exit 1
grep -Fq 'data-verified="false">Not identified' report.html || exit 1
grep -Fq 'password: spaces &amp; &lt;symbols&gt;!' report.html || exit 1
! grep -Fq '192.0.2.13:161' report.html || exit 1
! grep -Fq 'user=wrong' report.html || exit 1
cat > boundaries.txt <<'EOFBOUNDARIES'
Nmap scan report for 192.0.2.20
21/tcp open ftp
| root:root - Valid credentials
22/tcp closed ssh
| guest:guest - Valid credentials
Nmap scan report for 192.0.2.21
3306/tcp open mysql
| mysql-users:
|_  root
Host script results:
| username: host-only
Command: echo root:root - Valid credentials
resource (test.rc)> set USERNAME login successful
EOFBOUNDARIES
credential_candidate_lines boundaries.txt > boundaries.rows
python3 - <<'PYTEST'
from pathlib import Path
source=Path('boundaries.txt').read_text().splitlines()
rows=[row.split('\x1c') for row in Path('boundaries.rows').read_text().strip('\n').split('\n')]
assert len(rows)==4
for nr,evidence,value,endpoint in rows:
    assert source[int(nr)-1].strip()==evidence
assert rows[0][3]=='192.0.2.20:21'
assert rows[1][3]==''  # Closed port cannot inherit the previous port.
assert rows[2][2:] == ['username: root','192.0.2.21:3306']
assert rows[3][3]==''  # A host script supplies no service port.
PYTEST
printf 'Credential endpoint checks passed.\n'
)

# Affected endpoints
printf 'Running: Affected endpoints\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/checks.sh
source lib/report.sh
test_dir="$(mktemp -d /tmp/bident-affected-endpoints.XXXXXX)"
cd "$test_dir"
mkdir -p "$TOOL_DIR" "$MSF_RESULT_DIR"

append_command_header rpc.txt impacket-rpcdump -p 135 192.0.2.10
printf 'Protocol: test\nProvider: rpc\n' >> rpc.txt
append_command_header rpc.txt impacket-rpcdump -p 135 192.0.2.11
printf 'Protocol: partial\nConnection refused\n' >> rpc.txt
[[ "$(tool_finding_endpoints 'Exposed RPC Services' rpc.txt)" == '192.0.2.10:135' ]] || exit 1

append_command_header anon-rpc.txt rpcclient -U '' -N -c enumprivs 192.0.2.12
printf 'SeBackupPrivilege\n' >> anon-rpc.txt
[[ "$(tool_finding_endpoints 'Unauthenticated Remote Procedure Call' anon-rpc.txt)" == '192.0.2.12:445' ]] || exit 1
append_command_header auth-rpc.txt rpcclient -U admin -c enumprivs 192.0.2.13
printf 'SeBackupPrivilege\n' >> auth-rpc.txt
[[ -z "$(tool_finding_endpoints 'Unauthenticated Remote Procedure Call' auth-rpc.txt)" ]] || exit 1

append_command_header ldap.txt ldapsearch -x -s base -b '' '(objectClass=*)' '*' -H ldap://192.0.2.20:3268
printf 'dn:\nnamingContexts: dc=example,dc=test\n' >> ldap.txt
append_command_header ldap.txt ldapsearch -x -D admin -H ldap://192.0.2.21:389
printf 'dn: dc=example,dc=test\n' >> ldap.txt
[[ "$(tool_finding_endpoints 'LDAP Anonymous Bind' ldap.txt)" == '192.0.2.20:3268' ]] || exit 1

cat > smb.txt <<'EOF'
Command: netexec smb targets_live.txt
SMB 192.0.2.30 445 HOST [*] (signing:False) (SMBv1:True)
SMB 192.0.2.31 445 HOST [*] (signing:True) (SMBv1:False)
SMB 192.0.2.30 445 HOST [*] (signing:False)
EOF
[[ "$(tool_finding_endpoints 'Misconfigured Server Message Block Signing' smb.txt)" == '192.0.2.30:445' ]] || exit 1
[[ "$(tool_finding_endpoints 'SMBv1 Enabled' smb.txt)" == '192.0.2.30:445' ]] || exit 1

append_command_header dns.txt dig @192.0.2.40 google.com A
printf ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0\n' >> dns.txt
append_command_header dns.txt dig @192.0.2.41 google.com A
printf ';; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 2\n;; flags: qr rd ra; QUERY: 1, ANSWER: 0\n' >> dns.txt
[[ "$(tool_finding_endpoints 'DNS Recursion Enabled' dns.txt)" == '192.0.2.40:53' ]] || exit 1
# An absent AD flag does not prove DNSSEC is unconfigured.
[[ -z "$(tool_finding_endpoints 'DNSSec Not Configured' dns.txt)" ]] || exit 1

append_command_header ike.txt ike-scan -M 192.0.2.50
printf '192.0.2.50 Main Mode Handshake returned\nSA=(Enc=3DES Hash=SHA1 Group=2:modp1024)\n' >> ike.txt
append_command_header ike.txt ike-scan -M 192.0.2.51
printf 'No handshake returned\nSuggested transform: Enc=3DES Hash=SHA1\n' >> ike.txt
[[ "$(tool_finding_endpoints 'IKE VPN Peer Weak Encryption' ike.txt)" == '192.0.2.50:500' ]] || exit 1

file="$MSF_RESULT_DIR/rdp_scanner_tcp_3389.txt"
cat > "$file" <<'EOF'
resource (rdp.rc)> set RHOSTS file:targets.txt
[*] Detected RDP on 192.0.2.60:3389 (name:LAB)
[-] 192.0.2.61:3389 Auxiliary failed: NameError Net::NTLM
[*] Auxiliary module execution completed
EOF
[[ "$(msf_finding_lines "$file" endpoints)" == '192.0.2.60:3389' ]] || exit 1
printf '[+] The target is vulnerable.\n' > "$MSF_RESULT_DIR/cve_2019_0708_bluekeep_tcp_3389.txt"
[[ -z "$(msf_finding_lines "$MSF_RESULT_DIR/cve_2019_0708_bluekeep_tcp_3389.txt" endpoints)" ]] || exit 1
printf '[+] 192.0.2.62:161 Found 1 users: alice\n' > "$MSF_RESULT_DIR/snmp_enumusers_udp_161.txt"
[[ "$(msf_finding_lines "$MSF_RESULT_DIR/snmp_enumusers_udp_161.txt" endpoints)" == '192.0.2.62:161' ]] || exit 1

append_finding_item report.html Review 'Exposed RPC Services' rpc.txt
append_finding_glob_item report.html Review 'RDP Detection' "$file"
# Full raw output is retained; validate promoted findings separately.
python3 - <<'PYTEST'
from pathlib import Path
import re
p = Path("report.html")
s = p.read_text()
assert "Full Evidence" in s
p.write_text(re.sub(r'<details class="artifact"><summary>Full Evidence.*?</pre></details>', '', s, flags=re.S))
PYTEST
grep -Fq '<div data-affected-targets>' report.html || exit 1
! grep -Fq '<summary>Affected' report.html || exit 1
! grep -Fq '<summary>Evidence</summary>' report.html || exit 1
grep -Fq '<td>192.0.2.10:135</td>' report.html || exit 1
grep -Fq '<td>192.0.2.60:3389</td>' report.html || exit 1
! grep -Fq 'Connection refused' report.html || exit 1
grep -Fq '192.0.2.10:135' report.html || exit 1
grep -Fq '192.0.2.60:3389' report.html || exit 1
! grep -Fq '192.0.2.61:3389' report.html || exit 1
[[ "$(printf '%s\n' '[2001:db8::1]:443' '[2001::::1]:443' '999.2.3.4:22' '192.0.2.1:70000' | verified_ip_port_lines)" == '[2001:db8::1]:443' ]] || exit 1
printf 'Affected endpoint checks passed.\n'
)

# Cross-host attribution
printf 'Running: Cross-host attribution\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/report.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-attribution.XXXXXX")"
cd "$fixture_dir"
mkdir -p "$TOOL_DIR"
cat > ssh.txt <<'DATA'
Command: ssh-audit 192.0.2.1
(enc) aes128-cbc -- [fail] deprecated CBC
Connection reset by peer
Command: ssh-audit 192.0.2.2
(enc) 3des-cbc -- [fail] deprecated 3DES
DATA
[[ "$(ssh_weak_cipher_rows ssh.txt)" == $'192.0.2.2:22\t3des-cbc' ]] || exit 1
cat > "$TOOL_DIR/ssh-audit_results.txt" <<'DATA'
Command: ssh-audit 999.1.1.1
(enc) aes128-cbc -- [fail] deprecated CBC
Command: ssh-audit 192.0.2.3
(enc) 3des-cbc -- [fail] deprecated 3DES
DATA
append_ssh_weak_cipher_finding ssh.html
grep -Fq '<td>192.0.2.3:22</td>' ssh.html || exit 1
! grep -Fq '<td>999.1.1.1:22</td>' ssh.html || exit 1

cat > tls.txt <<'DATA'
Nmap scan report for 192.0.2.10
443/tcp open https
| ssl-enum-ciphers:
|   TLSv1.0:
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
8443/tcp closed https-alt
| ssl-cert: Subject: commonName=*.wrong.example
| Not valid after: 2020-01-01T00:00:00
Nmap scan report for 192.0.2.11
443/tcp open https
| ssl-enum-ciphers:
|   TLSv1.0:
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
|_ ERROR: Script execution failed
DATA
awk -v kind=nse -v now_utc=20261022000000 -f "$BIDENT_ROOT/lib/tls_findings.awk" tls.txt > tls.rows
[[ "$(awk -F '\034' '{print $1 ":" $2}' tls.rows)" == $'3:192.0.2.10:443\n6:192.0.2.10:443' ]] || exit 1
cat > smb.txt <<'DATA'
SMB 192.0.2.20 445 HOST [-] negotiation failed (signing:False) (SMBv1:True)
SMB 192.0.2.21 445 HOST [*] (signing:False) (SMBv1:True)
DATA
for title in 'Misconfigured Server Message Block Signing' 'SMBv1 Enabled'; do
 [[ "$(tool_finding_endpoints "$title" smb.txt)" == '192.0.2.21:445' ]] || exit 1
done
cat > ike.txt <<'DATA'
Command: ike-scan -M 192.0.2.30
192.0.2.30 Main Mode Handshake returned
192.0.2.31 SA=(Enc=3DES Hash=SHA1 Group=2:modp1024)
DATA
[[ -z "$(tool_finding_endpoints 'IKE VPN Peer Weak Encryption' ike.txt)" ]] || exit 1
cat > ftp_anonymous_tcp_21.txt <<'DATA'
[+] 192.0.2.40:21 Anonymous login failed
[+] 192.0.2.41:21 Anonymous READ access allowed
DATA
[[ "$(msf_finding_lines ftp_anonymous_tcp_21.txt endpoints)" == '192.0.2.41:21' ]] || exit 1
cat > snmp_enum_udp_161.txt <<'DATA'
Host IP : 192.0.2.50
  Hostname : unknown
  Contact : n/a
===== another command =====
  Description : must not use stale host
DATA
[[ -z "$(msf_finding_lines snmp_enum_udp_161.txt endpoints)" ]] || exit 1
printf 'Finding attribution checks passed.\n'
)

# SSH cipher findings
printf 'Running: SSH cipher findings\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/checks.sh
source lib/report.sh
test_dir="$(mktemp -d /tmp/bident-ssh-ciphers.XXXXXX)"
cd "$test_dir"
mkdir -p "$TOOL_DIR"
fixture="$TOOL_DIR/ssh-audit_results.txt"
cat > "$fixture" <<'EOF'
===== timestamp =====
Command: /usr/bin/ssh-audit 192.0.2.1
(kex) diffie-hellman-group1-sha1 -- [fail] weak
(enc) aes256-ctr -- [info] supported
(mac) hmac-sha1 -- [fail] weak
===== timestamp =====
Command: /usr/bin/ssh-audit 192.0.2.2
(enc) aes128-cbc -- [warn] using weak cipher mode
(enc) 3des-cbc -- [fail] deprecated cipher
  `- [warn] small block size
(rec) -hmac-sha1 -- [warn] remove
===== timestamp =====
Command: /usr/bin/ssh-audit -p 2222 192.0.2.3
(enc) weak-test-cipher -- [info] supported
  `- [warn] insecure mode
===== timestamp =====
Command: /usr/bin/ssh-audit 192.0.2.4
Connection refused
EOF
printf '\n===== timestamp =====\nCommand: /usr/bin/ssh-audit 192.0.2.2\n\033[31m(enc) aes128-cbc -- [warn] weak\033[0m\n' >> "$fixture"
expected=$'192.0.2.2:22\taes128-cbc\n192.0.2.2:22\t3des-cbc\n192.0.2.3:2222\tweak-test-cipher'
[[ "$(ssh_weak_cipher_rows "$fixture")" == "$expected" ]]
printf '(key) ssh-rsa -- [fail] deprecated\n(enc) aes256-ctr -- [info] available\n' > clean.txt
if result_output_has_finding 'Weak SSH Ciphers' clean.txt; then exit 1; fi
printf '(enc) aes128-cbc -- [warn] weak\n' > weak.txt
result_output_has_finding 'Weak SSH Ciphers' weak.txt
append_ssh_weak_cipher_finding report.html
grep -Fq '2 affected host(s)' report.html
grep -Fq '<td>192.0.2.2:22</td><td><ul class="cipher-list"><li>aes128-cbc</li><li>3des-cbc</li></ul></td>' report.html
grep -Fq '<td>192.0.2.3:2222</td>' report.html
! grep -Fq '<td>192.0.2.1:22</td>' report.html
! grep -Fq '<td>192.0.2.4:22</td>' report.html
printf 'SSH weak cipher checks passed.\n'
)
