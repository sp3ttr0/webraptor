#!/usr/bin/env bash
set -euo pipefail

# Each case runs in a subshell to isolate working directories, mocks and state.

# TLS finding extraction
printf 'Running: TLS finding extraction\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/report.sh
test_dir="$(mktemp -d /tmp/bident-tls-findings.XXXXXX)"
cd "$test_dir"
mkdir -p "$TOOL_DIR" "$NSE_DIR"
cat > "$TOOL_DIR/testssl_results.txt" <<'EOF'
===== 2026-10-21 10:00:00 =====
Command: testssl 192.0.2.10:443
 SSLv2 offered (NOT ok)
 SSLv3 offered (NOT ok)
 TLS 1 offered (deprecated)
 TLS 1.1 offered (deprecated)
 TLS 1.2 offered
 TLS 1.3 not offered
 NULL ciphers (no encryption) offered (NOT ok)
 BREACH (CVE-2013-3587) potentially NOT ok, "gzip deflate" HTTP compression detected
 BREACH (CVE-2013-3587) gzip:yes deflate:no
 Common Name (CN) *.example.test
 Signature Algorithm SHA1 with RSA
 Certificate Validity (UTC) expired (2020-01-01)
===== 2026-10-21 10:01:00 =====
Command: testssl 192.0.2.11:443
 SSLv2 not offered (OK)
 SSLv3 not offered (OK)
 TLS 1 not offered
 TLS 1.1 not offered
 TLS 1.3 offered
 NULL ciphers (no encryption) not offered (OK)
 BREACH (CVE-2013-3587) no gzip/deflate/compress/br HTTP compression (OK)
 Issuer CN=*.issuer.test
 Signature Algorithm SHA256 with RSA
 Certificate Validity (UTC) expires in 20 days
===== 2026-10-21 10:02:00 =====
Command: testssl 192.0.2.12:443
 SSLv2 offered
 Fatal error: connection refused
===== 2026-10-21 10:03:00 =====
Command: testssl 192.0.2.20:443
 TLS 1.3 offered
EOF
cat > "$TOOL_DIR/sslscan_results.txt" <<'EOF'
Command: sslscan 192.0.2.20:443
Testing SSL server 192.0.2.20 on port 443 using SNI name 192.0.2.20
SSLv2 enabled
SSLv3 enabled
TLSv1.0 enabled
TLSv1.1 enabled
TLSv1.2 enabled
TLSv1.3 disabled
Accepted TLSv1.2 112 bits DES-CBC3-SHA
SSL Certificate:
Signature Algorithm: sha1WithRSAEncryption
Subject: /CN=*.example.test
Not valid after: Jan  1 00:00:00 2020 GMT
Command: sslscan 192.0.2.21:443
Testing SSL server 192.0.2.21 on port 443 using SNI name 192.0.2.21
TLSv1.3 disabled
Rejected TLSv1.2 40 bits EXP-RC4-MD5
Command: sslscan 192.0.2.22:443
Testing SSL server 192.0.2.22 on port 443 using SNI name 192.0.2.22
TLSv1.2 enabled
TLSv1.3 disabled (client cannot test this protocol)
Accepted TLSv1.2 128 bits ECDHE-RSA-AES128-GCM-SHA256
Signature Algorithm: sha256WithRSAEncryption
SHA1 Fingerprint: abcdef
Subject: /CN=ordinary.example.test
Not valid after: Jan  1 00:00:00 2099 GMT
SSL Certificate chain:
Signature Algorithm: sha1WithRSAEncryption
Subject: /CN=*.issuer.test
Not valid after: Jan  1 00:00:00 2020 GMT
EOF
cat > "$NSE_DIR/ssl_tls_results.txt" <<'EOF'
Nmap scan report for 192.0.2.30
8443/tcp open https
| ssl-enum-ciphers:
|   SSLv3:
|     ciphers:
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
|   TLSv1.0:
|     ciphers:
|       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A
|   TLSv1.1:
|     ciphers:
|       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A
| ssl-cert: Subject: commonName=*.example.test
| Signature Algorithm: sha1WithRSAEncryption
| Not valid after: 2020-01-01T00:00:00
Nmap scan report for 192.0.2.31
443/tcp open https
| ssl-enum-ciphers:
|   TLSv1.0:
|_ ERROR: Script execution failed
Nmap scan report for 192.0.2.32
443/tcp open https
| ssl-enum-ciphers:
|   TLSv1.2:
|       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
EOF
append_tls_findings_summary findings.html
# Full raw output is retained; validate promoted findings separately.
python3 - <<'PYTEST'
from pathlib import Path
import re
p = Path("findings.html")
s = p.read_text()
assert "Full Evidence" in s
assert "nmap_scripts/ssl_tls_results.txt:15" in s
p.write_text(re.sub(r'<details class="artifact"><summary>Full Evidence.*?</pre></details>', '', s, flags=re.S))
PYTEST
[[ "$(grep -c '<li><details' findings.html)" -eq 10 ]] || exit 1
for endpoint in 192.0.2.10:443 192.0.2.20:443 192.0.2.30:8443; do
  grep -Fq "$endpoint" findings.html || exit 1
done
for endpoint in 192.0.2.11:443 192.0.2.12:443 192.0.2.21:443 192.0.2.22:443 192.0.2.31:443 192.0.2.32:443; do
  ! grep -Fq "$endpoint" findings.html || exit 1
done
grep -Fq 'Copy hosts' findings.html || exit 1
! grep -Fq '<summary>Evidence</summary>' findings.html || exit 1
grep -Fq '<li>DES-CBC3-SHA</li>' findings.html || exit 1
grep -Fq '<li>TLS_RSA_WITH_3DES_EDE_CBC_SHA</li>' findings.html || exit 1
grep -Fq 'Individual cipher names unavailable in saved output; rescan required.' findings.html || exit 1
grep -Fq 'TLSv1.3 Disabled</strong><span>1 affected host(s)' findings.html || exit 1
! grep -Fq 'potential BREACH exposure' findings.html || exit 1
! grep -Fq 'Wildcard use alone does not establish a vulnerability' findings.html || exit 1
# Cross-tool TLS 1.3 success suppresses a conflicting disabled observation.
awk -F '\034' -v kind=sslscan -v now_utc=20261021000000 -f "$BIDENT_ROOT/lib/tls_findings.awk" "$TOOL_DIR/sslscan_results.txt" > rows.txt
# A client-side TLS 1.3 testing limitation anywhere in this tool output
# invalidates its negative protocol conclusions, including earlier endpoints.
[[ -z "$(awk -F '\034' '$1 == 5 {print $2}' rows.txt)" ]] || exit 1
# NSE missing protocol headings cannot produce a TLS 1.3-disabled finding.
awk -F '\034' -v kind=nse -v now_utc=20261021000000 -f "$BIDENT_ROOT/lib/tls_findings.awk" "$NSE_DIR/ssl_tls_results.txt" > nse-rows.txt
[[ -z "$(awk -F '\034' '$1 == 5 {print}' nse-rows.txt)" ]] || exit 1
# Common testssl text output must work without debug-only compression markers.
printf 'Command: testssl 192.0.2.90:8443\nBREACH (CVE-2013-3587) potentially NOT ok, "gzip" HTTP compression detected.\n' > breach.txt
[[ "$(awk -v kind=testssl -v now_utc=20261021000000 -f "$BIDENT_ROOT/lib/tls_findings.awk" breach.txt | awk -F '\034' '$1 == 7 {print $2}')" == '192.0.2.90:8443' ]] || exit 1
generate_html_report
grep -Fq '<strong>Weak SSL/TLS Ciphers</strong>' report.html || exit 1
grep -Fq '<strong>Expired SSL Certificate</strong>' report.html || exit 1
printf 'TLS finding checks passed.\n'
)

# TLS false-positive filtering
printf 'Running: TLS false-positive filtering\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/report.sh
test_dir="$(mktemp -d /tmp/bident-tls-false-positives.XXXXXX)"
cd "$test_dir"
mkdir -p "$TOOL_DIR" "$NSE_DIR"
parse() { awk -v kind="$1" -v now_utc=20261021000000 -f "$BIDENT_ROOT/lib/tls_findings.awk" "$2"; }
cat > "$TOOL_DIR/sslscan_results.txt" <<'EOF'
Command: sslscan 192.0.2.40:443
Testing SSL server 192.0.2.40 on port 443 using SNI name 192.0.2.40
TLSv1.2 enabled
TLSv1.3 disabled
TLSv1.3 handshake timed out
Command: sslscan 192.0.2.41:443
Testing SSL server 192.0.2.41 on port 443 using SNI name 192.0.2.41
TLSv1.2 enabled
TLSv1.3 disabled
Command: sslscan 192.0.2.42:443
Testing SSL server 192.0.2.42 on port 443 using SNI name 192.0.2.42
TLSv1.2 enabled
TLSv1.3 disabled
Accepted TLSv1.3 128 bits TLS_AES_128_GCM_SHA256
EOF
append_tls_findings_summary findings.html
python3 - <<'PYTEST'
from pathlib import Path
import re
p=Path('findings.html')
p.write_text(re.sub(r'<details class="artifact"><summary>Full Evidence.*?</pre></details>', '', p.read_text(), flags=re.S))
PYTEST
grep -Fq 'TLSv1.3 Disabled</strong><span>1 affected host(s)' findings.html || exit 1
grep -Fq '192.0.2.41:443' findings.html || exit 1
! grep -Fq '192.0.2.40:443' findings.html || exit 1
! grep -Fq '192.0.2.42:443' findings.html || exit 1
cp "$TOOL_DIR/sslscan_results.txt" local-unsupported.txt
printf 'WARNING: Local OpenSSL build lacks TLSv1.3 support\n' >> local-unsupported.txt
[[ -z "$(parse sslscan local-unsupported.txt | awk -F '\034' '$1 == 5')" ]] || exit 1
# Positive TLS 1.3 handshakes still suppress conflicting negatives when a
# different, later operation fails in the same invocation.
printf 'Command: testssl 192.0.2.41:443\nTLS 1.3 offered\nFatal error: connection refused during another check\n' > "$TOOL_DIR/testssl_results.txt"
: > conflict.html
append_tls_findings_summary conflict.html
! grep -Fq 'TLSv1.3 Disabled' conflict.html || exit 1

cat > cert-text.txt <<'EOF'
Command: testssl 192.0.2.50:443
Certificate Validity (UTC) cannot determine whether certificate expired
Certificate Validity (UTC) not expired
Certificate Validity (UTC) expires in 3 days
Command: testssl 192.0.2.51:443
Certificate Validity (UTC) expired (2020-01-01)
Command: testssl 192.0.2.52:443
Certificate Validity (UTC) expired
Not valid after: Jan 1 00:00:00 2099 GMT
EOF
[[ "$(parse testssl cert-text.txt | awk -F '\034' '$1 == 10 {print $2}')" == '192.0.2.51:443' ]] || exit 1

for value in \
  'Feb 29 00:00:00 2023 GMT' \
  'Feb 30 00:00:00 2024 GMT' \
  'Apr 31 00:00:00 2020 GMT' \
  'Jan aa 00:00:00 2020 GMT' \
  'Jan 01 xx:00:00 2020 GMT' \
  'Jan 01 24:00:00 2020 GMT' \
  'Jan 01 00:60:00 2020 GMT' \
  'Jan 01 00:00:60 2020 GMT' \
  'Jan 01 00:00:00 2020 PST' \
  '2020-02-30T00:00:00Z' \
  '2020-01-01T00:00:00Ztrailing' \
  '2020-01-01T00:00:00+08:00' \
  '2099-01-01T00:00:00Z' \
  '2026-10-21T00:00:00Z'; do
  printf 'Command: sslscan 192.0.2.60:443\nSSL Certificate:\nNot valid after: %s\n' "$value" > date.txt
  [[ -z "$(parse sslscan date.txt | awk -F '\034' '$1 == 10')" ]] || { printf 'False expiry: %s\n' "$value" >&2; exit 1; }
done
for value in 'Feb 29 00:00:00 2024 GMT' '2024-02-29T00:00:00Z'; do
  printf 'Command: sslscan 192.0.2.61:443\nSSL Certificate:\nNot valid after: %s\n' "$value" > date.txt
  [[ "$(parse sslscan date.txt | awk -F '\034' '$1 == 10 {print $2}')" == '192.0.2.61:443' ]] || exit 1
done
cat > non-leaf.txt <<'EOF'
Command: sslscan 192.0.2.70:443
Not valid after: Jan 1 00:00:00 2020 GMT
Signature Algorithm: sha1WithRSAEncryption
SSL Certificate:
Subject: /O=*.organization.test/CN=ordinary.example.test
Not valid after: Jan 1 00:00:00 2099 GMT
Signature Algorithm: sha256WithRSAEncryption
SHA1 Fingerprint: abcdef
SSL Certificate chain:
Subject: /CN=*.issuer.test
Signature Algorithm: sha1WithRSAEncryption
Not valid after: Jan 1 00:00:00 2020 GMT
EOF
[[ -z "$(parse sslscan non-leaf.txt)" ]] || exit 1
cat > definitions.txt <<'EOF'
Command: testssl 192.0.2.80:443
TLS 1.2 offered
TLS 1.3 not offered (NOT ok)
Common Name (CN) *
Certificate Validity (UTC) expired (2026-10-20)
Command: testssl 192.0.2.81:443
Subject Alternative Name (SAN) unusual*name.example.test
Certificate Validity (UTC) expired (2026-10-21)
Command: testssl 192.0.2.82:443
Certificate Validity (UTC) expired
Command: sslscan 192.0.2.83:443
SSL Certificate:
Not valid after: Oct 21 00:00:00 2026 GMT
EOF
awk -v kind=testssl -v now_utc=20261021120000 -f "$BIDENT_ROOT/lib/tls_findings.awk" definitions.txt > definitions-rows.txt
[[ "$(awk -F '\034' '$1 == 5 {print $2}' definitions-rows.txt)" == '192.0.2.80:443' ]] || exit 1
[[ "$(awk -F '\034' '$1 == 8 {print $2}' definitions-rows.txt)" == $'192.0.2.80:443\n192.0.2.81:443' ]] || exit 1
[[ "$(awk -F '\034' '$1 == 10 {print $2}' definitions-rows.txt)" == '192.0.2.80:443' ]] || exit 1
printf 'TLS false-positive checks passed.\n'
)

# Individual cipher names
printf 'Running: Individual cipher names\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/report.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-cipher-names.XXXXXX")"
cd "$fixture_dir"
mkdir -p "$TOOL_DIR" "$NSE_DIR"
cat > "$TOOL_DIR/testssl_results.txt" <<'DATA'
Command: testssl --wide --mapping iana 192.0.2.10:443
 Obsoleted CBC ciphers (AES, ARIA etc.) offered
 Testing 370 ciphers via OpenSSL plus sockets against the server, ordered by encryption strength
 xc028 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 ECDH 256 AES 256 ECDHE-RSA-AES256-SHA384
 xc028 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 ECDH 256 AES 256 ECDHE-RSA-AES256-SHA384
 xc02f TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ECDH 256 AESGCM 128
 xc027 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 rejected
 Running client simulations
 xc027 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 ECDH 256 AES 128
Command: testssl 192.0.2.11:8443
 Obsoleted CBC ciphers (AES, ARIA etc.) offered
DATA
cat > "$TOOL_DIR/sslscan_results.txt" <<'DATA'
Command: sslscan 192.0.2.10:443
Accepted TLSv1.2 256 bits ECDHE-RSA-AES256-SHA384
Accepted TLSv1.2 128 bits AES128-SHA256
Accepted TLSv1.2 128 bits ECDHE-RSA-AES128-GCM-SHA256
Rejected TLSv1.2 128 bits AES128-SHA
DATA
awk -v kind=testssl -v now_utc=20261022000000 -f "$BIDENT_ROOT/lib/tls_findings.awk" "$TOOL_DIR/testssl_results.txt" > parsed
[[ "$(awk -F '\034' '$1==6 && $5 !~ /^Category only:/ {print $5}' parsed)" == TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 ]] || exit 1
append_tls_findings_summary report.html
python3 - <<'PYTEST'
from pathlib import Path
import re
s=Path('report.html').read_text()
table=re.search(r'<div data-affected-targets>.*?</tbody></table>',s,re.S).group()
assert '<li>TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384</li>' in table
assert '<li>ECDHE-RSA-AES256-SHA384</li>' in table
assert '<li>AES128-SHA256</li>' in table
assert 'Category only:' not in table
assert 'GCM' not in table
assert '<li>AES128-SHA</li>' not in table
assert 'rescan required' in table
assert 'Full Evidence' in s
PYTEST
printf 'TLS individual cipher checks passed.\n'
)

# Per-host TLS timeouts
printf 'Running: Per-host TLS timeouts\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/ui.sh
source lib/utils.sh
source lib/checks.sh
source lib/report.sh
source lib/workflow.sh
[[ "$TLS_TIMEOUT" == 1800 ]] || { printf "Assertion failed at line %s\n" "$LINENO" >&2; exit 1; }
if (main -t 192.0.2.1 --tls-timeout 600) >/dev/null 2>&1; then exit 1; fi
test_dir="$(mktemp -d /tmp/bident-tls-timeout.XXXXXX)"
cd "$test_dir"
mkdir -p bin "$TOOL_DIR" "$LOG_DIR"
export TLS_TEST_CALLS="$test_dir/calls.txt"
cat > bin/timeout <<'EOF'
#!/bin/bash
printf 'timeout %s\n' "$*" >> "$TLS_TEST_CALLS"
shift 2
"$@"
tool_status=$?
if [[ "${TLS_TEST_TIMEOUT_STATUS:-0}" -ne 0 ]]; then exit "$TLS_TEST_TIMEOUT_STATUS"; fi
exit "$tool_status"
EOF
cat > bin/testssl <<'EOF'
#!/bin/bash
printf 'tool %s\n' "$*" >> "$TLS_TEST_CALLS"
printf 'TLS 1.2 offered\nTLS 1.3 not offered\n'
exit "${TLS_TEST_TOOL_STATUS:-0}"
EOF
cp bin/testssl bin/sslscan
chmod +x bin/timeout bin/testssl bin/sslscan
export PATH="$test_dir/bin:$PATH"
TLS_TIMEOUT=5
export TLS_TEST_TIMEOUT_STATUS=124
run_tls_target "$TOOL_DIR/testssl_results.txt" testssl 192.0.2.1:443 > notice.txt
grep -Fq 'per-target timeout (5s)' notice.txt || exit 1
grep -Fq 'timeout --kill-after=10s 5s testssl --wide --mapping iana 192.0.2.1:443' "$TLS_TEST_CALLS" || exit 1
grep -Fq 'Bident TLS result: Incomplete:' "$TOOL_DIR/testssl_results.txt" || exit 1
[[ -z "$(awk -v kind=testssl -v now_utc=20261021000000 -f "$BIDENT_ROOT/lib/tls_findings.awk" "$TOOL_DIR/testssl_results.txt")" ]] || { printf "Assertion failed at line %s\n" "$LINENO" >&2; exit 1; }
export TLS_TEST_TIMEOUT_STATUS=0
run_tls_target "$TOOL_DIR/testssl_results.txt" testssl 192.0.2.2:443
grep -Fq 'Finished; review output' "$LOG_DIR/tls_status.tsv" || exit 1
[[ "$(awk -v kind=testssl -v now_utc=20261021000000 -f "$BIDENT_ROOT/lib/tls_findings.awk" "$TOOL_DIR/testssl_results.txt" | awk -F '\034' '$1 == 5 {print $2}')" == '192.0.2.2:443' ]] || { printf "Assertion failed at line %s\n" "$LINENO" >&2; exit 1; }
export TLS_TEST_TIMEOUT_STATUS=137
run_tls_target "$TOOL_DIR/sslscan_results.txt" sslscan 192.0.2.3:443 > /dev/null
grep -Fq 'timeout or forced termination' "$LOG_DIR/tls_status.tsv" || exit 1
export TLS_TEST_TIMEOUT_STATUS=0
export TLS_TEST_TOOL_STATUS=1
run_tls_target "$TOOL_DIR/sslscan_results.txt" sslscan 192.0.2.6:443 > /dev/null
grep -Fq 'tool exited with status 1' "$LOG_DIR/tls_status.tsv" || exit 1
command_available() { return 1; }
run_tls_target "$TOOL_DIR/testssl_results.txt" testssl 192.0.2.4:443 > /dev/null
grep -Fq 'Incomplete: timeout command unavailable' "$LOG_DIR/tls_status.tsv" || exit 1
append_tls_status_artifacts status.html
grep -Fq 'TLS External Check Status' status.html || exit 1
grep -Fq '192.0.2.1:443' status.html || exit 1
grep -Fq 'execution log' status.html || exit 1
printf 'TLS per-target timeout checks passed.\n'
)
