#!/usr/bin/env bash
set -euo pipefail

# Each case runs in a subshell to isolate working directories, mocks and state.

# External-tool failure handling
printf 'Running: External-tool failure handling\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/ports.sh
source lib/checks.sh
source lib/report.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-external-errors.XXXXXX")"
cd "$fixture_dir"
mkdir -p "$TOOL_DIR" "$LOG_DIR" bin
cat > bin/mock-tool <<'MOCK'
#!/bin/bash
printf '%b\n' "$MOCK_OUTPUT"
exit "$MOCK_EXIT"
MOCK
cp bin/mock-tool bin/ssh-audit
chmod +x bin/*
export MOCK_OUTPUT MOCK_EXIT
export PATH="$fixture_dir/bin:$PATH"
run_with_timeout() { "$@"; }
MOCK_OUTPUT="Traceback (most recent call last):\nAttributeError: module 'lib' has no attribute 'GEN_EMAIL'"
MOCK_EXIT=1
run_logged_check 'Exposed RPC Services' "$TOOL_DIR/s_rpcdump_135.txt" mock-tool -p 135 192.0.2.1 > terminal.txt
! grep -q 'No Exposed RPC Services Found' terminal.txt || exit 1
grep -q 'Incomplete:' terminal.txt || exit 1
[[ ! -s "$TOOL_DIR/s_rpcdump_135.txt" ]] || exit 1
[[ "$(wc -l < "$LOG_DIR/external_status.tsv" | tr -d ' ')" == 1 ]] || exit 1
# A zero exit status with a traceback remains incomplete.
MOCK_EXIT=0
! run_external_capture 'NetExec' captured mock-tool >> terminal.txt || exit 1
# Timeouts remain distinct from a completed negative check.
MOCK_OUTPUT='partial output'; MOCK_EXIT=124
! run_external_capture 'IKE' captured mock-tool >> terminal.txt || exit 1
grep -q 'timeout or forced termination' terminal.txt || exit 1
# ssh-audit uses 2 and 3 for successful scans with algorithm warnings/failures.
MOCK_OUTPUT='(enc) aes128-cbc -- [fail] deprecated CBC'
for MOCK_EXIT in 2 3; do run_external_capture 'SSH' captured ssh-audit >> terminal.txt || exit 1; done
MOCK_OUTPUT='connection refused'; MOCK_EXIT=1
! run_external_capture 'SSH' captured ssh-audit >> terminal.txt || exit 1
# Completed negatives stay silent.
MOCK_OUTPUT='No endpoints returned'; MOCK_EXIT=0
run_logged_check 'Exposed RPC Services' "$TOOL_DIR/s_rpcdump_135.txt" mock-tool > negative.txt
[[ ! -s negative.txt ]] || exit 1
# Successful findings are still retained with their command and evidence.
MOCK_OUTPUT='Protocol: test\nProvider: example'
run_logged_check 'Exposed RPC Services' "$TOOL_DIR/s_rpcdump_135.txt" mock-tool > positive.txt
grep -q 'Protocol: test' "$TOOL_DIR/s_rpcdump_135.txt" || exit 1
append_external_failed_artifacts artifacts.html
grep -q 'External Tool Failed / Incomplete Checks' artifacts.html || exit 1
grep -q GEN_EMAIL artifacts.html || exit 1
! grep -q 'deprecated CBC' artifacts.html || exit 1
# The report places execution errors under Core Artifacts.
generate_html_report
python3 - <<'PYTEST'
from pathlib import Path
s=Path('report.html').read_text()
assert s.index('External Tool Failed / Incomplete Checks') > s.index('<summary>Core Artifacts</summary>')
assert 'GEN_EMAIL' in s
PYTEST
# Exercise dedicated stage runners: none may overwrite a failure with "No ...".
for name in netexec dig ike-scan; do cp bin/mock-tool "bin/$name"; done
has_open_port() { return 0; }
open_target_ports() { printf '192.0.2.1 445\n'; }
MOCK_EXIT=1; MOCK_OUTPUT='Traceback (most recent call last):\nImportError: broken dependency'
printf 'old finding\n' > "$TOOL_DIR/nxc_smb_signing_false.txt"
run_smb_external_checks > smb-terminal.txt
! grep -q 'No .* Found' smb-terminal.txt || exit 1
[[ ! -s "$TOOL_DIR/nxc_smb_signing_false.txt" ]] || exit 1
open_target_ports() { printf '192.0.2.1 53\n'; }
run_dns_dig_checks > dns-terminal.txt
! grep -q 'No .* Found' dns-terminal.txt || exit 1
open_target_ports() { printf '192.0.2.1 500\n'; }
run_ike_weak_encryption_check > ike-terminal.txt
! grep -q 'No .* Found' ike-terminal.txt || exit 1
printf '192.0.2.1\n' > ssh-targets.txt
open_targets_file_for_ports() { printf 'ssh-targets.txt'; }
resolve_command() { printf '%s/bin/ssh-audit' "$fixture_dir"; }
print_progress_bar() { :; }
run_ssh_audit_check > ssh-terminal.txt
! grep -q 'No Weak SSH Ciphers Found' ssh-terminal.txt || exit 1
grep -q 'Incomplete' ssh-terminal.txt || exit 1
# Simulate sudo ownership handoff without requiring root in the test suite.
BIDENT_DROP_PRIVILEGES=true
BIDENT_RUN_USER=scan-owner
chown() { printf '%s\n' "$*" >> ownership.calls; }
MOCK_EXIT=1; MOCK_OUTPUT='Traceback (most recent call last):\nAttributeError: broken dependency'
! run_external_capture 'Ownership regression' captured mock-tool > ownership-terminal || exit 1
grep -q '^scan-owner logs/external_Ownership_regression' ownership.calls || exit 1
python3 - <<'PYTEST'
from pathlib import Path
import stat
files=list(Path('logs').glob('external_Ownership_regression.*'))
assert len(files)==1
assert stat.S_IMODE(files[0].stat().st_mode)==0o600
PYTEST
printf 'External failure handling checks passed.\n'
)

# NSE timeouts
printf 'Running: NSE timeouts\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/ui.sh
source lib/utils.sh
source lib/checks.sh
source lib/report.sh
source lib/workflow.sh
[[ "$SCRIPT_TIMEOUT" == 30m ]]

# Stop after argument validation; do not run any network commands.
require_root_scan_run() { printf 'validated:%s\n' "$SCRIPT_TIMEOUT"; exit 0; }
for value in 30m 15m 1h 900 0 1.5s 500ms; do
  output="$(main -t 192.0.2.1 --script-timeout "$value")"
  [[ "$output" == "validated:$value" ]]
done
for value in invalid -1 1d '15m;echo unsafe' ''; do
  if (main -t 192.0.2.1 --script-timeout "$value") >/dev/null 2>&1; then
    printf 'Unexpectedly accepted timeout: %s\n' "$value" >&2
    exit 1
  fi
done
if (main -t 192.0.2.1 --script-timeout) >/dev/null 2>&1; then exit 1; fi

# All version/script commands must carry the timeout, after the timing template.
while IFS= read -r command; do
  [[ "$command" == *--script-timeout* ]]
done < <(grep -E 'nmap .*-(sV|sUV|sU .*sV)' lib/workflow.sh)

test_dir="$(mktemp -d /tmp/bident-script-timeout.XXXXXX)"
cd "$test_dir"
has_open_port() { return 0; }
timed_out() { printf 'NSE: ssh-brute M:123 timed out\n'; }
failed() { printf 'command failure\n'; return 2; }
finished() { printf 'username: discovered-user\n'; }
run_if_open 'SSH NSE' tcp 22 timed_out
run_if_open 'FTP NSE' tcp 21 failed
run_if_open 'MySQL NSE' tcp 3306 finished
grep -Fq 'Incomplete: script timeout' "$LOG_DIR/nse_status.tsv"
grep -Fq 'Incomplete: command failed (exit 2)' "$LOG_DIR/nse_status.tsv"
grep -Fq 'Finished; review output' "$LOG_DIR/nse_status.tsv"
grep -Fq 'username: discovered-user' "$LOG_DIR/nse_MySQL_NSE.log"
append_nse_status_section report.html
! grep -Fq 'execution log' report.html
! grep -Fq 'not evidence that credentials or vulnerabilities are absent' report.html
append_nse_status_artifacts report.html
grep -Fq 'Incomplete: script timeout' report.html
grep -Fq 'logs/nse_SSH_NSE.log' report.html
printf 'Script timeout checks passed.\n'
)

# TLS fallback selection
printf 'Running: TLS fallback selection\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/checks.sh
source lib/report.sh
awk '
  /run_if_open.*NSE/ {last_nse = NR}
  /^[[:space:]]*run_ssl_checks$/ {tls = NR; count++}
  /^[[:space:]]*run_msf_auxiliary_checks$/ {msf = NR}
  END {if (count != 1 || tls <= last_nse || tls >= msf) exit 1}
' lib/workflow.sh || exit 1
test_dir="$(mktemp -d /tmp/bident-ssl-fallback.XXXXXX)"
cd "$test_dir"
mkdir -p "$TOOL_DIR"
command_available() {
  case "$1" in
    testssl) [[ "$testssl_available" == true ]] ;;
    sslscan) [[ "$sslscan_available" == true ]] ;;
    *) return 1 ;;
  esac
}
open_target_ports() { printf '192.0.2.1 443\n'; }
open_targets_file_for_ports() { printf 'tls-targets.txt'; }
print_progress_bar() { :; }
run_tls_target() { shift; printf '%s\n' "$*" >> calls.txt; return 0; }
run_if_open() { shift 3; "$@"; }
nmap() { printf 'nmap %s\n' "$*" >> calls.txt; }
check_case() {
  testssl_available="$1"; sslscan_available="$2"; expected="$3"
  : > calls.txt
  run_ssl_checks > /dev/null
  actual="$(cat calls.txt)"
  [[ "$actual" == "$expected" ]] || { printf 'Unexpected TLS routing: %s\n' "$actual" >&2; exit 1; }
}
check_case true true $'testssl 192.0.2.1:443\nsslscan 192.0.2.1:443'
check_case true false 'testssl 192.0.2.1:443'
check_case false true 'sslscan 192.0.2.1:443'
testssl_available=false; sslscan_available=false
: > calls.txt
run_ssl_checks > /dev/null
grep -Fq -- '--script ssl-* and not dos' calls.txt || exit 1
grep -Fq -- '--script-timeout 30m' calls.txt || exit 1
[[ "$(wc -l < calls.txt | tr -d ' ')" == 1 ]] || exit 1
external_status=1
check_case true true $'testssl 192.0.2.1:443\nsslscan 192.0.2.1:443'
printf 'TLS fallback checks passed.\n'
)

# Startup dependency checks
printf 'Running: Startup dependency checks\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/ui.sh
source lib/utils.sh
source lib/deps.sh
source lib/ports.sh
source lib/checks.sh
source lib/report.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-startup-checks.XXXXXX")"
cd "$fixture_dir"
mkdir -p bin "$LOG_DIR" "$TOOL_DIR"
export STARTUP_CALLS="$fixture_dir/calls"
cat > bin/netexec <<'MOCK'
#!/bin/bash
printf 'netexec %s\n' "$*" >> "$STARTUP_CALLS"
[[ "$*" == 'smb -L' ]] || exit 99
if [[ "${STARTUP_BROKEN:-false}" == true ]]; then
  printf "Traceback (most recent call last):\nAttributeError: 'typing.Union' object has no attribute '__module__'\n"
  exit 1
fi
printf 'Available SMB modules\n'
MOCK
cat > bin/impacket-rpcdump <<'MOCK'
#!/bin/bash
printf 'rpcdump %s\n' "$*" >> "$STARTUP_CALLS"
[[ "$*" == '-h' ]] || exit 99
if [[ "${STARTUP_BROKEN:-false}" == true ]]; then
  printf "Traceback (most recent call last):\nAttributeError: module 'lib' has no attribute 'GEN_EMAIL'\n"
  exit 1
fi
printf 'usage: rpcdump\n'
MOCK
chmod +x bin/*
export PATH="$fixture_dir/bin:$PATH"
run_with_timeout() { [[ "$TOOL_TIMEOUT" == 20 ]] || return 98; "$@"; }
export STARTUP_BROKEN=false
check_external_tool_startup > ok-terminal
[[ "$NETEXEC_STARTUP_OK" == true && "$RPCDUMP_STARTUP_OK" == true ]] || exit 1
[[ ! -s ok-terminal ]] || exit 1
[[ ! -s "$LOG_DIR/external_status.tsv" ]] || exit 1
export STARTUP_BROKEN=true
check_external_tool_startup > failed-terminal
[[ "$NETEXEC_STARTUP_OK" == false && "$RPCDUMP_STARTUP_OK" == false ]] || exit 1
grep -q INCOMPLETE failed-terminal || exit 1
[[ "$(wc -l < "$LOG_DIR/external_status.tsv" | tr -d ' ')" == 2 ]] || exit 1
append_external_failed_artifacts failed.html
grep -q GEN_EMAIL failed.html || exit 1
grep -q typing.Union failed.html || exit 1
# Broken optional tools must not be invoked again during the service checks.
has_open_port() { return 0; }
open_target_ports() { printf '192.0.2.1 135\n'; }
command_available() { [[ "$1" != rpcclient ]]; }
run_smb_external_checks > skipped-terminal
run_rpc_135_checks >> skipped-terminal
[[ "$(wc -l < "$STARTUP_CALLS" | tr -d ' ')" == 4 ]] || exit 1
# Guard startup ordering: initialization preserves preflight logs, and no
# responder/discovery starts before dependency probing.
python3 - "$BIDENT_ROOT/lib/workflow.sh" <<'PYTEST'
from pathlib import Path
import sys
s=Path(sys.argv[1]).read_text()
p=s.index('  check_external_tool_startup')
assert s.index(': > "${LOG_DIR}/external_status.tsv"') < p
assert p < s.index('  print_section \'Scope & Host Discovery\'')
assert p < s.index('    start_responder')
PYTEST
printf 'Startup dependency checks passed.\n'
)

# NetExec input/output separation and sudo-created file permissions.
printf 'Running: NetExec relay output permissions\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/checks.sh
source lib/report.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-smb-permissions.XXXXXX")"
cd "$fixture_dir"
mkdir -p bin "$TOOL_DIR" "$LOG_DIR"
export SMB_CALLS="$fixture_dir/calls"
cat > bin/netexec <<'MOCK'
#!/bin/bash
printf '%s\n' "$*" >> "$SMB_CALLS"
if [[ "${SMB_SIMULATE_PERMISSION_ERROR:-false}" == true ]]; then
 printf 'SMB 192.0.2.10 445 HOST [*] (signing:False) (SMBv1:True)\n'
 printf "PermissionError: [Errno 13] Permission denied: 'relay-file'\n" >&2
 exit 0
fi
[[ "$1" == smb ]] || exit 90
if [[ "${2:-}" == --gen-relay-list ]]; then
 relay="$3"; targets="$4"
 [[ "$relay" != "$targets" && -r "$targets" && -w "$relay" ]] || exit 91
 [[ "$(cat "$targets")" == 192.0.2.10 && ! -s "$relay" ]] || exit 92
 printf '192.0.2.10\n' >> "$relay"
fi
printf 'SMB 192.0.2.10 445 HOST [*] (signing:False) (SMBv1:True)\n'
MOCK
chmod +x bin/netexec
export PATH="$fixture_dir/bin:$PATH"
printf '192.0.2.99\n' > "$LIVE_TARGETS_FILE"
has_open_port() { return 0; }
open_target_ports() { printf '192.0.2.10 445\n'; }
run_with_timeout() { "$@"; }
BIDENT_DROP_PRIVILEGES=true
BIDENT_RUN_USER=scan-owner
chown() { printf '%s\n' "$*" >> ownership.calls; }
umask 077
run_smb_external_checks > terminal.txt
[[ "$(cat "$TOOL_DIR/targets_smb.txt")" == 192.0.2.10 ]] || exit 1
[[ "$(cat "$TOOL_DIR/targets_smb_relay.txt")" == 192.0.2.10 ]] || exit 1
grep -Fq 'scan-owner tool_results/targets_smb_relay.txt' ownership.calls || exit 1
grep -Fq 'scan-owner tool_results/targets_smb.txt' ownership.calls || exit 1
! grep -q targets_live.txt "$SMB_CALLS" || exit 1
grep -q 'Found' terminal.txt || exit 1
[[ ! -s "$LOG_DIR/external_status.tsv" ]] || exit 1
export SMB_SIMULATE_PERMISSION_ERROR=true
run_smb_external_checks > failed-terminal.txt
grep -q Incomplete failed-terminal.txt || exit 1
[[ ! -s "$TOOL_DIR/nxc_smb_signing_false.txt" && ! -s "$TOOL_DIR/nxc_smbv1_true.txt" ]] || exit 1
append_external_failed_artifacts failed-artifacts.html
grep -q PermissionError failed-artifacts.html || exit 1
python3 - <<'PYTEST'
from pathlib import Path
import stat
for name in ['targets_smb.txt','targets_smb_relay.txt']:
 assert stat.S_IMODE(Path('tool_results',name).stat().st_mode)==0o600
PYTEST
printf 'NetExec relay permission checks passed.\n'
)

# Permission failures must be recognized consistently across external tools.
printf 'Running: Cross-tool permission error handling\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/checks.sh
source lib/report.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-tool-access.XXXXXX")"
cd "$fixture_dir"
mkdir -p bin "$LOG_DIR" "$TOOL_DIR"
cat > bin/mock-tool <<'MOCK'
#!/bin/bash
printf '%s\n' "${MOCK_ACCESS_OUTPUT}"
exit 0
MOCK
cat > bin/timeout <<'MOCK'
#!/bin/bash
shift 2
"$@"
MOCK
chmod +x bin/*
export PATH="$fixture_dir/bin:$PATH"
run_with_timeout() { "$@"; }
run_unprivileged() { "$@"; }
export MOCK_ACCESS_OUTPUT
for message in 'PermissionError: [Errno 13] Permission denied' 'Operation not permitted' 'Read-only file system'; do
 MOCK_ACCESS_OUTPUT="$message"
 for tool in impacket-rpcdump rpcclient ldapsearch ssh-audit dig ike-scan; do
  ! run_external_capture "$tool" captured mock-tool >> terminal.txt || exit 1
 done
done
cp bin/mock-tool bin/testssl
cp bin/mock-tool bin/sslscan
MOCK_ACCESS_OUTPUT='PermissionError: cannot write cache'
for tool in testssl sslscan; do
 run_tls_target "$TOOL_DIR/${tool}_results.txt" "$tool" 192.0.2.1:443 >> terminal.txt
 grep -q 'Bident TLS result: Incomplete' "$TOOL_DIR/${tool}_results.txt" || exit 1
done
# Prior hosts' permission errors must not poison the next TLS result.
MOCK_ACCESS_OUTPUT='TLSv1.2 enabled'
run_tls_target "$TOOL_DIR/sslscan_results.txt" sslscan 192.0.2.2:443 >> terminal.txt
[[ "$(tail -1 "$LOG_DIR/tls_status.tsv" | cut -f3)" == 'Finished; review output' ]] || exit 1
printf '[-] Permission denied @ rb_sysopen - module-output.txt\n' > msf.txt
[[ -n "$(msf_failure_lines msf.txt)" ]] || exit 1
append_external_failed_artifacts report.html
grep -q 'Read-only file system' report.html || exit 1
printf 'Cross-tool permission checks passed.\n'
)

# Explicit anonymous RPC access denial is a silent negative, not an error.
printf 'Running: Anonymous RPC denied response\n'
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/checks.sh
source lib/report.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-rpc-denied.XXXXXX")"
cd "$fixture_dir"
mkdir -p bin "$TOOL_DIR" "$LOG_DIR"
cat > bin/rpcclient <<'MOCK'
#!/bin/bash
printf '%b\n' "$RPC_OUTPUT"
exit "$RPC_EXIT"
MOCK
chmod +x bin/rpcclient
export PATH="$fixture_dir/bin:$PATH"
export RPC_OUTPUT='Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED' RPC_EXIT=1
run_with_timeout() { "$@"; }
run_logged_check 'Unauthenticated Remote Procedure Call' "$TOOL_DIR/rpc.txt" rpcclient -U '' -N -c enumprivs 192.0.2.1 > terminal.txt
[[ ! -s terminal.txt && ! -s "$LOG_DIR/external_status.tsv" && ! -s "$TOOL_DIR/rpc.txt" ]] || exit 1
RPC_OUTPUT='SeBackupPrivilege'; RPC_EXIT=0
run_logged_check 'Unauthenticated Remote Procedure Call' "$TOOL_DIR/rpc.txt" rpcclient -U '' -N -c enumprivs 192.0.2.2 > found.txt
grep -Fq 'Unauthenticated Remote Procedure Call: Found and verified.' found.txt || exit 1
RPC_OUTPUT='Connection refused'; RPC_EXIT=1
run_logged_check 'Unauthenticated Remote Procedure Call' "$TOOL_DIR/rpc.txt" rpcclient -U '' -N -c enumprivs 192.0.2.3 > failed.txt
grep -q Incomplete failed.txt || exit 1
RPC_OUTPUT='Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED\nTraceback (most recent call last):\nImportError: broken'
run_logged_check 'Unauthenticated Remote Procedure Call' "$TOOL_DIR/rpc.txt" rpcclient -U '' -N -c enumprivs 192.0.2.4 > mixed.txt
grep -q Incomplete mixed.txt || exit 1
RPC_OUTPUT='Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED'; RPC_EXIT=124
run_logged_check 'Unauthenticated Remote Procedure Call' "$TOOL_DIR/rpc.txt" rpcclient -U '' -N -c enumprivs 192.0.2.5 > timeout.txt
grep -q Incomplete timeout.txt || exit 1
printf 'Anonymous RPC denial checks passed.\n'
)

# External notifications require report-verifiable results, without host lists.
(
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source lib/config.sh
source lib/utils.sh
source lib/checks.sh
source lib/report.sh
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/bident-external-notify.XXXXXX")"
trap 'rm -rf "$fixture_dir"' EXIT
cd "$fixture_dir"
printf 'dn:\nnamingContexts: DC=example,DC=test\n' > output.txt
output="$(external_notify_command 'LDAP Anonymous Bind' output.txt ldapsearch -x -H ldap://192.0.2.10:389)"
[[ "$output" == *'[+] LDAP Anonymous Bind: Found and verified.'* ]] || exit 1
[[ "$output" != *'192.0.2.10'* ]] || exit 1
# Authenticated LDAP or malformed hosts must not be called verified.
[[ -z "$(external_notify_command 'LDAP Anonymous Bind' output.txt ldapsearch -D admin -H ldap://192.0.2.10:389)" ]] || exit 1
[[ -z "$(external_notify_command 'LDAP Anonymous Bind' output.txt ldapsearch -x -H ldap://999.0.2.10:389)" ]] || exit 1
printf 'Cannot connect to server. Error was NT_STATUS_ACCESS_DENIED\n' > output.txt
[[ -z "$(external_notify_command 'Unauthenticated Remote Procedure Call' output.txt rpcclient -U '' -N -c enumprivs 192.0.2.10)" ]] || exit 1
printf 'SeBackupPrivilege 0:17\n' > output.txt
output="$(external_notify_command 'Unauthenticated Remote Procedure Call' output.txt rpcclient -U '' -N -c enumprivs 192.0.2.10)"
[[ "$output" == *'Found and verified.'* && "$output" != *'192.0.2.10'* ]] || exit 1
mkdir -p "$TOOL_DIR" "$NSE_DIR"
cat > "$TOOL_DIR/testssl_results.txt" <<'DATA'
Command: testssl 192.0.2.10:443
 SSLv2 not offered (OK)
 TLS 1 not offered
 TLS 1.2 offered (OK)
 TLS 1.3 not offered
Bident TLS result: Finished; review output
DATA
# Verify the notification path runs the same classifier as report generation.
append_tls_findings_summary expected.html
expected_count="$(grep -c '<strong>' expected.html || true)"
output="$(external_notify_tls_findings)"
[[ "$expected_count" -gt 0 ]] || exit 1
actual_count="$(printf '%s\n' "$output" | grep -c 'Found and verified' || true)"
[[ "$actual_count" == "$expected_count" ]] || exit 1
[[ "$output" != *'192.0.2.10'* ]] || exit 1
printf 'External tool notification checks passed.\n'
)
