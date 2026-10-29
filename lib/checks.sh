run_nse_check() {
  local label="$1"
  shift
  local slug log_file status rc=0
  local pipeline_status=()
  slug="$(printf '%s' "$label" | tr -c '[:alnum:]_-' '_')"
  mkdir -p "$LOG_DIR"
  log_file="${LOG_DIR}/nse_${slug}.log"
  if "$@" 2>&1 | tee "$log_file"; then
    rc=0
  else
    pipeline_status=("${PIPESTATUS[@]}")
    rc="${pipeline_status[0]}"
    if [[ "$rc" -eq 0 ]]; then rc="${pipeline_status[1]}"; fi
  fi
  if [[ "$rc" -ne 0 ]]; then
    status="Incomplete: command failed (exit ${rc})"
  elif grep -Eiq 'NSE:.*(timed out|timeout)|Script.*timed out' "$log_file"; then
    status="Incomplete: script timeout"
  else
    status="Finished; review output"
  fi
  printf '%s\t%s\t%s\n' "$label" "$status" "$log_file" >> "${LOG_DIR}/nse_status.tsv"
  if [[ "$status" == Incomplete:* ]]; then
    printf '%s%s: %s. Continuing remaining checks.%s\n' "$CLR_YELLOW" "$label" "$status" "$CLR_RESET"
  fi
  return 0
}

run_if_open() {
  local label="$1"
  local proto="$2"
  local ports_csv="$3"
  shift 3
  local ports=()
  local check_label="$label"

  check_label="${check_label% NSE}"
  check_label="${check_label% scan}"

  IFS=',' read -r -a ports <<< "$ports_csv"
  printf '%sChecking %s (%s)%s\n' "$CLR_CYAN" "$check_label" "$ports_csv" "$CLR_RESET"
  if has_open_port "$proto" "${ports[@]}"; then
    printf '%sRunning %s:%s Detected Open %s Port(s): (%s)\n' "$CLR_CYAN" "$label" "$CLR_RESET" "$proto" "$ports_csv"
    run_nse_check "$label" "$@"
  else
    printf '%sNo %s (%s) Found%s\n' "$CLR_YELLOW" "$check_label" "$ports_csv" "$CLR_RESET"
  fi
}

append_command_header() {
  local outfile="$1"
  shift

  {
    printf '\n===== %s =====\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    printf 'Command:'
    printf ' %q' "$@"
    printf '\n\n'
  } >> "$outfile"
}

run_logged() {
  local outfile="$1"
  shift

  append_command_header "$outfile" "$@"
  run_with_timeout "$@" >> "$outfile" 2>&1
}

print_smb_relay_note() {
  printf '%sNote:%s Possible for Server Message Block (SMB) Relay Attack when SMB signing is disabled.\n' "$CLR_YELLOW" "$CLR_RESET"
}

result_output_has_finding() {
  local label="$1"
  local result_file="$2"

  [[ -s "$result_file" ]] || return 1

  case "$label" in
    "Weak SSH Ciphers")
      [[ -n "$(ssh_weak_cipher_rows "$result_file" 'current-target:22')" ]]
      ;;
    "Exposed RPC Services")
      grep -Eiq '(^Protocol:|^Provider:|^[[:space:]]*[0-9a-fA-F-]{36}|ncacn_|MS-RPCE|uuid)' "$result_file" &&
        ! grep -Eiq 'connection refused|NT_STATUS_|failed|error|timed out|No route to host' "$result_file"
      ;;
    "Unauthenticated Remote Procedure Call")
      grep -Eiq 'Se[A-Za-z]+Privilege|found[[:space:]]+[0-9]+[[:space:]]+privileges|privilege' "$result_file" &&
        ! grep -Eiq 'NT_STATUS_ACCESS_DENIED|NT_STATUS_LOGON_FAILURE|Cannot connect|failed|error|timed out' "$result_file"
      ;;
    "LDAP Anonymous Bind")
      grep -Eiq '^(dn:|namingContexts:|defaultNamingContext:|rootDomainNamingContext:|supportedLDAPVersion:|supportedSASLMechanisms:)' "$result_file" &&
        ! grep -Eiq 'Invalid credentials|Can.t contact LDAP server|ldap_bind:|failed|error|timed out' "$result_file"
      ;;
    "Misconfigured Server Message Block Signing")
      grep -Eq 'signing:False' "$result_file"
      ;;
    "DNS Recursion Enabled")
      grep -q 'status: NOERROR' "$result_file" && grep -Eq 'ANSWER: [1-9][0-9]*' "$result_file" &&
        grep -Eq 'flags:.*[[:space:]]rd[;[:space:]].*[[:space:]]ra[;[:space:]]' "$result_file"
      ;;
    "SMBv1 Enabled")
      grep -Eq 'SMBv1:True' "$result_file"
      ;;
    *)
      grep -Ev '^[[:space:]]*$|^===== |^Command:' "$result_file" >/dev/null
      ;;
  esac
}

external_output_has_error() {
  local output="$1" start_line="${2:-1}"
  # Consume the full stream so pipefail does not turn grep matches into
  # false negatives when the producer receives SIGPIPE.
  tail -n "+${start_line}" "$output" | grep -Ei 'Traceback \(most recent call last\)|AttributeError:|ImportError:|ModuleNotFoundError:|SyntaxError:|PermissionError:|permission denied|operation not permitted|read-only file system|exception while calling proto_flow|command not found|connection refused|connection reset|no route to host|timed out|no servers could be reached|network is unreachable|cannot connect|unable to connect|can.t contact LDAP server|^ldap_[a-z_]+:|^fatal([ :]|$)|^error([ :]|$)|status: (SERVFAIL|REFUSED|FORMERR)' > /dev/null
}

rpc_anonymous_access_denied() {
  local output="$1"
  local denial='^[[:space:]]*(Cannot connect to server[.][[:space:]]*Error was[[:space:]]+)?NT_STATUS_ACCESS_DENIED[[:space:]]*$'
  # Recognize only a pure access-denied response. Mixed diagnostics, partial
  # results and dependency failures must still follow incomplete handling.
  grep -Ei "$denial" "$output" > /dev/null &&
    ! grep -Eiv "$denial|^[[:space:]]*$" "$output" > /dev/null
}

run_external_capture() {
  local label="$1" output="$2" rc=0 status slug log_file tool
  shift 2
  tool="${1##*/}"
  run_with_timeout "$@" > "$output" 2>&1 || rc=$?
  if [[ "$label" == 'Unauthenticated Remote Procedure Call' && "$tool" == rpcclient && ( "$rc" -eq 0 || "$rc" -eq 1 ) ]] && rpc_anonymous_access_denied "$output"; then
    return 0
  fi
  status=""
  if [[ "$tool" == ssh-audit && ( "$rc" -eq 2 || "$rc" -eq 3 ) ]]; then :
  elif [[ "$rc" -eq 124 || "$rc" -eq 137 ]]; then status="Incomplete: timeout or forced termination (exit ${rc})"
  elif [[ "$rc" -ne 0 ]]; then status="Incomplete: command failed (exit ${rc})"
  fi
  if external_output_has_error "$output"; then
    status='Incomplete: tool or connection error'
  fi
  if [[ -n "$status" ]]; then
    mkdir -p "$LOG_DIR"
    slug="$(printf '%s' "$label" | tr -c '[:alnum:]_-' '_')"
    log_file="$(mktemp "${LOG_DIR}/external_${slug}.XXXXXX")"
    append_command_header "$log_file" "$@"
    cat "$output" >> "$log_file"
    # mktemp creates mode 0600; retain privacy, but return ownership to the
    # invoking user immediately so even interrupted scans remain readable.
    if [[ "${BIDENT_DROP_PRIVILEGES:-false}" == true && -n "${BIDENT_RUN_USER:-}" ]]; then
      if ! chown "$BIDENT_RUN_USER" "$log_file"; then
        printf '%sWarning: Could not return log ownership: %s%s\n' "$CLR_YELLOW" "$log_file" "$CLR_RESET" >&2
      fi
    fi
    printf '%s\t%s\t%s\t%s\n' "$label" "$status" "$rc" "$log_file" >> "${LOG_DIR}/external_status.tsv"
    printf '%s%s: %s. Details: %s%s\n' "$CLR_YELLOW" "$label" "$status" "$log_file" "$CLR_RESET"
    return 1
  fi
  return 0
}

run_logged_check() {
  local label="$1"
  local outfile="$2"
  local temp_output
  local status=0
  shift 2

  temp_output="$(mktemp "${TMPDIR:-/tmp}/bident_check.XXXXXX")"
  if ! run_external_capture "$label" "$temp_output" "$@"; then
    rm -f "$temp_output"
    return 0
  fi
  if result_output_has_finding "$label" "$temp_output"; then
    append_command_header "$outfile" "$@"
    cat "$temp_output" >> "$outfile"
  elif [[ ! -s "$outfile" ]]; then
    rm -f "$outfile"
  fi
  if result_output_has_finding "$label" "$temp_output"; then
    external_notify_command "$label" "$temp_output" "$@"
  fi
  rm -f "$temp_output"
  return "$status"
}

run_rpc_135_checks() {
  local found=false
  local target
  local port

  printf '%sChecking MSRPC (135)%s\n' "$CLR_CYAN" "$CLR_RESET"
  rm -f ${TOOL_DIR}/s_rpcdump_135.txt ${TOOL_DIR}/s_rpcclient_135.txt

  while read -r target port; do
    [[ -n "${target:-}" ]] || continue
    found=true

    if [[ "${RPCDUMP_STARTUP_OK:-true}" == false ]]; then
      printf '%sSkipping impacket-rpcdump For %s:%s: Incomplete startup check; see Core Artifacts.%s\n' "$CLR_YELLOW" "$target" "$port" "$CLR_RESET"
    elif command_available impacket-rpcdump; then
      printf '%sChecking For Exposed RPC Services:%s %s:%s\n' "$CLR_CYAN" "$CLR_RESET" "$target" "$port"
      run_logged_check "Exposed RPC Services" ${TOOL_DIR}/s_rpcdump_135.txt impacket-rpcdump -p "$port" "$target" || true
    else
      printf '%sSkipping impacket-rpcdump For %s:%s:%s Command Not Found\n' "$CLR_YELLOW" "$target" "$port" "$CLR_RESET"
    fi

    if command_available rpcclient; then
      printf '%sChecking For Unauthenticated Remote Procedure Call:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$target"
      run_logged_check "Unauthenticated Remote Procedure Call" ${TOOL_DIR}/s_rpcclient_135.txt rpcclient -U "" -N -c enumprivs "$target" || true
    else
      printf '%sSkipping rpcclient For %s:%s Command Not Found\n' "$CLR_YELLOW" "$target" "$CLR_RESET"
    fi
  done < <(open_target_ports tcp 135)

  if [[ "$found" == false ]]; then
    return
  fi
}

run_ldapsearch_checks() {
  local found=false
  local target
  local port

  rm -f ${TOOL_DIR}/s_ldapsearch.txt

  while read -r target port; do
    [[ -n "${target:-}" ]] || continue
    found=true

    if command_available ldapsearch; then
      printf '%sChecking For LDAP Anonymous Bind:%s %s:%s\n' "$CLR_CYAN" "$CLR_RESET" "$target" "$port"
      run_logged_check "LDAP Anonymous Bind" ${TOOL_DIR}/s_ldapsearch.txt ldapsearch -x -s base -b "" "(objectClass=*)" "*" -H "ldap://${target}:${port}" || true
    else
      printf '%sSkipping ldapsearch For %s:%s:%s Command Not Found\n' "$CLR_YELLOW" "$target" "$port" "$CLR_RESET"
    fi
  done < <(open_target_ports tcp 389 3268)

  if [[ "$found" == false ]]; then
    return
  fi
}

write_open_targets_file() {
  local proto="$1"
  local port="$2"
  local outfile="$3"

  open_target_ports "$proto" "$port" | awk '{print $1}' > "$outfile"
}

run_smb_external_checks() {
  local temp_output
  local targets_file="${TOOL_DIR}/targets_smb.txt"
  local relay_file="${TOOL_DIR}/targets_smb_relay.txt"
  local data_file

  if ! has_open_port tcp 445; then
    return
  fi

  write_open_targets_file tcp 445 "$targets_file"
  if [[ ! -s "$targets_file" ]]; then
    return
  fi

  if [[ "${NETEXEC_STARTUP_OK:-true}" == false ]]; then
    rm -f "${TOOL_DIR}/nxc_smb_signing_false.txt" "${TOOL_DIR}/nxc_smbv1_true.txt"
    printf '%sSkipping NetExec SMB Checks:%s Incomplete startup check; see Core Artifacts.\n' "$CLR_YELLOW" "$CLR_RESET"
    return 0
  fi
  if ! command_available netexec; then
    printf '%sSkipping NetExec SMB Checks:%s Command Not Found\n' "$CLR_YELLOW" "$CLR_RESET"
    return
  fi

  rm -f "${TOOL_DIR}/nxc_smb_signing_false.txt" "${TOOL_DIR}/nxc_smbv1_true.txt"
  # Input scope and NetExec output must be separate. Prepare the relay file
  # before dropping privileges; this also handles restrictive root umasks.
  : > "$relay_file"
  for data_file in "$targets_file" "$relay_file"; do
    chmod 600 "$data_file"
    if [[ "${BIDENT_DROP_PRIVILEGES:-false}" == true && -n "${BIDENT_RUN_USER:-}" ]]; then
      chown "$BIDENT_RUN_USER" "$data_file"
    fi
  done
  run_logged_check "Misconfigured Server Message Block Signing" "${TOOL_DIR}/nxc_smb_signing_false.txt" netexec smb --gen-relay-list "$relay_file" "$targets_file"
  run_logged_check "SMBv1 Enabled" "${TOOL_DIR}/nxc_smbv1_true.txt" netexec smb "$targets_file"
}

run_ssh_audit_check() {
  local targets_file
  local target
  local temp_output
  local ssh_audit_cmd
  local finding_found=false
  local incomplete=false
  local total_targets=0
  local completed_targets=0
  rm -f "${TOOL_DIR}/ssh_weak_cipher_targets.txt"

  if ! has_open_port tcp 22; then
    return
  fi

  if ! ssh_audit_cmd="$(resolve_command ssh-audit)"; then
    printf '%sSkipping ssh-audit:%s Command Not Found\n' "$CLR_YELLOW" "$CLR_RESET"
    printf '%sTip:%s Install ssh-audit in a common path or in the original sudo user path.\n' "$CLR_YELLOW" "$CLR_RESET"
    return
  fi

  printf '%sChecking For Weak SSH Ciphers%s\n' "$CLR_CYAN" "$CLR_RESET"
  targets_file="$(open_targets_file_for_ports tcp 22 ssh)"
  if [[ ! -s "$targets_file" ]]; then
    return
  fi

  total_targets="$(wc -l < "$targets_file" | tr -d '[:space:]')"
  rm -f ${TOOL_DIR}/ssh-audit_results.txt
  print_progress_bar "ssh-audit Progress" "$completed_targets" "$total_targets"

  while IFS= read -r target; do
    [[ -n "${target:-}" ]] || continue
    temp_output="$(mktemp "${TMPDIR:-/tmp}/bident_check.XXXXXX")"
    if ! run_external_capture "ssh-audit ${target}:22" "$temp_output" "$ssh_audit_cmd" "$target"; then
      incomplete=true
      rm -f "$temp_output"
      completed_targets=$((completed_targets + 1))
      print_progress_bar "ssh-audit Progress" "$completed_targets" "$total_targets"
      continue
    fi
    if result_output_has_finding "Weak SSH Ciphers" "$temp_output"; then
      finding_found=true
      append_command_header ${TOOL_DIR}/ssh-audit_results.txt "$ssh_audit_cmd" "$target"
      cat "$temp_output" >> ${TOOL_DIR}/ssh-audit_results.txt
    fi
    rm -f "$temp_output"
    completed_targets=$((completed_targets + 1))
    print_progress_bar "ssh-audit Progress" "$completed_targets" "$total_targets"
  done < "$targets_file"

  if [[ "$finding_found" == true ]]; then
    if [[ -n "$(ssh_weak_cipher_rows "${TOOL_DIR}/ssh-audit_results.txt" | cut -f1 | verified_ip_port_lines)" ]]; then
      printf '%s[+] Weak SSH Ciphers: Found and verified.%s\n' "$CLR_GREEN" "$CLR_RESET"
    fi
    ssh_weak_cipher_rows "${TOOL_DIR}/ssh-audit_results.txt" | cut -f1 | sort -u > "${TOOL_DIR}/ssh_weak_cipher_targets.txt"
  else
    rm -f ${TOOL_DIR}/ssh-audit_results.txt
    if [[ "$incomplete" == true ]]; then printf '%sssh-audit: Incomplete; one or more hosts could not be checked.%s\n' "$CLR_YELLOW" "$CLR_RESET"; fi
  fi
}

run_dns_dig_checks() {
  local target port temp_output
  local dig_args=(dig)
  has_open_port any 53 || return 0
  if ! command_available dig; then
    printf '%sSkipping DNS dig Checks:%s Command Not Found\n' "$CLR_YELLOW" "$CLR_RESET"
    return 0
  fi
  [[ "$NO_UDP" != true ]] || dig_args+=(+tcp)
  rm -f "${TOOL_DIR}/dnssec_not_configured.txt" "${TOOL_DIR}/dns_recursion_enabled.txt"
  while read -r target port; do
    [[ -n "$target" ]] || continue
    temp_output="$(mktemp "${TMPDIR:-/tmp}/bident_dns.XXXXXX")"
    run_external_capture "DNSSEC ${target}:${port}" "$temp_output" "${dig_args[@]}" +dnssec "@${target}" google.com A || true
    rm -f "$temp_output"
    run_logged_check "DNS Recursion Enabled" "${TOOL_DIR}/dns_recursion_enabled.txt" "${dig_args[@]}" "@${target}" google.com A
  done < <(open_target_ports any 53)
}

run_tls_target() {
  local outfile="$1" tool="$2" entry="$3" runner="" status rc=0
  mkdir -p "$LOG_DIR"
  local output_start
  output_start=1
  if [[ -f "$outfile" ]]; then output_start=$(( $(wc -l < "$outfile") + 1 )); fi
  local tool_args=("$tool")
  if [[ "$tool" == testssl ]]; then tool_args=("$tool" --wide --mapping iana); fi
  append_command_header "$outfile" "${tool_args[@]}" "$entry"
  if command_available timeout; then runner="$(command -v timeout)"
  elif command_available gtimeout; then runner="$(command -v gtimeout)"
  fi
  if [[ -z "$runner" ]]; then
    status='Incomplete: timeout command unavailable'
    rc=125
    printf '%sInstall GNU coreutils (timeout/gtimeout) to run bounded TLS checks.%s\n' "$CLR_YELLOW" "$CLR_RESET"
  else
    run_unprivileged "$runner" --kill-after=10s "${TLS_TIMEOUT}s" "${tool_args[@]}" "$entry" >> "$outfile" 2>&1 || rc=$?
  fi
  if [[ "$rc" -eq 0 ]] && external_output_has_error "$outfile" "$output_start"; then
    status='Incomplete: tool or connection error'
  fi
  if [[ -z "${status:-}" ]]; then
    case "$rc" in
      0) status='Finished; review output' ;;
      124) status="Incomplete: per-target timeout (${TLS_TIMEOUT}s)" ;;
      137) status='Incomplete: timeout or forced termination' ;;
      *) status="Incomplete: tool exited with status ${rc}" ;;
    esac
  fi
  printf '\nBident TLS result: %s\n' "$status" >> "$outfile"
  printf '%s\t%s\t%s\t%s\t%s\n' "$tool" "$entry" "$status" "$rc" "$outfile" >> "${LOG_DIR}/tls_status.tsv"
  if [[ "$status" == Incomplete:* ]]; then
    printf '%s%s %s: %s. Continuing remaining checks.%s\n' "$CLR_YELLOW" "$tool" "$entry" "$status" "$CLR_RESET"
  fi
  return 0
}

run_ssl_checks() {
  mkdir -p "$LOG_DIR"
  : > "${LOG_DIR}/tls_status.tsv"
  if command_available testssl || command_available sslscan; then
    printf '%sSSL/TLS Mode:%s External tools available; skipping SSL/TLS NSE fallback.\n' "$CLR_CYAN" "$CLR_RESET"
    run_ssl_external_checks
  else
    printf '%sSSL/TLS Mode:%s Neither testssl nor sslscan found; using NSE fallback.\n' "$CLR_YELLOW" "$CLR_RESET"
    run_if_open "SSL/TLS NSE" tcp "443,8443" \
      nmap -d -n -sV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" --script 'ssl-* and not dos' -p 443,8443 -oN "${NSE_DIR}/ssl_tls_results.txt" -iL "$(open_targets_file_for_ports tcp 443,8443 ssl_tls)" --open
  fi
}

run_ssl_external_checks() {
  local found=false
  local has_testssl=false
  local has_sslscan=false
  local target
  local port
  local ssl_targets=()
  local entry
  local total_targets=0
  local completed_targets=0

  if command_available testssl; then
    has_testssl=true
    : > ${TOOL_DIR}/testssl_results.txt
  else
    printf '%sSkipping testssl Checks:%s Command Not Found\n' "$CLR_YELLOW" "$CLR_RESET"
  fi

  if command_available sslscan; then
    has_sslscan=true
    : > ${TOOL_DIR}/sslscan_results.txt
  else
    printf '%sSkipping sslscan Checks:%s Command Not Found\n' "$CLR_YELLOW" "$CLR_RESET"
  fi

  if [[ "$has_testssl" == false && "$has_sslscan" == false ]]; then
    return
  fi

  while read -r target port; do
    [[ -n "${target:-}" ]] || continue
    found=true
    ssl_targets+=("${target}:${port}")
  done < <(open_target_ports tcp 443 8443)

  if [[ "$found" == false ]]; then
    [[ ! -e ${TOOL_DIR}/testssl_results.txt || -s ${TOOL_DIR}/testssl_results.txt ]] || rm -f ${TOOL_DIR}/testssl_results.txt
    [[ ! -e ${TOOL_DIR}/sslscan_results.txt || -s ${TOOL_DIR}/sslscan_results.txt ]] || rm -f ${TOOL_DIR}/sslscan_results.txt
    return
  fi

  total_targets="${#ssl_targets[@]}"

  if [[ "$has_testssl" == true ]]; then
    printf '%sRunning testssl (Primary SSL/TLS Check)%s\n' "$CLR_CYAN" "$CLR_RESET"
    completed_targets=0
    print_progress_bar "testssl Progress" "$completed_targets" "$total_targets"
    for entry in "${ssl_targets[@]}"; do
      run_tls_target "${TOOL_DIR}/testssl_results.txt" testssl "$entry"
      completed_targets=$((completed_targets + 1))
      print_progress_bar "testssl Progress" "$completed_targets" "$total_targets"
    done
  fi

  if [[ "$has_sslscan" == true ]]; then
    printf '%sRunning sslscan (SSL/TLS Cross-check)%s\n' "$CLR_CYAN" "$CLR_RESET"
    completed_targets=0
    print_progress_bar "sslscan Progress" "$completed_targets" "$total_targets"
    for entry in "${ssl_targets[@]}"; do
      run_tls_target "${TOOL_DIR}/sslscan_results.txt" sslscan "$entry"
      completed_targets=$((completed_targets + 1))
      print_progress_bar "sslscan Progress" "$completed_targets" "$total_targets"
    done
  fi

  [[ ! -e ${TOOL_DIR}/testssl_results.txt || -s ${TOOL_DIR}/testssl_results.txt ]] || rm -f ${TOOL_DIR}/testssl_results.txt
  [[ ! -e ${TOOL_DIR}/sslscan_results.txt || -s ${TOOL_DIR}/sslscan_results.txt ]] || rm -f ${TOOL_DIR}/sslscan_results.txt
  external_notify_tls_findings
}

run_ike_weak_encryption_check() {
  local found=false
  local finding=false
  local target
  local port
  local temp_output
  local outfile="${TOOL_DIR}/ike_weak_encryption.txt"

  if ! has_open_port udp 500; then
    return
  fi

  if ! command_available ike-scan; then
    printf '%sSkipping ike-scan Checks:%s Command Not Found\n' "$CLR_YELLOW" "$CLR_RESET"
    return
  fi

  rm -f "$outfile"

  while read -r target port; do
    [[ -n "${target:-}" ]] || continue
    found=true

    printf '%sChecking For IKE VPN Peer Weak Encryption:%s %s:%s\n' "$CLR_CYAN" "$CLR_RESET" "$target" "$port"
    temp_output="$(mktemp "${TMPDIR:-/tmp}/bident_check.XXXXXX")"
    if ! run_external_capture "IKE ${target}:${port}" "$temp_output" ike-scan -M "$target"; then
      rm -f "$temp_output"
      continue
    fi

    if grep -Eiq '(^|[^A-Za-z0-9])(3des|des|md5|sha-?1|group[[:space:]]*1|group[[:space:]]*2|modp768|modp1024)([^A-Za-z0-9]|$)' "$temp_output"; then
      append_command_header "$outfile" ike-scan -M "$target"
      cat "$temp_output" >> "$outfile"
      external_notify_command 'IKE VPN Peer Weak Encryption' "$temp_output" ike-scan -M "$target"
      finding=true
    fi

    rm -f "$temp_output"
  done < <(open_target_ports udp 500)

  if [[ "$found" == false ]]; then
    return
  fi

  [[ "$finding" == true ]] || rm -f "$outfile"
}

run_if_any_open() {
  local label="$1"
  shift

  if has_any_open_port; then
    printf '%sRunning %s:%s At Least One Confirmed Open Port Was Detected\n' "$CLR_CYAN" "$label" "$CLR_RESET"
    "$@"
  else
    printf '%sNo %s Found%s\n' "$CLR_YELLOW" "$label" "$CLR_RESET"
  fi
}

# Validate the current command block using the same endpoint attribution as the
# report. A successful exit or keyword by itself is not a verified finding.
external_notify_command() {
  local label="$1" output="$2" block endpoints
  shift 2
  block="$(mktemp "${TMPDIR:-/tmp}/bident_notify.XXXXXX")"
  append_command_header "$block" "$@"
  cat "$output" >> "$block"
  endpoints="$(tool_finding_endpoints "$label" "$block")"
  if [[ -n "$endpoints" ]]; then
    printf '%s[+] %s: Found and verified.%s\n' "${CLR_GREEN:-}" "$label" "${CLR_RESET:-}"
  fi
  rm -f "$block"
}

external_notify_tls_findings() {
  local summary title
  summary="$(mktemp "${TMPDIR:-/tmp}/bident_tls_notify.XXXXXX")"
  # Share the report renderer classifier, including cross-tool contradictions.
  # Only finding titles are read back; hosts and evidence never reach stdout.
  append_tls_findings_summary "$summary"
  while IFS= read -r title; do
    [[ -n "$title" ]] || continue
    printf '%s[+] %s: Found and verified.%s\n' "${CLR_GREEN:-}" "$title" "${CLR_RESET:-}"
  done < <(sed -nE 's/.*<strong>([^<]+)<\/strong>.*/\1/p' "$summary" | sort -u)
  rm -f "$summary"
}
