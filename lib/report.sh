# Normalize terminal formatting before escaping output for HTML. Raw files
# remain unchanged; every embedded evidence view uses this shared renderer.
html_escape_stream() {
  awk '
    BEGIN { esc = sprintf("%c", 27); bell = sprintf("%c", 7) }
    {
      # OSC titles/hyperlinks, then CSI colors and cursor controls.
      gsub(esc "\\][^" bell esc "]*(" bell "|" esc "\\\\)", "")
      gsub(esc "\\[[0-?]*[ -/]*[@-~]", "")
      # Some tools/loggers save printable escapes or drop the ESC byte.
      gsub(/\\(x1[bB]|033|u001[bB])\[[0-9;]*m/, "")
      gsub(/\[[0-9;]*m/, "")
      gsub(/\r/, "")
      gsub(/&/, "\\&amp;")
      gsub(/</, "\\&lt;")
      gsub(/>/, "\\&gt;")
      print
    }
  '
}

html_escape_file() {
  html_escape_stream < "$1"
}

file_size_bytes() {
  wc -c < "$1" | tr -d '[:space:]'
}

html_escape_file_preview() {
  html_escape_file "$1"
}

html_escape_text() {
  printf '%s' "$1" | html_escape_stream
}

title_case_acronyms() {
  awk '{
    for (i = 1; i <= NF; i++) {
      lower = tolower($i)
      if (lower == "ssh" || lower == "ftp" || lower == "smtp" || lower == "dns" ||
          lower == "smb" || lower == "mssql" || lower == "mysql" || lower == "rdp" ||
          lower == "vnc" || lower == "snmp" || lower == "ntp" ||
          lower == "msrpc" || lower == "ldap" || lower == "afp" || lower == "sip") {
        $i = toupper($i)
      } else {
        $i = toupper(substr($i, 1, 1)) substr($i, 2)
      }
    }
    print
  }'
}

default_result_label() {
  local result_name="${1##*/}"
  local msf_name
  if [[ "$result_name" == tomcat_ghostcat_tcp_8009.txt ]]; then printf 'Apache Tomcat AJP File Read (Ghostcat)'; return; fi
  if [[ "$result_name" == nbname_udp_137.txt ]]; then printf 'NetBIOS Information Disclosure'; return; fi

  if [[ "$result_name" =~ ^[A-Za-z0-9_]+_(tcp|udp)_[0-9]+\.txt$ ]]; then
    msf_name="${result_name%.txt}"
    msf_name="$(printf '%s' "$msf_name" | sed -E 's/_(tcp|udp)_[0-9]+$//; s/_/ /g')"
    printf '%s Metasploit Results' "$(printf '%s' "$msf_name" | title_case_acronyms)"
    return
  fi

  case "$result_name" in
    s_ftp.txt) printf 'FTP NMAP Results' ;;
    s_ssh.txt) printf 'SSH NMAP Results' ;;
    s_telnet.txt) printf 'Telnet NMAP Results' ;;
    s_smtp.txt) printf 'SMTP NMAP Results' ;;
    s_dns.txt) printf 'DNS NMAP Results' ;;
    s_http.txt) printf 'HTTP NMAP Results' ;;
    s_ajp.txt) printf 'AJP NMAP Results' ;;
    s_kerberos.txt) printf 'Kerberos NMAP Results' ;;
    s_pop3.txt) printf 'POP3 NMAP Results' ;;
    s_rpcbind.txt) printf 'RPCBind NMAP Results' ;;
    s_ntp.txt) printf 'NTP NMAP Results' ;;
    s_netbios.txt) printf 'NetBIOS NMAP Results' ;;
    s_smb.txt) printf 'SMB NMAP Results' ;;
    s_snmp.txt) printf 'SNMP NMAP Results' ;;
    s_ldap.txt) printf 'LDAP NMAP Results' ;;
    s_ike.txt) printf 'IKE NMAP Results' ;;
    s_ipmi.txt) printf 'IPMI NMAP Results' ;;
    ike_weak_encryption.txt) printf 'IKE VPN Peer Weak Encryption' ;;
    s_oracle.txt) printf 'Oracle NMAP Results' ;;
    s_nfs.txt) printf 'NFS NMAP Results' ;;
    s_rdp.txt) printf 'RDP NMAP Results' ;;
    s_sip.txt) printf 'SIP NMAP Results' ;;
    s_vnc.txt) printf 'VNC NMAP Results' ;;
    ssl_tls_results.txt) printf 'SSL/TLS NMAP Results' ;;
    testssl_results.txt) printf 'testssl Results' ;;
    sslscan_results.txt) printf 'sslscan Results' ;;
    dnssec_not_configured.txt) printf 'DNSSec Not Configured' ;;
    dns_recursion_enabled.txt) printf 'DNS Recursion Enabled' ;;
    db_mssql.txt) printf 'MSSQL NMAP Results' ;;
    db_mysql.txt) printf 'MySQL NMAP Results' ;;
    *) printf '%s' "$result_name" ;;
  esac
}

resolve_result_file() {
  local result_file="$1"

  if [[ -s "$result_file" ]]; then
    printf '%s' "$result_file"
    return 0
  fi

  for result_file in "${NSE_DIR}/${result_file}" "${TOOL_DIR}/${result_file}" "${SCAN_DIR}/${result_file}" "${LOG_DIR}/${result_file}"; do
    if [[ -s "$result_file" ]]; then
      printf '%s' "$result_file"
      return 0
    fi
  done

  return 1
}

append_result_file_section() {
  local outfile="$1"
  local result_file="$2"
  local result_label="${3:-}"
  local resolved_file
  local result_name

  if [[ -z "$result_label" ]]; then
    result_label="$(default_result_label "$result_file")"
  fi

  resolved_file="$(resolve_result_file "$result_file")" || return 1
  result_name="${resolved_file##*/}"

  {
    printf '<details class="artifact result-panel">\n'
    if [[ "$result_label" == "$result_name" ]]; then
      printf '<summary>%s</summary>\n' "$(html_escape_text "$resolved_file")"
    else
      printf '<summary>%s <span class="artifact-file">%s</span></summary>\n' "$(html_escape_text "$result_label")" "$(html_escape_text "$resolved_file")"
    fi
    printf '<pre>'
    html_escape_file_preview "$resolved_file"
    printf '</pre>\n'
    printf '</details>\n'
  } >> "$outfile"
  return 0
}

append_ssl_external_result_files() {
  local outfile="$1"
  local appended=1

  append_result_file_section "$outfile" testssl_results.txt && appended=0
  append_result_file_section "$outfile" sslscan_results.txt && appended=0
  return "$appended"
}

append_artifact_link() {
  local outfile="$1"
  local artifact="$2"

  if [[ -s "$artifact" ]]; then
    printf '<a href="%s">%s</a>\n' "$(html_escape_text "$artifact")" "$(html_escape_text "$artifact")" >> "$outfile"
  fi
}

append_core_artifact_group() {
  local outfile="$1"
  local label="$2"
  shift 2
  local artifact
  local temp_file
  local item_count=0

  temp_file="$(mktemp "${TMPDIR:-/tmp}/bident_artifacts.XXXXXX")"
  for artifact in "$@"; do
    if [[ -s "$artifact" ]]; then
      printf '<a href="%s">%s</a>\n' "$(html_escape_text "$artifact")" "$(html_escape_text "$artifact")" >> "$temp_file"
      item_count=$((item_count + 1))
    fi
  done

  if [[ -s "$temp_file" ]]; then
    {
      printf '    <details class="artifact artifact-group">\n'
      printf '      <summary>%s <span class="artifact-file">%s item(s)</span></summary>\n' "$(html_escape_text "$label")" "$item_count"
      printf '      <div class="file-list">'
      cat "$temp_file"
      printf '      </div>\n'
      printf '    </details>\n'
    } >> "$outfile"
  fi

  rm -f "$temp_file"
}

append_external_failed_artifacts() {
  local outfile="$1" label status rc log_file
  [[ -s "${LOG_DIR}/external_status.tsv" ]] || return 0
  printf '<details class="artifact artifact-group"><summary>External Tool Failed / Incomplete Checks</summary>\n' >> "$outfile"
  while IFS=$'\t' read -r label status rc log_file; do
    printf '<details class="artifact result-panel"><summary>%s — %s</summary><pre>' "$(html_escape_text "$label")" "$(html_escape_text "$status")" >> "$outfile"
    if [[ -s "$log_file" ]]; then html_escape_file "$log_file" >> "$outfile"
    else printf 'Execution log unavailable.' >> "$outfile"; fi
    printf '</pre></details>\n' >> "$outfile"
  done < "${LOG_DIR}/external_status.tsv"
  printf '</details>\n' >> "$outfile"
}

append_msf_output_artifacts() {
  local outfile="$1" result_file count=0
  printf '<details class="artifact artifact-group"><summary>Metasploit Results</summary>\n' >> "$outfile"
  for result_file in "${MSF_RESULT_DIR}"/*.txt; do
    [[ -s "$result_file" ]] || continue
    append_result_file_section "$outfile" "$result_file"
    count=$((count + 1))
  done
  if [[ "$count" -eq 0 ]]; then
    printf '<div class="empty">No per-module result files were saved. Review the console log for execution or spool errors.</div>\n' >> "$outfile"
  fi
  if [[ -s "${MSF_DIR}/msfconsole.log" ]]; then
    append_result_file_section "$outfile" "${MSF_DIR}/msfconsole.log" 'Full Metasploit Console Output'
  else
    printf '<div class="empty">No Metasploit console output was saved.</div>\n' >> "$outfile"
  fi
  printf '</details>\n' >> "$outfile"
}

append_msf_result_files() {
  local outfile="$1"
  local proto="$2"
  local port="$3"
  local result_file
  local appended=1

  [[ "${NO_MSF:-false}" == true ]] && return 1

  for result_file in "${MSF_RESULT_DIR}/"*"_${proto}_${port}.txt"; do
    [[ -s "$result_file" ]] || continue
    append_result_file_section "$outfile" "$result_file" && appended=0
  done
  return "$appended"
}

append_base_scan_port_evidence() {
  local outfile="$1"
  local proto="$2"
  local port="$3"
  local temp_file
  local source_file
  local sources=()

  temp_file="$(mktemp "${TMPDIR:-/tmp}/bident_base_evidence.XXXXXX")"

  case "$proto" in
    tcp)
      sources=("${SCAN_DIR}/syn.gnmap" "${SCAN_DIR}/con.gnmap")
      ;;
    udp)
      sources=("${SCAN_DIR}/udp.gnmap")
      ;;
    *)
      sources=("${SCAN_DIR}/syn.gnmap" "${SCAN_DIR}/con.gnmap" "${SCAN_DIR}/udp.gnmap")
      ;;
  esac

  for source_file in "${sources[@]}"; do
    local normal_file="${source_file%.gnmap}.nmap" excerpt
    excerpt=""
    if [[ -s "$normal_file" ]]; then
      excerpt="$(awk -v port="$port" -v proto="$proto" '
        /^Nmap scan report for / {host=$0; next}
        $1 ~ /^[0-9]+\/(tcp|udp)$/ {
          split($1, endpoint, "/")
          if (endpoint[1] == port && endpoint[2] == proto && $2 == "open") {
            print host
            print "PORT     STATE SERVICE / VERSION"
            print $0
            print ""
          }
        }
      ' "$normal_file")"
    fi
    if [[ -n "$excerpt" ]]; then
      printf '===== %s =====\n%s\n\n' "$normal_file" "$excerpt" >> "$temp_file"
    elif [[ -s "$source_file" ]]; then
      awk -v wanted_port="$port" -v wanted_proto="$proto" -v source_file="$source_file" '
        /Ports:/ {
          host=$0; sub(/[[:space:]]*Ports:.*/, "", host)
          text=$0; sub(/^.*Ports: /, "", text)
          n=split(text, ports, ", ")
          for (i=1; i<=n; i++) {
            split(ports[i], fields, "/")
            if (fields[1] == wanted_port && fields[2] == "open" && fields[3] == wanted_proto) {
              print "===== " source_file " (formatted) ====="
              print host
              print "PORT     STATE SERVICE / VERSION"
              print fields[1] "/" fields[3] "  " fields[2] "  " fields[5] "  " fields[7]
              print ""
            }
          }
        }
      ' "$source_file" >> "$temp_file"
    fi
  done

  if [[ -s "$temp_file" ]]; then
    {
      printf '<details class="artifact result-panel">\n'
      printf '<summary>Base Scan Evidence <span class="artifact-file">%s/%s</span></summary>\n' "$(html_escape_text "$proto")" "$(html_escape_text "$port")"
      printf '<pre>'
      html_escape_file_preview "$temp_file"
      printf '</pre>\n'
      printf '</details>\n'
    } >> "$outfile"
    rm -f "$temp_file"
    return 0
  fi

  rm -f "$temp_file"
  return 1
}

append_nse_status_section() {
  local outfile="$1"
  {
    printf '  <section class="notice" aria-label="NSE check status">\n'
    printf '    <strong>NSE Check Status</strong>\n'
    printf '    <p>Script timeout: %s per instance (0 = unlimited). Timed-out checks are incomplete. Details are available under Core Artifacts &gt; NSE Check Status.</p>\n' "$(html_escape_text "$SCRIPT_TIMEOUT")"
    printf '  </section>\n'
  } >> "$outfile"
}

append_nse_status_artifacts() {
  local outfile="$1" label status log_file
  {
    printf '  <details class="artifact artifact-group">\n'
    printf '    <summary>NSE Check Status</summary>\n'
    if [[ -s "${LOG_DIR}/nse_status.tsv" ]]; then
      printf '  <ul>\n'
      while IFS=$'\t' read -r label status log_file; do
        printf '    <li><strong>%s</strong>: %s — <a href="%s">execution log</a></li>\n' \
          "$(html_escape_text "$label")" "$(html_escape_text "$status")" "$(html_escape_text "$log_file")"
      done < "${LOG_DIR}/nse_status.tsv"
      printf '  </ul>\n'
    else
      printf '  <p class="muted">No follow-up NSE checks recorded for this run.</p>\n'
    fi
    printf '  </details>\n'
  } >> "$outfile"
}

append_tls_status_artifacts() {
  local outfile="$1" tool endpoint status rc source_file
  [[ -s "${LOG_DIR}/tls_status.tsv" ]] || return 0
  {
    printf '  <details class="artifact artifact-group"><summary>TLS External Check Status</summary>\n'
    printf '    <p class="muted">Per-tool, per-target timeout: %s seconds. Incomplete output is excluded from verified TLS findings.</p>\n' "$(html_escape_text "$TLS_TIMEOUT")"
    printf '    <ul>\n'
    while IFS=$'\t' read -r tool endpoint status rc source_file; do
      printf '      <li><strong>%s %s</strong>: %s — <a href="%s">execution log</a></li>\n' \
        "$(html_escape_text "$tool")" "$(html_escape_text "$endpoint")" "$(html_escape_text "$status")" "$(html_escape_text "$source_file")"
    done < "${LOG_DIR}/tls_status.tsv"
    printf '    </ul>\n  </details>\n'
  } >> "$outfile"
}

append_scan_configuration_section() {
  local outfile="$1"
  local scope_display="${SCOPE_FILE:-resume}"
  local udp_mode="Enabled"
  local msf_mode="Enabled"
  local ports_mode="Default Nmap ports"
  local discovery_timeout="${DISCOVERY_HOST_TIMEOUT:-5m}"

  [[ "$NO_UDP" == true ]] && udp_mode="Disabled"
  [[ "$NO_MSF" == true ]] && msf_mode="Disabled"
  [[ "$PORT_FLAG" == "-p-" ]] && ports_mode="All ports (-p-)"

  {
    printf '  <h2>Scan Configuration</h2>\n'
    printf '  <section class="summary-grid">\n'
    printf '    <div class="summary-card"><span>Target input</span><strong>%s</strong></div>\n' "$(html_escape_text "$scope_display")"
    printf '    <div class="summary-card"><span>Ports</span><strong>%s</strong></div>\n' "$(html_escape_text "$ports_mode")"
    printf '    <div class="summary-card"><span>Timing</span><strong>-%s</strong></div>\n' "$(html_escape_text "$TIMING")"
    printf '    <div class="summary-card"><span>Base min-rate</span><strong>%s</strong></div>\n' "$(html_escape_text "$MIN_RATE")"
    printf '    <div class="summary-card"><span>NSE min-rate</span><strong>%s</strong></div>\n' "$(html_escape_text "$NSE_MIN_RATE")"
    printf '    <div class="summary-card"><span>Host discovery timeout</span><strong>%s</strong></div>\n' "$(html_escape_text "$discovery_timeout")"
    printf '    <div class="summary-card"><span>UDP scans</span><strong>%s</strong></div>\n' "$(html_escape_text "$udp_mode")"
    printf '    <div class="summary-card"><span>Metasploit</span><strong>%s</strong></div>\n' "$(html_escape_text "$msf_mode")"
    printf '    <div class="summary-card"><span>Tool timeout</span><strong>%s</strong></div>\n' "$([[ "$TOOL_TIMEOUT" -gt 0 ]] && html_escape_text "${TOOL_TIMEOUT}s" || printf 'Disabled')"
    printf '    <div class="summary-card"><span>Metasploit timeout</span><strong>%s</strong></div>\n' "$([[ "$MSF_TIMEOUT" -gt 0 ]] && html_escape_text "${MSF_TIMEOUT}s" || printf 'Disabled')"
    printf '    <div class="summary-card"><span>Metasploit threads</span><strong>%s</strong></div>\n' "$(html_escape_text "$MSF_THREADS")"
    printf '    <div class="summary-card"><span>Metasploit connect timeout</span><strong>%ss</strong></div>\n' "$(html_escape_text "$MSF_CONNECT_TIMEOUT")"
    printf '    <div class="summary-card"><span>Metasploit TCP timeout</span><strong>%ss</strong></div>\n' "$(html_escape_text "$MSF_TCP_TIMEOUT")"
    printf '  </section>\n'
  } >> "$outfile"
}

finding_count_for_file() {
  local file="$1"

  [[ -s "$file" ]] || {
    printf '0'
    return
  }

  awk 'END {print NR + 0}' "$file"
}

finding_file_has_verified_evidence() {
  local title="$1"
  local source_file="$2"

  [[ -s "$source_file" ]] || return 1

  case "$title" in
    "Weak SSH Ciphers")
      [[ -n "$(ssh_weak_cipher_rows "$source_file")" ]]
      ;;
    "Exposed RPC Services")
      grep -Eiq '(^Protocol:|^Provider:|^[[:space:]]*[0-9a-fA-F-]{36}|ncacn_|MS-RPCE|uuid)' "$source_file" &&
        ! grep -Eiq 'connection refused|NT_STATUS_|failed|error|timed out|No route to host' "$source_file"
      ;;
    "Unauthenticated Remote Procedure Call")
      grep -Eiq 'Se[A-Za-z]+Privilege|found[[:space:]]+[0-9]+[[:space:]]+privileges|privilege' "$source_file" &&
        ! grep -Eiq 'NT_STATUS_ACCESS_DENIED|NT_STATUS_LOGON_FAILURE|Cannot connect|failed|error|timed out' "$source_file"
      ;;
    "Misconfigured Server Message Block Signing")
      grep -Eq 'signing:False' "$source_file"
      ;;
    "SMBv1 Enabled")
      grep -Eq 'SMBv1:True' "$source_file"
      ;;
    "LDAP Anonymous Bind")
      grep -Eiq '^(dn:|namingContexts:|defaultNamingContext:|rootDomainNamingContext:|supportedLDAPVersion:|supportedSASLMechanisms:)' "$source_file" &&
        ! grep -Eiq 'Invalid credentials|Can.t contact LDAP server|ldap_bind:|failed|error|timed out' "$source_file"
      ;;
    "DNSSec Not Configured")
      grep -q 'flags:' "$source_file" && ! grep -Eq 'flags:.*[[:space:]]ad[;[:space:]]' "$source_file"
      ;;
    "DNS Recursion Enabled")
      grep -Eq 'flags:.*[[:space:]]ra[;[:space:]]' "$source_file"
      ;;
    "IKE VPN Peer Weak Encryption")
      grep -Eiq '(^|[^A-Za-z0-9])(3des|des|md5|sha-?1|group[[:space:]]*1|group[[:space:]]*2|modp768|modp1024)([^A-Za-z0-9]|$)' "$source_file"
      ;;
    *)
      return 1
      ;;
  esac
}

print_cipher_list() {
  local cipher
  printf '<ul class="cipher-list">'
  while IFS= read -r cipher; do
    [[ -n "$cipher" ]] && printf '<li>%s</li>' "$(html_escape_text "$cipher")"
  done
  printf '</ul>'
}

append_ssh_weak_cipher_finding() {
  local outfile="$1" source_file="${TOOL_DIR}/ssh-audit_results.txt"
  local rows target ciphers target_count
  [[ -s "$source_file" ]] || return 0
  rows="$(ssh_weak_cipher_rows "$source_file" | awk -F '\t' '
    !seen[$1 SUBSEP $2]++ {
      if (!($1 in ciphers)) order[++n] = $1
      ciphers[$1] = ciphers[$1] (ciphers[$1] == "" ? "" : ", ") $2
    }
    END {for (i = 1; i <= n; i++) print order[i] "\t" ciphers[order[i]]}
  ')"
  [[ -n "$rows" ]] || return 0
  local valid_endpoints
  valid_endpoints="$(printf '%s\n' "$rows" | cut -f1 | verified_ip_port_lines)"
  rows="$(awk -F '\t' 'NR==FNR {valid[$0]=1; next} $1 in valid' <(printf '%s\n' "$valid_endpoints") <(printf '%s\n' "$rows"))"
  [[ -n "$rows" ]] || return 0
  target_count="$(printf '%s\n' "$rows" | awk 'END {print NR}')"
  {
    printf '    <li><details class="finding-panel">\n'
    printf '      <summary><div><strong>Weak SSH Ciphers</strong><span>%s affected host(s)</span></div></summary>\n' "$target_count"
    printf '      <div data-affected-targets>\n'
    print_copy_targets_button
    printf '      <div class="service-table-wrap"><table class="service-table"><thead><tr><th>Host:Port</th><th>Weak/Deprecated Ciphers Found:</th></tr></thead><tbody>\n'
    while IFS=$'\t' read -r target ciphers; do
      printf '        <tr><td>%s</td><td>' "$(html_escape_text "$target")"
      printf '%s\n' "$ciphers" | awk 'BEGIN {RS=", "} {print}' | print_cipher_list
      printf '</td></tr>\n' 
    done <<< "$rows"
    printf '      </tbody></table></div></div>\n'
    printf '      <details class="artifact"><summary>Full Evidence — %s</summary><pre class="finding-evidence">' "$(html_escape_text "$source_file")"
    html_escape_file_preview "$source_file"
    printf '</pre></details>\n'
    printf '    </details></li>\n'
  } >> "$outfile"
}

verified_ip_port_lines() {
  awk '
    function valid_ip(ip, parts, n, j, compressed, count, rest) {
      if (ip ~ /:/) {
        if (ip !~ /^[0-9a-fA-F:]+$/ || ip ~ /:::/) return 0
        compressed = index(ip, "::") > 0
        rest = ip; sub(/::/, "X", rest)
        if (rest ~ /::/) return 0
        if (!compressed && (ip ~ /^:/ || ip ~ /:$/)) return 0
        n = split(ip, parts, ":"); count = 0
        for (j = 1; j <= n; j++) {
          if (length(parts[j]) > 4) return 0
          if (parts[j] != "") count++
        }
        return compressed ? count < 8 : count == 8
      }
      n = split(ip, parts, ".")
      if (n != 4) return 0
      for (j = 1; j <= n; j++) if (parts[j] !~ /^[0-9]+$/ || (parts[j] + 0) > 255) return 0
      return 1
    }
    {
      endpoint = $0; ip = endpoint; port = endpoint
      if (endpoint ~ /^\[/) { sub(/^\[/, "", ip); sub(/\]:[0-9]+$/, "", ip); sub(/^.*\]:/, "", port) }
      else { sub(/:[0-9]+$/, "", ip); sub(/^.*:/, "", port); if (ip ~ /:/) next }
      if (port ~ /^[0-9]+$/ && (port + 0) > 0 && (port + 0) <= 65535 && valid_ip(ip) && !seen[endpoint]++) print endpoint
    }
  '
}

# Extract endpoints only from the same command block as verified evidence.
# Never promote a scope/targets file or an unrelated banner IP to a finding.
tool_finding_endpoints() {
  local title="$1" file="$2" mode="${3:-endpoints}"
  html_escape_stream < "$file" | awk -v title="$title" -v mode="$mode" '
    function valid_ip(ip, parts, n, j) {
      if (ip ~ /:/) return ip ~ /^[0-9a-fA-F:]+$/ && ip ~ /:.*:/
      n = split(ip, parts, ".")
      if (n != 4) return 0
      for (j = 1; j <= n; j++) if (parts[j] !~ /^[0-9]+$/ || (parts[j] + 0) > 255) return 0
      return 1
    }
    function emit(ip, port, single_text, single_nr, key, j) {
      if (!valid_ip(ip) || port !~ /^[0-9]+$/ || (port + 0) < 1 || (port + 0) > 65535) return
      key = (ip ~ /:/ ? "[" ip "]" : ip) ":" port
      if (mode == "rows") {
        if (single_text != "") print key "\034" single_nr "\034" single_text
        else for (j = 1; j <= evidence_count; j++) print key "\034" evidence_nr[j] "\034" evidence[j]
      } else if (!seen[key]++) print key
    }
    function flush() {
      if (!error && positive && permitted) emit(host, port)
      for (j in evidence) delete evidence[j]
      for (j in evidence_nr) delete evidence_nr[j]
      evidence_count = 0
      host = ""; port = ""; positive = 0; error = 0; permitted = 0; dns_answer = 0; dns_ok = 0; dns_ra = 0; handshake = 0; weak = 0
    }
    /^===== / { flush(); next }
    /^Command:/ {
      flush()
      command = $0
      if (title == "Exposed RPC Services" && command ~ /(^|[\/[:space:]])impacket-rpcdump[[:space:]]/) { host = $NF; port = 135; permitted = 1 }
      if (title == "Unauthenticated Remote Procedure Call" && command ~ /(^|[\/[:space:]])rpcclient[[:space:]]/ && command ~ / -N([[:space:]]|$)/ && command ~ / -U[[:space:]]+(\047\047|"")([[:space:]]|$)/) { host = $NF; port = 445; permitted = 1 }
      if (title == "LDAP Anonymous Bind" && command ~ /ldapsearch[[:space:]]/ && command ~ / -x([[:space:]]|$)/ && command !~ / -(D|w|W|y|Y|U)([[:space:]]|$)/) {
        for (i = 1; i <= NF; i++) if ($i ~ /^ldap:\/\//) {
          uri = $i; sub(/^ldap:\/\//, "", uri); sub(/\/$/, "", uri)
          host = uri; sub(/:[0-9]+$/, "", host)
          port = uri; sub(/^.*:/, "", port); permitted = 1
        }
      }
      if (title == "DNS Recursion Enabled" && command ~ /(^|[[:space:]])dig[[:space:]]/ && command ~ /google[.]com/) {
        for (i = 1; i <= NF; i++) if ($i ~ /^@/) { host = substr($i, 2); port = 53; permitted = 1 }
      }
      if (title == "IKE VPN Peer Weak Encryption" && command ~ /(^|[[:space:]])ike-scan[[:space:]]/) { host = $NF; port = 500; permitted = 1 }
      for (i = 1; i < NF; i++) if ($i == "-p") port = $(i + 1)
      gsub(/[\\\[\]]/, "", host)
      next
    }
    {
      lower = tolower($0)
      relevant = 0
      if (lower ~ /connection refused|cannot connect|no route to host|timed out|nt_status_|invalid credentials|ldap_bind:|(^|[[:space:]])(error|failed|failure|exception)([[:space:]:]|$)/) error = 1
      if (title == "Exposed RPC Services" && $0 ~ /^(Protocol:|Provider:)|ncacn_|^[[:space:]]*[0-9a-fA-F-]{36}/) { positive = 1; relevant = 1 }
      if (title == "Unauthenticated Remote Procedure Call" && $0 ~ /Se[A-Za-z]+Privilege/) { positive = 1; relevant = 1 }
      if (title == "LDAP Anonymous Bind" && $0 ~ /^(dn:|namingContexts:|defaultNamingContext:|rootDomainNamingContext:|supportedLDAPVersion:|supportedSASLMechanisms:)/) { positive = 1; relevant = 1 }
      if (title == "DNS Recursion Enabled") {
        if ($0 ~ /status: NOERROR/) dns_ok = 1
        if ($0 ~ /ANSWER: [1-9][0-9]*/) dns_answer = 1
        if ($0 ~ /flags:.*[[:space:]]rd[;[:space:]]/ && $0 ~ /flags:.*[[:space:]]ra[;[:space:]]/) dns_ra = 1
        positive = dns_ok && dns_answer && dns_ra
        if ($0 ~ /status:|flags:/) relevant = 1
      }
      if (title == "IKE VPN Peer Weak Encryption") {
        if ($1 == host && lower ~ /handshake returned/ && lower !~ /no handshake/) handshake = 1
        if (handshake && ($0 ~ /^[[:space:]]*SA=/ || $1 == host) && lower ~ /sa=/ && lower ~ /(enc|hash|group).*(3des|md5|sha1|sha-1|modp768|modp1024|group[[:space:]]*[12]([^0-9]|$))/) weak = 1
        positive = handshake && weak
        if (($1 == host && lower ~ /handshake returned/) || (handshake && ($0 ~ /^[[:space:]]*SA=/ || $1 == host) && lower ~ /sa=/)) relevant = 1
      }
      if (relevant) { evidence[++evidence_count] = $0; evidence_nr[evidence_count] = NR }
      # NetExec identifies host and actual port on each result line. Ignore
      # the command header, which commonly contains a whole targets file.
      if ($1 == "SMB" && lower !~ /error|failed|failure|timeout|timed out|refused/ && ((title == "Misconfigured Server Message Block Signing" && $0 ~ /signing:False/) || (title == "SMBv1 Enabled" && $0 ~ /SMBv1:True/))) emit($2, $3, $0, NR)
    }
    END { flush() }
  ' | if [[ "$mode" == rows ]]; then cat; else verified_ip_port_lines; fi
}

print_copy_icon() {
  printf '<svg class="copy-icon" aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/></svg>'
}

print_copy_targets_button() {
  printf '      <div class="copy-targets-toolbar"><button type="button" class="copy-targets">Copy hosts %s</button><span class="copy-targets-status muted" role="status" aria-live="polite"></span></div>\n' "$(print_copy_icon)"
}

append_affected_endpoint_list() {
  local endpoints="$1" target
  printf '      <div data-affected-targets>\n'
  print_copy_targets_button
  printf '<div class="service-table-wrap"><table class="service-table"><thead><tr><th>Host:Port</th></tr></thead><tbody>\n'
  while IFS= read -r target; do
    [[ -n "$target" ]] && printf '<tr><td>%s</td></tr>\n' "$(html_escape_text "$target")"
  done <<< "$endpoints"
  printf '</tbody></table></div></div>\n'
}

append_tls_cipher_table() {
  local rows_file="$1" endpoints="$2" endpoint ciphers
  printf '      <div data-affected-targets>\n'
  print_copy_targets_button
  printf '      <div class="service-table-wrap"><table class="service-table"><thead><tr><th>Host:Port</th><th>Weak/Deprecated Ciphers Found:</th></tr></thead><tbody>\n'
  while IFS= read -r endpoint; do
    ciphers="$(awk -F '\034' -v host="$endpoint" '$1 == host && $2 != "" && $2 !~ /^Category only:/ && !seen[$2]++ {value=value (value == "" ? "" : "\n") $2} END {print value}' "$rows_file")"
    printf '        <tr><td>%s</td><td>' "$(html_escape_text "$endpoint")"
    if [[ -n "$ciphers" ]]; then printf '%s\n' "$ciphers" | print_cipher_list
    else printf '%s' 'Individual cipher names unavailable in saved output; rescan required.'; fi
    printf '</td></tr>\n' 
  done <<< "$endpoints"
  printf '      </tbody></table></div></div>\n'
}

append_finding_full_evidence() {
  local rows_file="$1" source matches
  while IFS= read -r source; do
    [[ -s "$source" ]] || continue
    matches="$(awk -F '\034' -v source="$source" -v endpoints="$(printf '%s' "$2" | tr '\n' ',')" '
      BEGIN {split(endpoints, hosts, ","); for (i in hosts) valid[hosts[i]]=1}
      {path=$3; sub(/:[0-9]+$/, "", path); if (path==source && ($1 in valid) && !seen[$3]++) refs=refs (refs=="" ? "" : ", ") $3}
      END {print refs}' "$rows_file")"
    printf '<details class="artifact"><summary>Full Evidence — %s</summary><p class="muted evidence-source">Matched source lines: %s</p><pre class="finding-evidence">' "$(html_escape_text "$source")" "$(html_escape_text "$matches")"
    html_escape_file "$source"
    printf '</pre></details>\n'
  done < <(awk -F '\034' '{source=$3; sub(/:[0-9]+$/, "", source); if (!seen[source]++) print source}' "$rows_file")
}

append_finding_item() {
  local outfile="$1"
  local severity="$2"
  local title="$3"
  local source_file="$4"
  local detail="${5:-}"
  local count=0
  local endpoints evidence_rows endpoint evidence_line evidence_text

  [[ -s "$source_file" ]] || return 0
  endpoints="$(tool_finding_endpoints "$title" "$source_file")"
  [[ -n "$endpoints" ]] || return 0
  count="$(finding_count_for_file "$source_file")"

  {
    printf '    <li><details class="finding-panel">\n'
    printf '      <summary><div><strong>%s</strong>\n' "$(html_escape_text "$title")"
    printf '        <span>%s affected host(s)</span>\n' "$(printf '%s\n' "$endpoints" | awk 'NF {n++} END {print n+0}')"
    printf '      </div></summary>\n'
    append_affected_endpoint_list "$endpoints"
    evidence_rows="$(mktemp "${TMPDIR:-/tmp}/bident_tool_evidence.XXXXXX")"
    while IFS=$'\034' read -r endpoint evidence_line evidence_text; do
      printf '%s\034\034%s:%s\034%s\n' "$endpoint" "$source_file" "$evidence_line" "$evidence_text" >> "$evidence_rows"
    done < <(tool_finding_endpoints "$title" "$source_file" rows)
    append_finding_full_evidence "$evidence_rows" "$endpoints" true
    rm -f "$evidence_rows"
    printf '    </details></li>\n'
  } >> "$outfile"
}

# Only explicit module result messages qualify as Metasploit findings.
# The HTML renderer also normalizes ANSI sequences before classification.
msf_finding_lines() {
  local file="$1" kind="${1##*/}" mode="${2:-evidence}" port="" scope_file=""
  if [[ "$kind" =~ _(tcp|udp)_([0-9]+)[.]txt$ ]]; then
    port="${BASH_REMATCH[2]}"
    scope_file="${MSF_DIR}/targets_${BASH_REMATCH[1]}_${port}.txt"
    [[ -s "$scope_file" ]] || scope_file=""
  fi
  if [[ "$kind" == tomcat_ghostcat_tcp_8009.txt ]]; then
    command -v python3 >/dev/null 2>&1 || return 0
    python3 "${BIDENT_ROOT}/lib/ghostcat.py" read "$file" "${MSF_DIR}/targets_tcp_8009.txt" "$mode"
    return
  fi
  html_escape_stream < "$file" | awk -v kind="$kind" -v mode="$mode" -v default_port="$port" -v scope_file="$scope_file" '
    BEGIN {
      if (scope_file != "") while ((getline scoped_host < scope_file) > 0) {gsub(/^[[:space:]]+|[[:space:]]+$/, "", scoped_host); allowed[scoped_host]=1}
      if (scope_file != "") close(scope_file)
    }
    function endpoint_from_message(message, ip, port, n, parts, j) {
      sub(/^\[[+*]\][[:space:]]*/, "", message)
      sub(/^Detected RDP on[[:space:]]+/, "", message)
      sub(/[,[:space:]].*$/, "", message)
      ip = message; port = default_port
      if (ip ~ /^\[[0-9a-fA-F:]+\]:[0-9]+$/) {
        port = ip; sub(/^.*\]:/, "", port); sub(/\]:[0-9]+$/, "", ip); sub(/^\[/, "", ip)
      } else if (ip ~ /^[0-9.]+:[0-9]+$/) {
        port = ip; sub(/^.*:/, "", port); sub(/:[0-9]+$/, "", ip)
      }
      if (port !~ /^[0-9]+$/ || (port + 0) < 1 || (port + 0) > 65535 || (default_port != "" && port + 0 != default_port + 0)) return ""
      if (scope_file != "" && !(ip in allowed)) return ""
      if (ip ~ /:/) {
        if (ip !~ /^[0-9a-fA-F:]+$/ || ip !~ /:.*:/) return ""
        return "[" ip "]:" port
      }
      n = split(ip, parts, ".")
      if (n != 4) return ""
      for (j = 1; j <= 4; j++) if (parts[j] !~ /^[0-9]+$/ || (parts[j] + 0) > 255) return ""
      return ip ":" port
    }

    {
      line = $0
      lower = tolower(line)
      if (line ~ /^===== / || line ~ /^Command:/) {context=""; shares=0; next}
      if (lower ~ /^[[:space:]]*resource[[:space:](]/ || lower ~ / => /) { context = ""; next }
      if (line ~ /^\[[+*-]\]/) context = ""
      if (kind ~ /^snmp_enumshares_/ && line ~ /^\[\+\]/) context = endpoint_from_message(line)
      if (kind ~ /^snmp_enum_/ && lower ~ /^[[:space:]]*host ip[[:space:]]*:/) {
        context_line = line; sub(/^[^:]*:[[:space:]]*/, "", context_line)
        context = endpoint_from_message(context_line)
      }
      if (lower ~ /^\[-\]/ || lower ~ /not vulnerable|not likely vulnerable|not currently vulnerable|does not appear vulnerable|not exploitable|not (an )?open (smtp )?relay|no anonymous|anonymous.*(denied|disabled|not allowed)|login failed|authentication failed|connection refused|timed out|auxiliary failed|unable to|could not/) { shares = 0; next }
      good = (line ~ /^\[\+\]/)
      result = (line ~ /^\[[+*]\]/)
      found = 0
      if (kind ~ /^ftp_anonymous_/) found = good && lower ~ /anonymous.*(allowed|enabled|login|read|write)|logged in successfully/
      else if (kind ~ /^smtp_relay_/) found = good && lower ~ /(open.*relay.*detected|relay.*(accepted|allowed|successful))/
      else if (kind ~ /^smb_ms17_010_/) found = good && lower ~ /(host is likely vulnerable|ms17-010.*(detected|vulnerable)|vulnerable.*ms17-010)/
      else if (kind ~ /^rdp_scanner_/) found = result && lower ~ /detected rdp on[[:space:]]+[^[:space:]]+/
      else if (kind ~ /^cve_2019_0708_bluekeep_/) found = good && lower ~ /(target (is|appears to be) vulnerable|bluekeep.*vulnerable|vulnerable.*bluekeep)/
      else if (kind ~ /^vnc_none_auth_/) found = good && lower ~ /(security types includes none|no authentication (required|needed)|authentication.*disabled|does not require authentication)/
      else if (kind ~ /^nbname_udp_137[.]txt$/) found = good && lower ~ /\[[^][]+\][[:space:]]+os:(windows|unix)/ && lower ~ /mac:([0-9a-f][0-9a-f]:){5}[0-9a-f][0-9a-f]/
      else if (kind ~ /^snmp_login_/) found = good && lower ~ /login successful:/
      else if (kind ~ /^snmp_enumusers_/) found = good && lower ~ /found[[:space:]]+[1-9][0-9]*[[:space:]]+users:/
      else if (kind ~ /^snmp_enumshares_/) {
        if (result) shares = good
        if (shares && line ~ /^[[:space:]]+[^[:space:]].* - .+ \([^)]+\)/) found = 1
      }
      else if (kind ~ /^snmp_enum_/) {
        # A populated field is evidence; headings such as "System information"
        # alone are not. Metasploit prints these as indented table rows.
        value=lower; sub(/^[^:]*:[[:space:]]*/, "", value); sub(/[[:space:]]+$/, "", value)
        found = lower ~ /^[[:space:]]*(hostname|description|contact|location|uptime (snmp|system))[[:space:]]*:[[:space:]]*[^[:space:]-]/ && value !~ /^(unknown|none|null|n\/a|not available|not provided|unavailable)$/
      }
      if (found) {
        endpoint = endpoint_from_message(line)
        if (kind ~ /^rdp_scanner_/) {
          payload=line; sub(/^.*Detected RDP on[[:space:]]+/, "", payload)
          if (endpoint != endpoint_from_message(payload)) next
        }
        if (endpoint == "" && kind ~ /^snmp_enum(shares)?_/) endpoint = context
        if (endpoint == "") next
        if (mode == "endpoints") {
          if (!seen[endpoint]++) print endpoint
        } else if (mode == "rows") print endpoint "\034" NR "\034" line
        else print line
      }
    }
  ' | if [[ "$mode" == endpoints ]]; then verified_ip_port_lines; else cat; fi
}

msf_failure_lines() {
  html_escape_stream < "$1" | awk '
    {
      lower = tolower($0)
      if (lower ~ /^[[:space:]]*resource[[:space:](]/ || lower ~ / => /) next
      if (lower ~ /auxiliary (failed|aborted)|failed to (load|execute|run).*module|unknown command|uninitialized constant|call stack:|(^|[^a-z])(nameerror|nomethoderror|loaderror|syntaxerror|runtimeerror|optionvalidateerror|msf::optionvalidateerror)|exception|timed out|permission denied|operation not permitted|read-only file system|errno::eacces|errno::eperm/ ||
          (lower ~ /^\[-\]/ && lower ~ /unable to |connection (refused|reset)|unreachable|handshake failed|auth negotiation failed|parsing error|unknown error/)) print
    }
  '
}

append_msf_failed_artifacts() {
  local outfile="$1" file failures temp_file label status
  temp_file="$(mktemp "${TMPDIR:-/tmp}/bident_msf_failed.XXXXXX")"
  for file in "${MSF_RESULT_DIR}"/*.txt "${MSF_DIR}/msfconsole.log"; do
    [[ -s "$file" ]] || continue
    failures="$(msf_failure_lines "$file")"
    [[ -n "$failures" ]] || continue
    {
      printf '    <details class="artifact artifact-group"><summary>%s — Failed / incomplete</summary>\n' "$(html_escape_text "$(default_result_label "$file")")"
      printf '      <p><a href="%s">Full execution log</a></p>\n' "$(html_escape_text "$file")"
      printf '      <pre>%s</pre>\n' "$failures"
      printf '    </details>\n'
    } >> "$temp_file"
  done
  if [[ -s "${MSF_DIR}/run_status.tsv" ]]; then
    while IFS=$'\t' read -r label status; do
      [[ "$status" == 0 ]] && continue
      printf '    <p>%s: Failed / incomplete (exit %s). <a href="%s">Execution log</a></p>\n' \
        "$(html_escape_text "$label")" "$(html_escape_text "$status")" "$(html_escape_text "${MSF_DIR}/msfconsole.log")" >> "$temp_file"
    done < "${MSF_DIR}/run_status.tsv"
  fi
  if [[ -s "$temp_file" ]]; then
    {
      printf '  <details class="artifact artifact-group"><summary>Metasploit Failed / Incomplete Checks</summary>\n'
      cat "$temp_file"
      printf '  </details>\n'
    } >> "$outfile"
  fi
  rm -f "$temp_file"
}

ftp_anonymous_nse_lines() {
  local file="$1" mode="${2:-rows}"
  html_escape_stream < "$file" | awk -v mode="$mode" '
    function flush(key) {
      if (host != "" && port != "" && evidence != "" && !failed) {
        key=(host ~ /:/ ? "[" host "]" : host) ":" port
        if (mode == "endpoints") print key
        else if (mode == "rows") print key "\034" evidence_nr "\034" evidence
        else print evidence
      }
      evidence=""; failed=0; active=0
    }
    /^Nmap scan report for / {flush(); host=$NF; gsub(/[()]/,"",host); port=""; next}
    /^[0-9]+\/(tcp|udp)[[:space:]]/ {
      flush(); port=""
      if ($0 ~ /^[0-9]+\/tcp[[:space:]]+open[[:space:]]/) {port=$1; sub(/\/.*/,"",port)}
      next
    }
    /^Host script results:|^===== |^Command:/ {flush(); host=""; port=""; next}
    {
      original=$0; text=$0; sub(/^\|[_ ]*/,"",text)
      lower=tolower(text)
      if (lower ~ /^ftp-anon:/) {flush(); active=1}
      else if (lower ~ /^[a-z0-9_-]+:/ && lower !~ /^error:/) {flush()}
      if (active && lower ~ /^ftp-anon:[[:space:]]*anonymous ftp login allowed[[:space:]]*\(ftp code 230\)/) {evidence=original; evidence_nr=NR}
      if (active && lower ~ /error:|script execution failed|timed out|login denied|not allowed/) failed=1
    }
    END {flush()}
  ' | if [[ "$mode" == endpoints ]]; then verified_ip_port_lines; else cat; fi
}

finding_source_lines() {
  if [[ "$1" == "${NSE_DIR}/s_ftp.txt" ]]; then ftp_anonymous_nse_lines "$@"
  else msf_finding_lines "$@"; fi
}

append_finding_glob_item() {
  local outfile="$1"
  local severity="$2"
  local title="$3"
  local source_pattern="$4"
  local detail="${5:-}"
  local source_file nse_source=""
  if [[ "$title" == "FTP Anonymous Enabled" ]]; then nse_source="${NSE_DIR}/s_ftp.txt"; fi
  local files=()
  local count=0
  local evidence_count endpoints="" file_endpoints evidence_rows endpoint evidence_line evidence_text

  for source_file in $source_pattern "$nse_source"; do
    [[ -s "$source_file" ]] || continue
    evidence_count="$(finding_source_lines "$source_file" | awk 'END {print NR + 0}')"
    [[ "$evidence_count" -gt 0 ]] || continue
    file_endpoints="$(finding_source_lines "$source_file" endpoints)"
    [[ -n "$file_endpoints" ]] || continue
    endpoints="${endpoints}${file_endpoints}"$'\n'
    files+=("$source_file")
    count=$((count + evidence_count))
  done

  [[ "${#files[@]}" -gt 0 ]] || return 0
  endpoints="$(printf '%s' "$endpoints" | sort -u)"

  {
    printf '    <li><details class="finding-panel">\n'
    printf '      <summary><div><strong>%s</strong>\n' "$(html_escape_text "$title")"
    printf '        <span>%s affected host(s)</span>\n' "$(printf '%s\n' "$endpoints" | awk 'NF {n++} END {print n+0}')"
    printf '      </div></summary>\n'
    append_affected_endpoint_list "$endpoints"
    evidence_rows="$(mktemp "${TMPDIR:-/tmp}/bident_msf_evidence.XXXXXX")"
    for source_file in "${files[@]}"; do
      while IFS=$'\034' read -r endpoint evidence_line evidence_text; do
        printf '%s\034\034%s:%s\034%s\n' "$endpoint" "$source_file" "$evidence_line" "$evidence_text" >> "$evidence_rows"
      done < <(finding_source_lines "$source_file" rows)
    done
    append_finding_full_evidence "$evidence_rows" "$endpoints" true
    rm -f "$evidence_rows"
    printf '    </details></li>\n'
  } >> "$outfile"
}

credential_candidate_lines() {
  local file="$1" msf_port=""
  if [[ "$file" =~ _(tcp|udp)_([0-9]+)[.]txt$ ]]; then msf_port="${BASH_REMATCH[2]}"; fi

  awk -v msf_port="$msf_port" '
    BEGIN { esc = sprintf("%c", 27) }
    function endpoint(ip, port) {
      if (ip == "" || port == "") return ""
      return (ip ~ /:/ && ip !~ /^\[/ ? "[" ip "]" : ip) ":" port
    }

    function trim(value) {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      return value
    }
    function is_credential_line(value, lowered, field, token) {
      lowered = tolower(value)
      if (lowered ~ /^\[-\]/) return 0
      sub(/^\|[_ ]*[[:space:]]*/, "", lowered)
      sub(/^\[[+*!-]\][[:space:]]*/, "", lowered)
      sub(/^([0-9.]+|\[[0-9a-f:]+\]):[0-9]+[[:space:]]+(-[[:space:]]+)?/, "", lowered)
      sub(/^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+[[:space:]]+(-[[:space:]]+)?/, "", lowered)
      # Rejected attempts and diagnostic/help text are not discoveries.
      if (lowered ~ /^(error|warning|usage|example|command|debug|failed|invalid|testing|trying|attempting)([[:space:]:]|$)/ ||
          lowered ~ /(login|authentication|access)[[:space:]]+(failed|failure|denied|disabled|not allowed)/ ||
          lowered ~ /(invalid|incorrect|rejected)[[:space:]]+(credentials|password)|credentials[[:space:]]+(invalid|rejected|not found)/ ||
          lowered ~ /(no|not)[[:space:]]+(valid[[:space:]]+)?credentials/ ||
          lowered ~ /status_logon_failure|nt_status_logon_failure/) return 0

      # NSE brute scripts report successful pairs without a username label.
      # Accept the explicit success suffix, never an unlabelled wordlist pair.
      if (lowered ~ /^[^[:space:]:<>=]+:[^[:space:]].*[[:space:]]+-[[:space:]]+valid credentials[.!]?[[:space:]]*$/ && lowered !~ /:.*(<unknown>|\[redacted\]|[*][*][*])/) return 1

      # Require an actual field, rather than a URL parameter, script name,
      # NTLM domain metadata, or a mention of credential terminology.
      if (lowered ~ /^(user(name)?|login|account|acct|password|passwd|pwd|credential|credentials|hash|secret|token)[[:space:]]*[:=]/) {
        field = lowered
        sub(/[:=].*$/, "", field)
        token = lowered
        sub(/^[^:=]*[:=][[:space:]]*/, "", token)
        sub(/[[:space:],;].*$/, "", token)
        if (token == "" || token ~ /^(none|null|nil|n\/a|unknown|redacted|disabled|required|not|false|true|\*+|x{4,}|<[^>]*>|\[[^]]*\])$/) return 0
        return 1
      }
      if (lowered ~ /^(ftp-anon:[[:space:]]*)?anonymous[[:space:]_-]*(login|access|ftp).*(allowed|enabled|successful)/ ||
          lowered ~ /^(valid[[:space:]_-]+credentials[[:space:]]*[:=]|login successful[[:space:]:]|authentication successful([[:space:]:]|$)|empty[[:space:]_-]+password.*(allowed|enabled|found)|default[[:space:]_-]+credentials.*(found|valid|accepted))/) return 1
      return 0
    }
    {
      line = trim($0)
      gsub(esc "\\[[0-?]*[ -/]*[@-~]", "", line)
      gsub(/\[[0-9;]*m/, "", line)
      found_endpoint = ""
      if (line ~ /^Nmap scan report for /) {
        host = $NF; gsub(/[()]/, "", host); port = ""; in_mysql_users = 0; next
      }
      if (line ~ /^[0-9]+\/(tcp|udp)[[:space:]]/) {
        port = ""; in_mysql_users = 0
        if (line ~ /^[0-9]+\/(tcp|udp)[[:space:]]+open[[:space:]]/) {port = $1; sub(/\/.*/, "", port)}
        next
      }
      if (line ~ /^Host script results:/) { port = ""; in_mysql_users = 0; next }
      if (line ~ /^===== / || line ~ /^Command:/ || line ~ /^#/ || line ~ /^resource[[:space:](]/) {
        host = ""; port = ""; in_mysql_users = 0
        next
      }
      # A result-line endpoint overrides any context. Never use IPs found
      # inside passwords, URLs, command echoes, or stack traces.
      if (line ~ /^\[[+*]\][[:space:]]+/) {
        peer = line; sub(/^\[[+*]\][[:space:]]+/, "", peer); sub(/[[:space:],].*$/, "", peer)
        if (peer ~ /^([0-9.]+|\[[0-9a-fA-F:]+\]):[0-9]+$/) found_endpoint = peer
        else if (peer ~ /^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+$/) found_endpoint = endpoint(peer, msf_port)
      } else if (line ~ /^SMB[[:space:]]+/) found_endpoint = endpoint($2, $3)
      else found_endpoint = endpoint(host, port)
      # Nmap headers and echoed invocations describe requested checks,
      # not discovered credentials (for example --script-args user=...).
      if (line ~ /^#/ || tolower(line) ~ /(^|[[:space:]])([^[:space:]]*\/)?nmap([[:space:]]|$)/) {
        in_mysql_users = 0
        next
      }
      if (line ~ /^\|[ _]*mysql-users:[[:space:]]*$/) {
        in_mysql_users = 1
        next
      }
      if (in_mysql_users) {
        # Only indented, single-name entries belong to this NSE list.
        # Stop at another script, host, port, or non-list output line.
        if (line ~ /^\|[_ ]?[[:space:]]+[^[:space:]:]+[[:space:]]*$/) {
          username = line
          sub(/^\|[_ ]?[[:space:]]+/, "", username)
          username = trim(username)
          print NR "\034" line "\034username: " username "\034" found_endpoint
          if (line ~ /^\|_/) in_mysql_users = 0
          next
        }
        in_mysql_users = 0
      }
      if (line != "" && is_credential_line(line)) {
        print NR "\034" line "\034\034" found_endpoint
      }
    }
  ' "$file"
}

credential_candidate_count() {
  local file
  local total_count=0

  for file in "${NSE_DIR}"/*.txt "${TOOL_DIR}"/*.txt "${MSF_RESULT_DIR}"/*.txt; do
    [[ -s "$file" ]] || continue
    total_count=$((total_count + $(credential_candidate_lines "$file" | awk 'END {print NR + 0}')))
  done

  printf '%s' "$total_count"
}

append_tls_findings_summary() {
  local outfile="$1" rows_file file kind id title detail endpoints endpoint source_line evidence known source_name cipher_detail evidence_rows
  local now_utc
  now_utc="$(date -u '+%Y%m%d%H%M%S')"
  rows_file="$(mktemp "${TMPDIR:-/tmp}/bident_tls_findings.XXXXXX")"
  for kind in testssl sslscan nse; do
    case "$kind" in
      testssl) file="${TOOL_DIR}/testssl_results.txt" ;;
      sslscan) file="${TOOL_DIR}/sslscan_results.txt" ;;
      nse) file="${NSE_DIR}/ssl_tls_results.txt" ;;
    esac
    [[ -s "$file" ]] || continue
    awk -v kind="$kind" -v now_utc="$now_utc" -f "${BIDENT_ROOT}/lib/tls_findings.awk" "$file" \
      | awk -F '\034' -v source_file="$file" 'BEGIN {OFS="\034"} {print $1,$2,source_file ":" $3,$4,$5}' >> "$rows_file"
  done
  for id in 1 2 3 4 5 6 7 8 9 10; do
    case "$id" in
      1) title='SSLv2 Enabled' ;;
      2) title='SSLv3 Enabled' ;;
      3) title='TLSv1.0 Enabled' ;;
      4) title='TLSv1.1 Enabled' ;;
      5) title='TLSv1.3 Disabled' ;;
      6) title='Weak SSL/TLS Ciphers' ;;
      7) title='HTTP Compression Enabled (BREACH Vulnerability)' ;;
      8) title='Wildcard SSL Certificates in Use' ;;
      9) title='SSL Certificate Using Weak Hashing Algorithm' ;;
      10) title='Expired SSL Certificate' ;;
    esac
    endpoints="$(awk -F '\034' -v wanted="$id" '
      $1 == 11 {supported[$2] = 1}
      $1 == wanted {candidate[$2] = 1}
      END {for (endpoint in candidate) if (wanted != 5 || !supported[endpoint]) print endpoint}
    ' "$rows_file" | verified_ip_port_lines | sort -u)"
    [[ -n "$endpoints" ]] || continue
    detail='Explicit tool results tied to the listed endpoints. Review the evidence before remediation.'
    case "$id" in
      5) detail='The tool explicitly reports TLS 1.3 unavailable on a working TLS service. Inconclusive tests, client capability warnings, and contradictory TLS 1.3 successes are excluded.' ;;
      6) detail='Accepted weak cipher suites or an explicitly offered weak cipher category; rejected suites are excluded.' ;;
      7) detail='HTTP compression was observed on the tested response. This is potential BREACH exposure; exploitability depends on application secrets and attacker-controlled input.' ;;
      8) detail='A wildcard name was observed in the served certificate. Wildcard use alone does not establish a vulnerability.' ;;
      9) detail='The served certificate signature uses SHA-1, MD5, or MD2. Cipher-suite MACs and certificate fingerprints are excluded.' ;;
      10) detail='The served certificate expiry date is before today (UTC). Certificates expiring today, unknown dates, chain-only dates, and contradictory unexpired dates for the same certificate are excluded.' ;;
    esac
    {
      printf '    <li><details class="finding-panel">\n'
      printf '      <summary><div><strong>%s</strong><span>%s affected host(s)</span></div></summary>\n' "$(html_escape_text "$title")" "$(printf '%s\n' "$endpoints" | awk 'END {print NR}')"
      if [[ "$id" != 6 ]]; then append_affected_endpoint_list "$endpoints"; fi
      evidence_rows="$(mktemp "${TMPDIR:-/tmp}/bident_tls_evidence.XXXXXX")"
      while IFS=$'\034' read -r known endpoint source_line evidence cipher_detail; do
        [[ "$known" == "$id" ]] || continue
        printf '%s\034%s\034%s\034%s\n' "$endpoint" "$cipher_detail" "$source_line" "$evidence" >> "$evidence_rows"
      done < "$rows_file"
      if [[ "$id" == 6 ]]; then
        append_tls_cipher_table "$evidence_rows" "$endpoints"
        append_finding_full_evidence "$evidence_rows" "$endpoints" false true
      else append_finding_full_evidence "$evidence_rows" "$endpoints"; fi
      rm -f "$evidence_rows"
      printf '    </details></li>\n'
    } >> "$outfile"
  done
  rm -f "$rows_file"
}

print_report_section_heading() {
  local title="$1" expand_id="$2" collapse_id="$3" status_id="$4" scope="$5" count="${6:-0}"
  printf '<div class="section-heading"><h2>%s <span class="section-count" aria-label="%s %s">%s</span></h2><nav class="report-controls" aria-label="%s controls">' "$(html_escape_text "$title")" "$count" "$scope" "$count" "$(html_escape_text "$scope")"
  printf '<button class="report-toggle" id="%s" type="button" title="Expand all %s" aria-label="Expand all %s"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m8 7 4-4 4 4M4 10h16M4 14h16m-12 3 4 4 4-4"/></svg></button>' "$expand_id" "$scope" "$scope"
  printf '<button class="report-toggle" id="%s" type="button" title="Collapse all %s" aria-label="Collapse all %s"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m8 3 4 4 4-4M4 10h16M4 14h16m-12 7 4-4 4 4"/></svg></button></nav></div><span class="report-toggle-status" id="%s" role="status" aria-live="polite"></span>\n' "$collapse_id" "$scope" "$scope" "$status_id"
}

append_findings_summary_section() {
  local outfile="$1"
  local temp_file

  temp_file="$(mktemp "${TMPDIR:-/tmp}/bident_findings.XXXXXX")"
  append_ssh_weak_cipher_finding "$temp_file"
  append_tls_findings_summary "$temp_file"
  append_finding_item "$temp_file" "Review" "Exposed RPC Services" "${TOOL_DIR}/s_rpcdump_135.txt"
  append_finding_item "$temp_file" "Review" "Unauthenticated Remote Procedure Call" "${TOOL_DIR}/s_rpcclient_135.txt"
  append_finding_item "$temp_file" "Review" "Misconfigured Server Message Block Signing" "${TOOL_DIR}/nxc_smb_signing_false.txt" "Possible Server Message Block (SMB) relay attack exposure."
  append_finding_item "$temp_file" "Review" "SMBv1 Enabled" "${TOOL_DIR}/nxc_smbv1_true.txt"
  append_finding_item "$temp_file" "Review" "LDAP Anonymous Bind" "${TOOL_DIR}/s_ldapsearch.txt"
  append_finding_item "$temp_file" "Review" "DNSSec Not Configured" "${TOOL_DIR}/dnssec_not_configured.txt"
  append_finding_item "$temp_file" "Review" "DNS Recursion Enabled" "${TOOL_DIR}/dns_recursion_enabled.txt"
  append_finding_item "$temp_file" "Review" "IKE VPN Peer Weak Encryption" "${TOOL_DIR}/ike_weak_encryption.txt"
  append_finding_glob_item "$temp_file" "Review" "FTP Anonymous Enabled" "${MSF_RESULT_DIR}/ftp_anonymous_tcp_*.txt"
  append_finding_glob_item "$temp_file" "Review" "SMTP Open Relay" "${MSF_RESULT_DIR}/smtp_relay_tcp_*.txt"
  append_finding_glob_item "$temp_file" "Review" "Server Message Block (SMB) MS17-010 (EternalBlue) Vulnerability" "${MSF_RESULT_DIR}/smb_ms17_010_tcp_*.txt"
  append_finding_glob_item "$temp_file" "Review" "Apache Tomcat AJP File Read (Ghostcat)" "${MSF_RESULT_DIR}/tomcat_ghostcat_tcp_8009.txt"
  append_finding_glob_item "$temp_file" "Review" "Remote Desktop Protocol Detection" "${MSF_RESULT_DIR}/rdp_scanner_tcp_*.txt"
  append_finding_glob_item "$temp_file" "Review" "Remote Desktop Protocol (RDP) BlueKeep Vulnerability" "${MSF_RESULT_DIR}/cve_2019_0708_bluekeep_tcp_*.txt"
  append_finding_glob_item "$temp_file" "Review" "Virtual Network Computing (VNC) None Authentication" "${MSF_RESULT_DIR}/vnc_none_auth_tcp_*.txt"
  append_finding_glob_item "$temp_file" "Review" "NetBIOS Information Disclosure" "${MSF_RESULT_DIR}/nbname_udp_137.txt"
  append_finding_glob_item "$temp_file" "Review" "SNMP Default/Weak Community String" "${MSF_RESULT_DIR}/snmp_login_udp_*.txt"
  append_finding_glob_item "$temp_file" "Review" "SNMP Information Disclosure" "${MSF_RESULT_DIR}/snmp_enum_udp_*.txt"
  append_finding_glob_item "$temp_file" "Review" "SNMP Users Enumeration" "${MSF_RESULT_DIR}/snmp_enumusers_udp_*.txt"
  append_finding_glob_item "$temp_file" "Review" "SNMP Shares Enumeration" "${MSF_RESULT_DIR}/snmp_enumshares_udp_*.txt"

  {
    printf '  <section class="report-section" id="findingsSummary" aria-label="Findings Summary">\n'
    print_report_section_heading 'Findings Summary' expandAll collapseAll reportToggleStatus findings "$(awk '/^[[:space:]]*<li><details class="finding-panel">/ {n++} END {print n+0}' "$temp_file")"
    printf '  <p class="muted">Review each finding and its full evidence carefully before taking action. Automated results may contain false positives.</p>\n'
    if [[ -s "$temp_file" ]]; then
      printf '  <ul class="finding-list">\n'
      cat "$temp_file"
      printf '  </ul>\n'
    else
      printf '  <div class="empty">No targeted findings were written by follow-up checks.</div>\n'
    fi
    printf '  </section>\n'
  } >> "$outfile"

  rm -f "$temp_file"
}

credential_display_value() {
  printf '%s\n' "$1" | awk '
    {
      line = $0
      sub(/^\|[_ ]*[[:space:]]*/, "", line)
      sub(/^\[[+*!-]\][[:space:]]*/, "", line)
      lower = tolower(line)
      if (lower ~ /^[^[:space:]:<>=]+:[^[:space:]].*[[:space:]]+-[[:space:]]+valid credentials[.!]?[[:space:]]*$/) {print line; next}
      if (lower ~ /^(user(name)?|login|account|acct|password|passwd|pwd|credential|credentials|hash|secret|token)[[:space:]]*[:=]/) {
        label = lower; sub(/[:=].*$/, "", label); sub(/[[:space:]]+$/, "", label)
        value = line; sub(/^[^:=]*[:=][[:space:]]*/, "", value)
        if (label == "acct") label = "account"
        if (label == "passwd" || label == "pwd") label = "password"
        print label ": " value
      } else if (match(lower, /login successful:[[:space:]]*/)) {
        print "credentials: " substr(line, RSTART + RLENGTH)
      } else print line
    }
  '
}

append_credential_summary_section() {
  local outfile="$1"
  local temp_file
  local file
  local file_label
  local line_number
  local line_text
  local display_value
  local total_count=0
  local max_items=80
  local endpoint endpoint_verified

  temp_file="$(mktemp "${TMPDIR:-/tmp}/bident_credentials.XXXXXX")"
  for file in "${NSE_DIR}"/*.txt "${TOOL_DIR}"/*.txt "${MSF_RESULT_DIR}"/*.txt; do
    [[ -s "$file" ]] || continue
    file_label="$(default_result_label "$file")"
    while IFS=$'\034' read -r line_number line_text display_value endpoint; do
      [[ -n "${line_text:-}" ]] || continue
      total_count=$((total_count + 1))
      [[ "$total_count" -le "$max_items" ]] || continue
      if [[ -z "$display_value" ]]; then
        display_value="$(credential_display_value "$line_text")"
      fi
      endpoint="$(printf '%s\n' "$endpoint" | verified_ip_port_lines)"
      endpoint_verified=false
      if [[ -n "$endpoint" ]]; then endpoint_verified=true; else endpoint='Not identified'; fi
      {
        printf '    <li data-credential-entry><details class="finding-panel">\n'
        printf '      <summary><div><strong class="credential-value">%s</strong><span>%s</span><p>%s:%s</p></div></summary>\n' \
          "$(html_escape_text "$display_value")" \
          "$(html_escape_text "$file_label")" \
          "$(html_escape_text "$file")" \
          "$(html_escape_text "$line_number")"
        printf '      <p>Found at: <span class="credential-endpoint" data-verified="%s">%s</span></p>\n' "$endpoint_verified" "$(html_escape_text "$endpoint")"
        printf '      <pre class="finding-evidence">%s</pre>\n' "$(html_escape_text "$line_text")"
        printf '    </details></li>\n'
      } >> "$temp_file"
    done < <(credential_candidate_lines "$file")
  done

  {
    printf '  <section class="report-section" data-credential-copy>\n'
    print_report_section_heading 'Discovered Usernames & Credentials' expandCredentials collapseCredentials credentialToggleStatus credentials "$(awk '/<li data-credential-entry>/ {n++} END {print n+0}' "$temp_file")"
    printf '  <p class="muted">Review each entry, its Host:Port, and the supporting output carefully. Enumerated usernames alone do not confirm valid credentials.</p>\n'
    if [[ -s "$temp_file" ]]; then
      printf '  <div class="copy-targets-toolbar"><button class="copy-targets copy-credentials" type="button" data-copy-mode="entries" title="Copy displayed username/credential entries with Host:Port, separated by tabs">Copy Credentials %s</button><button class="copy-targets copy-credentials" type="button" data-copy-mode="targets" title="Copy unique verified Host:Port values only">Copy Hosts %s</button><span class="copy-targets-status muted" role="status" aria-live="polite"></span></div>\n' "$(print_copy_icon)" "$(print_copy_icon)"
      printf '  <ul class="finding-list credential-list">\n'
      cat "$temp_file"
      printf '  </ul>\n'
      if [[ "$total_count" -gt "$max_items" ]]; then
        printf '  <p class="muted">Showing first %s of %s possible credential-related line(s).</p>\n' "$max_items" "$total_count"
      fi
    else
      printf '  <div class="empty">No username or credential-related lines were detected in saved result files.</div>\n'
    fi
    printf '  </section>\n'
  } >> "$outfile"

  rm -f "$temp_file"
}

append_per_host_summary_section() {
  local outfile="$1"
  local open_tsv="$2"

  printf '  <h2>Per-Host Summary</h2>\n' >> "$outfile"
  if [[ ! -s "$open_tsv" ]]; then
    printf '  <div class="empty">No per-host open-port summary is available.</div>\n' >> "$outfile"
    return
  fi

  {
    printf '  <div class="host-summary-grid">\n'
    awk -F '\t' '
      NR > 1 {
        host = $1
        entry = $3 "/" toupper($2)
        if (!seen[host, entry]++) {
          ports[host] = ports[host] ? ports[host] ", " entry : entry
        }
      }
      END {
        for (host in ports) {
          print host "\034" ports[host]
        }
      }
    ' "$open_tsv" | sort | while IFS=$'\034' read -r host ports; do
      [[ -n "${host:-}" ]] || continue
      printf '    <details class="artifact host-summary"><summary>%s</summary><pre>%s</pre></details>\n' "$(html_escape_text "$host")" "$(html_escape_text "$ports")"
    done
    printf '  </div>\n'
  } >> "$outfile"
}

normalize_service_name() {
  local proto="$1"
  local port="$2"
  local name="${3:-}"
  local lowered

  lowered="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')"

  case "${proto}/${port}" in
    tcp/443|tcp/8443)
      printf 'HTTPS'
      return
      ;;
    tcp/80|tcp/81|tcp/8000|tcp/8080)
      printf 'HTTP'
      return
      ;;
  esac

  case "$lowered" in
    ""|unknown)
      case "${proto}/${port}" in
        tcp/21) printf 'FTP' ;;
        tcp/22) printf 'SSH' ;;
        tcp/23) printf 'Telnet' ;;
        tcp/25|tcp/465|tcp/587) printf 'SMTP' ;;
        tcp/53|udp/53) printf 'DNS' ;;
        tcp/88) printf 'Kerberos' ;;
        tcp/110|tcp/995) printf 'POP3' ;;
        tcp/111|udp/111) printf 'RPCBind' ;;
        tcp/135) printf 'MSRPC' ;;
        udp/123) printf 'NTP' ;;
        udp/137) printf 'NetBIOS' ;;
        tcp/139|tcp/445) printf 'SMB' ;;
        udp/161|udp/162) printf 'SNMP' ;;
        tcp/389|tcp/636|tcp/3268|tcp/3269) printf 'LDAP' ;;
        udp/500) printf 'IKE' ;;
        udp/623) printf 'IPMI' ;;
        tcp/1433) printf 'MSSQL' ;;
        tcp/1521) printf 'Oracle' ;;
        tcp/2049) printf 'NFS' ;;
        tcp/3306) printf 'MySQL' ;;
        tcp/3389) printf 'RDP' ;;
        udp/5060) printf 'SIP' ;;
        tcp/5800|tcp/5801|tcp/5900|tcp/5901) printf 'VNC' ;;
        tcp/8009) printf 'AJP13' ;;
        *) printf 'Unknown' ;;
      esac
      ;;
    ssl\|http|ssl/http|https)
      printf 'HTTPS'
      ;;
    http|http*)
      printf 'HTTP'
      ;;
    ssh)
      printf 'SSH'
      ;;
    ftp)
      printf 'FTP'
      ;;
    smtp)
      printf 'SMTP'
      ;;
    dns|domain)
      printf 'DNS'
      ;;
    ntp)
      printf 'NTP'
      ;;
    msrpc)
      printf 'MSRPC'
      ;;
    ldap|ldapssl|ldaps)
      printf 'LDAP'
      ;;
    afp)
      printf 'AFP'
      ;;
    sip)
      printf 'SIP'
      ;;
    snmp|snmptrap)
      printf 'SNMP'
      ;;
    rpcbind)
      printf 'RPCBind'
      ;;
    nfs)
      printf 'NFS'
      ;;
    vnc)
      printf 'VNC'
      ;;
    irc)
      printf 'IRC'
      ;;
    ajp13|ajp)
      printf 'AJP13'
      ;;
    java-rmi)
      printf 'Java-RMI'
      ;;
    ms-sql*|mssql*)
      printf 'MSSQL'
      ;;
    mysql*)
      printf 'MySQL'
      ;;
    netbios*|netbios-ssn)
      printf 'NetBIOS'
      ;;
    microsoft-ds)
      printf 'SMB'
      ;;
    *)
      printf '%s' "$name" | awk '{print toupper(substr($0, 1, 1)) substr($0, 2)}'
      ;;
  esac
}

port_card_label() {
  local proto="$1"
  local port="$2"
  local services_tsv="$3"
  local name=""
  local proto_upper

  proto_upper="$(printf '%s' "$proto" | tr '[:lower:]' '[:upper:]')"
  if [[ -s "$services_tsv" ]]; then
    name="$(awk -F '\t' -v wanted_proto="$proto" -v wanted_port="$port" '
      NR > 1 && $2 == wanted_proto && $3 == wanted_port && $4 != "" {
        print $4
        exit
      }
    ' "$services_tsv")"
  fi

  printf '%s/%s (%s)' "$port" "$proto_upper" "$(normalize_service_name "$proto" "$port" "$name")"
}

append_port_result_files() {
  local outfile="$1"
  local proto="$2"
  local port="$3"
  local appended=1

  case "${proto}/${port}" in
    tcp/21) append_result_file_section "$outfile" s_ftp.txt && appended=0 ;;
    tcp/22)
      append_result_file_section "$outfile" s_ssh.txt && appended=0
      append_result_file_section "$outfile" ssh-audit_results.txt "Weak SSH Ciphers" && appended=0
      ;;
    tcp/23) append_result_file_section "$outfile" s_telnet.txt && appended=0 ;;
    tcp/25) append_result_file_section "$outfile" s_smtp.txt && appended=0 ;;
    tcp/465|tcp/587)
      append_result_file_section "$outfile" s_smtp.txt && appended=0
      append_result_file_section "$outfile" ssl_tls_results.txt && appended=0
      append_ssl_external_result_files "$outfile" && appended=0
      ;;
    tcp/53|udp/53)
      append_result_file_section "$outfile" s_dns.txt && appended=0
      append_result_file_section "$outfile" dnssec_not_configured.txt && appended=0
      append_result_file_section "$outfile" dns_recursion_enabled.txt && appended=0
      ;;
    tcp/80|tcp/81|tcp/8000|tcp/8080)
      append_result_file_section "$outfile" s_http.txt && appended=0
      ;;
    tcp/443|tcp/8443)
      append_result_file_section "$outfile" s_http.txt "HTTPS NMAP Results" && appended=0
      append_result_file_section "$outfile" ssl_tls_results.txt && appended=0
      append_ssl_external_result_files "$outfile" && appended=0
      ;;
    tcp/8009) append_result_file_section "$outfile" s_ajp.txt && appended=0 ;;
    tcp/88) append_result_file_section "$outfile" s_kerberos.txt && appended=0 ;;
    tcp/110)
      append_result_file_section "$outfile" s_pop3.txt && appended=0
      ;;
    tcp/995)
      append_result_file_section "$outfile" s_pop3.txt && appended=0
      append_result_file_section "$outfile" ssl_tls_results.txt && appended=0
      append_ssl_external_result_files "$outfile" && appended=0
      ;;
    tcp/993)
      append_result_file_section "$outfile" ssl_tls_results.txt && appended=0
      append_ssl_external_result_files "$outfile" && appended=0
      ;;
    tcp/111|udp/111) append_result_file_section "$outfile" s_rpcbind.txt && appended=0 ;;
    tcp/135)
      append_result_file_section "$outfile" s_rpcdump_135.txt "Exposed RPC Services" && appended=0
      append_result_file_section "$outfile" s_rpcclient_135.txt "Unauthenticated Remote Procedure Call" && appended=0
      ;;
    udp/123) append_result_file_section "$outfile" s_ntp.txt && appended=0 ;;
    udp/137) append_result_file_section "$outfile" s_netbios.txt && appended=0 ;;
    tcp/139|tcp/445)
      append_result_file_section "$outfile" s_smb.txt && appended=0
      append_result_file_section "$outfile" nxc_smb_signing_false.txt "Misconfigured Server Message Block Signing" && appended=0
      append_result_file_section "$outfile" nxc_smbv1_true.txt "SMBv1 Enabled" && appended=0
      ;;
    udp/161|udp/162) append_result_file_section "$outfile" s_snmp.txt && appended=0 ;;
    tcp/389|tcp/3268)
      append_result_file_section "$outfile" s_ldap.txt && appended=0
      append_result_file_section "$outfile" s_ldapsearch.txt "LDAP Anonymous Bind" && appended=0
      ;;
    tcp/636|tcp/3269)
      append_result_file_section "$outfile" s_ldap.txt && appended=0
      append_result_file_section "$outfile" s_ldapsearch.txt "LDAP Anonymous Bind" && appended=0
      append_result_file_section "$outfile" ssl_tls_results.txt && appended=0
      append_ssl_external_result_files "$outfile" && appended=0
      ;;
    udp/500)
      append_result_file_section "$outfile" s_ike.txt && appended=0
      append_result_file_section "$outfile" ike_weak_encryption.txt && appended=0
      ;;
    udp/623) append_result_file_section "$outfile" s_ipmi.txt && appended=0 ;;
    tcp/1433) append_result_file_section "$outfile" db_mssql.txt && appended=0 ;;
    tcp/1521) append_result_file_section "$outfile" s_oracle.txt && appended=0 ;;
    tcp/2049) append_result_file_section "$outfile" s_nfs.txt && appended=0 ;;
    tcp/3306) append_result_file_section "$outfile" db_mysql.txt && appended=0 ;;
    tcp/3389)
      append_result_file_section "$outfile" s_rdp.txt && appended=0
      append_result_file_section "$outfile" ssl_tls_results.txt && appended=0
      append_ssl_external_result_files "$outfile" && appended=0
      ;;
    udp/5060) append_result_file_section "$outfile" s_sip.txt && appended=0 ;;
    tcp/5800|tcp/5801|tcp/5900|tcp/5901) append_result_file_section "$outfile" s_vnc.txt && appended=0 ;;
  esac

  append_msf_result_files "$outfile" "$proto" "$port" && appended=0
  [[ "$appended" -eq 0 ]] || append_base_scan_port_evidence "$outfile" "$proto" "$port"
}

generate_html_report() {
  local report_file="report.html"
  local open_tsv="targets_with_open_ports/open_ports_all.tsv"
  local services_tsv="targets_with_open_ports/services.tsv"
  local scope_count=0
  local live_count=0
  local open_rows=0
  local service_rows=0
  local generated_at
  local key
  local proto
  local port
  local previous_key=""
  local previous_proto=""
  local previous_port=""
  local first_group=true
  local display_label=""

  [[ -f "$TARGETS_FILE" ]] && scope_count="$(wc -l < "$TARGETS_FILE" | tr -d '[:space:]')"
  [[ -f "$LIVE_TARGETS_FILE" ]] && live_count="$(wc -l < "$LIVE_TARGETS_FILE" | tr -d '[:space:]')"
  if [[ -f "$open_tsv" ]]; then
    open_rows="$(awk 'NR > 1 {count++} END {print count + 0}' "$open_tsv")"
  fi
  if [[ -f "$services_tsv" ]]; then
    service_rows="$(awk 'NR > 1 {count++} END {print count + 0}' "$services_tsv")"
  fi
  generated_at="$(date '+%Y-%m-%d %H:%M:%S %Z')"

  {
    cat <<'HTML'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Bident Network Security Assessment Report</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #eef4ff;
      --bg-accent: #f7fbff;
      --panel: #ffffff;
      --text: #18202a;
      --muted: #657080;
      --line: #cfd9ea;
      --accent: #2457c5;
      --accent-2: #0f9f8f;
      --accent-3: #d97706;
      --chip: #e8f0ff;
      --chip-text: #153f9f;
      --code-bg: #101827;
      --code-text: #e5eefc;
      --shadow: 0 12px 30px rgba(31, 65, 120, 0.10);
    }
    [data-theme="dark"] {
      color-scheme: dark;
      --bg: #0c1220;
      --bg-accent: #111a2d;
      --panel: #151f33;
      --text: #edf4ff;
      --muted: #9fb0c9;
      --line: #2a3954;
      --accent: #6ea8ff;
      --accent-2: #39d5c4;
      --accent-3: #f7b955;
      --chip: #1d345d;
      --chip-text: #bfdbff;
      --code-bg: #070b12;
      --code-text: #e7edf7;
      --shadow: 0 12px 30px rgba(0, 0, 0, 0.28);
    }
    body {
      margin: 0;
      background:
        radial-gradient(circle at top left, color-mix(in srgb, var(--accent) 18%, transparent), transparent 34rem),
        linear-gradient(135deg, var(--bg), var(--bg-accent));
      color: var(--text);
      font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      min-height: 100vh;
    }
    main {
      max-width: 1180px;
      margin: 0 auto;
      padding: 32px 20px 56px;
    }
    h1, h2, h3 {
      line-height: 1.2;
      margin: 0;
    }
    h1 {
      font-size: clamp(22px, 2.4vw, 28px);
      margin-bottom: 6px;
    }
    h2 {
      font-size: 20px;
      margin-top: 30px;
      margin-bottom: 12px;
    }
    h3 {
      font-size: 16px;
      margin-bottom: 10px;
    }
    .muted {
      color: var(--muted);
    }
    .report-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 18px;
      margin-bottom: 20px;
    }
    .brand {
      align-items: center;
      display: flex;
      gap: 14px;
    }
    .report-mark {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      flex: 0 0 auto;
      height: 72px;
      padding: 8px;
      width: 62px;
    }
    .copy-targets-toolbar {
      align-items: center;
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      padding: 14px;
      margin: 0;
    }
    .copy-icon { width: 17px; height: 17px; flex: 0 0 17px; }
    .copy-targets, .report-toggle {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      background: var(--panel);
      border: 1px solid var(--accent);
      border-radius: 6px;
      color: var(--accent);
      cursor: pointer;
      font: inherit;
      font-weight: 700;
      padding: 6px 12px;
    }
    .copy-targets:hover,
    .copy-targets:focus-visible,
    .report-toggle:hover,
    .report-toggle:focus-visible {
      background: color-mix(in srgb, var(--accent) 12%, var(--panel));
      outline: 2px solid var(--accent);
      outline-offset: 2px;
    }
    details[data-affected-targets] > .copy-targets-toolbar {
      padding: 14px;
    }
    .copy-targets-status {
      font-size: 12px;
      min-width: 0;
      overflow-wrap: anywhere;
    }
    .theme-toggle {
      align-items: center;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: var(--panel);
      color: var(--text);
      cursor: pointer;
      display: inline-flex;
      font-size: 18px;
      height: 42px;
      justify-content: center;
      line-height: 1;
      padding: 0;
      box-shadow: var(--shadow);
      white-space: nowrap;
      width: 42px;
    }
    .theme-toggle:hover {
      border-color: var(--accent);
    }
    .notice {
      background: color-mix(in srgb, var(--accent-3) 12%, var(--panel));
      border: 1px solid color-mix(in srgb, var(--accent-3) 45%, var(--line));
      border-left: 5px solid var(--accent-3);
      border-radius: 8px;
      box-shadow: var(--shadow);
      margin: 24px 0 0;
      padding: 14px 16px;
    }
    .notice strong {
      display: block;
      margin-bottom: 4px;
    }
    .notice .disclaimer-heading { display: flex; align-items: center; gap: 8px; }
    .disclaimer-icon { width: 18px; height: 18px; flex: 0 0 18px; color: var(--accent-3); }
    .notice.disclaimer {
      background: #2e2514;
      border: 1px solid #b88320;
      border-left-width: 5px;
      color: #ffdda6;
    }
    .notice.disclaimer p, .notice.disclaimer .disclaimer-icon { color: inherit; }
    .notice p {
      margin: 0;
      color: var(--muted);
    }
    .notice[aria-label="Scan details"] {
      background: var(--panel);
      border: 1px solid var(--line);
      box-shadow: none;
    }
    .notice[aria-label="Scan details"] h2 { color: var(--text); }
    .notice[aria-label="Scan details"] .metric {
      background: transparent;
      border: 1px solid var(--line);
      box-shadow: none;
    }
    .notice[aria-label="Scan details"] .metric-time strong {
      font-size: 15px;
      line-height: 1.5;
      overflow-wrap: anywhere;
    }
    .notice[aria-label="Scan details"] .metrics { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .notice[aria-label="Scan details"] .metric { min-width: 0; }
    @media (max-width: 650px) {
      .notice[aria-label="Scan details"] .metrics { gap: 8px; }
      .notice[aria-label="Scan details"] .metric { padding: 10px 8px; }
      .notice[aria-label="Scan details"] .metric-time strong { font-size: 12px; }
      .notice[aria-label="Scan details"] .metric span { font-size: 11px; overflow-wrap: anywhere; }
    }
    .notice[aria-label="Scan details"] .metric > span { display: block; margin-bottom: 8px; }
    details > summary {
      list-style: none;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    details > summary::-webkit-details-marker { display: none; }
    details > summary::marker { content: ""; }
    details > summary::after {
      content: "+";
      color: var(--accent);
      font: 700 20px/1 monospace;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 20px;
      height: 20px;
      flex: 0 0 20px;
      margin-left: auto;
      align-self: center;
    }
    details[open] > summary::after { content: "−"; }
    .port-summary > .port-title { flex: 1; }
    .section-heading {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      margin: 24px 0 12px;
    }
    .section-heading h2 { margin: 0; min-width: 0; }
    .section-count { color: var(--muted); font-size: 0.8em; font-weight: 600; white-space: nowrap; margin-left: 6px; }
    #findingsSummary .section-count,
    [data-credential-copy] .section-count {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 24px;
      height: 24px;
      box-sizing: border-box;
      padding: 0;
      border: 1px solid var(--line);
      border-radius: 50%;
      background: var(--chip);
      color: var(--chip-text);
      font-size: 12px;
      font-weight: 700;
      line-height: 1.3;
      vertical-align: middle;
      position: relative;
      top: -2px;
    }
    .report-controls { display: flex; align-items: center; gap: 8px; flex: 0 0 auto; }
    .report-toggle {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 42px;
      height: 42px;
      padding: 9px;
      border-color: var(--line);
      border-radius: 12px;
      color: var(--text);
    }
    .report-toggle svg { width: 22px; height: 22px; }
    .report-toggle-status {
      position: absolute;
      width: 1px;
      height: 1px;
      overflow: hidden;
      clip-path: inset(50%);
      white-space: nowrap;
    }
    .report-footer {
      border-top: 1px solid var(--line);
      color: var(--muted);
      display: flex;
      flex-wrap: wrap;
      gap: 8px 16px;
      justify-content: center;
      text-align: center;
      flex-direction: column;
      align-items: center;
      margin-top: 28px;
      padding-top: 14px;
      font-size: 12px;
    }
    .report-footer strong {
      color: var(--text);
    }
    .metrics {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 12px;
      margin: 24px 0;
    }
    .metric, .port-card, .artifact, .empty {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }
    .metric {
      padding: 14px 16px;
      border-top: 4px solid var(--accent);
    }
    .metric:nth-child(2) {
      border-top-color: var(--accent-2);
    }
    .metric:nth-child(3) {
      border-top-color: var(--accent-3);
    }
    .metric strong {
      display: block;
      font-size: 26px;
      line-height: 1;
      margin-bottom: 6px;
    }
    .summary-grid {
      display: grid;
      gap: 10px;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      margin-bottom: 18px;
    }
    .summary-card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      padding: 12px 14px;
    }
    .summary-card span {
      color: var(--muted);
      display: block;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0;
      margin-bottom: 5px;
      text-transform: uppercase;
    }
    .summary-card strong {
      display: block;
      font-size: 14px;
      line-height: 1.35;
      overflow-wrap: anywhere;
    }
    .finding-list {
      display: grid;
      gap: 8px;
      list-style: none;
      margin: 0 0 18px;
      padding: 0;
    }
    .finding-list li {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      overflow: hidden;
    }
    .finding-panel > summary {
      align-items: flex-start;
      cursor: pointer;
      display: flex;
      gap: 10px;
      list-style: none;
      padding: 11px 12px;
    }
    .finding-panel > summary::-webkit-details-marker {
      display: none;
    }
    .finding-list strong,
    .finding-list span,
    .finding-list p {
      display: block;
    }
    .finding-list span {
      color: var(--muted);
      font-size: 12px;
      overflow-wrap: anywhere;
    }
    .finding-list p {
      color: var(--muted);
      margin: 5px 0 0;
    }

    .finding-panel > summary > div {
      min-width: 0;
      flex: 1;
    }
    .finding-panel > p {
      margin: 0;
      padding: 4px 16px 14px;
    }
    .finding-panel > p .credential-endpoint {
      display: inline;
      color: var(--text);
      font-size: inherit;
    }
    .finding-panel > .artifact,
    .finding-panel > [data-affected-targets] {
      margin: 0 16px 16px;
    }
    .finding-panel > div[data-affected-targets] > .copy-targets-toolbar {
      padding: 0 0 12px;
    }
    .finding-panel > .finding-evidence {
      margin: 0 16px 16px;
      border: 1px solid var(--line);
      border-radius: 6px;
    }
    [data-credential-copy] > .copy-targets-toolbar {
      padding: 0 0 14px;
    }
    .finding-evidence {
      border-top: 1px solid var(--line);
      margin: 0;
      max-height: 360px;
      overflow: auto;
      padding: 12px;
      background: var(--code-bg);
      color: var(--code-text);
      font: 12px/1.45 "SFMono-Regular", Consolas, monospace;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .finding-list .cipher-list {
      margin: 0;
      padding: 0;
      list-style: none;
    }
    .finding-list .cipher-list > li {
      background: transparent;
      border: 0;
      border-radius: 0;
      box-shadow: none;
      overflow: visible;
      padding: 2px 0;
      overflow-wrap: anywhere;
    }
    .credential-list {
      max-height: none;
      overflow: visible;
    }
    .host-summary-grid {
      display: grid;
      gap: 8px;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      margin-bottom: 18px;
    }
    .host-summary {
      box-shadow: var(--shadow);
      overflow: hidden;
    }
    .host-summary summary {
      color: var(--accent);
      cursor: pointer;
      font-weight: 800;
      padding: 10px 12px;
    }
    .host-summary pre {
      background: transparent;
      color: var(--text);
      font: 13px/1.5 "SFMono-Regular", Consolas, monospace;
      margin: 0;
      padding: 0 12px 12px;
      white-space: pre-wrap;
    }
    .port-card {
      margin-bottom: 5px;
      overflow: hidden;
    }
    .open-ports-wrap {
      max-height: min(620px, 64vh);
      overflow: auto;
      padding-right: 4px;
    }
    .open-ports-wrap .port-card:last-child {
      margin-bottom: 0;
    }
    .port-summary {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      cursor: pointer;
      list-style: none;
      padding: 7px 12px;
      min-height: 32px;
      border-left: 4px solid var(--accent);
      transition: background 160ms ease, border-color 160ms ease;
    }
    .port-summary::-webkit-details-marker {
      display: none;
    }
    .port-title {
      display: inline-flex;
      align-items: center;
      gap: 9px;
    }
    .port-summary strong {
      display: block;
      font-size: 13px;
      line-height: 1.2;
    }
    .port-card[open] .port-summary {
      background: color-mix(in srgb, var(--accent) 10%, transparent);
    }
    .badge {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 2px 8px;
      background: var(--chip);
      color: var(--chip-text);
      font-weight: 700;
      font-size: 11px;
      text-transform: uppercase;
    }
    .targets {
      background: transparent;
      color: var(--text);
      font: 14px/1.65 "SFMono-Regular", Consolas, monospace;
      margin: 0;
      padding: 0 14px 14px;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .table-tools {
      display: flex;
      justify-content: flex-end;
      margin: 0 0 10px;
    }
    .service-search {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      color: var(--text);
      font: inherit;
      max-width: 340px;
      padding: 10px 12px;
      width: 100%;
    }
    .service-search:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 18%, transparent);
      outline: none;
    }
    .service-table-wrap {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      max-height: min(560px, 58vh);
      overflow: auto;
    }
    .service-table {
      border-collapse: collapse;
      min-width: 860px;
      width: 100%;
    }
    .service-table th,
    .service-table td {
      border-bottom: 1px solid var(--line);
      padding: 10px 12px;
      text-align: left;
      vertical-align: top;
    }
    .service-table tbody tr:last-child td {
      border-bottom: 0;
    }
    .service-table tbody tr:hover {
      background: color-mix(in srgb, var(--accent) 8%, transparent);
    }
    .service-table th {
      background: color-mix(in srgb, var(--panel) 88%, var(--accent));
      box-shadow: 0 1px 0 var(--line);
      position: sticky;
      top: 0;
      z-index: 2;
    }
    .sort-button {
      align-items: center;
      background: transparent;
      border: 0;
      color: var(--text);
      cursor: pointer;
      display: inline-flex;
      font: inherit;
      font-weight: 800;
      gap: 6px;
      padding: 0;
    }
    .sort-button::after {
      color: var(--muted);
      content: "↕";
      font-size: 12px;
    }
    .sort-button[data-direction="asc"]::after {
      color: var(--accent);
      content: "↑";
    }
    .sort-button[data-direction="desc"]::after {
      color: var(--accent);
      content: "↓";
    }
    .service-table td:nth-child(4) {
      color: var(--muted);
      min-width: 240px;
    }
    .service-table td:nth-child(5) {
      font-family: "SFMono-Regular", Consolas, monospace;
      white-space: nowrap;
    }
    .table-tools {
      align-items: end;
      display: grid;
      gap: 10px;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      margin-bottom: 12px;
    }
    .service-search {
      grid-column: 1 / -1;
    }
    .service-filter {
      display: grid;
      gap: 5px;
    }
    .service-filter label {
      color: var(--muted);
      font-size: 11px;
      font-weight: 800;
      text-transform: uppercase;
    }
    .service-filter select,
    .service-search {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      color: var(--text);
      font: inherit;
      min-width: 0;
      padding: 10px 12px;
    }
    li {
      break-inside: avoid;
    }
    details.artifact {
      overflow: hidden;
      transition: border-color 160ms ease, background 160ms ease;
    }
    details.artifact[open] {
      border-color: color-mix(in srgb, var(--accent) 45%, var(--line));
    }
    details.artifact > summary {
      overflow-wrap: anywhere;
      cursor: pointer;
      padding: 12px 14px;
      font-weight: 700;
      color: var(--accent);
      background: color-mix(in srgb, var(--panel) 92%, var(--accent));
    }
    details.artifact[open] > summary {
      border-bottom: 1px solid var(--line);
    }
    .evidence-source { padding: 10px 14px; overflow-wrap: anywhere; }
    .artifact-file {
      color: var(--muted);
      font-size: 12px;
      font-weight: 600;
      margin-left: 8px;
    }
    .port-host-list {
      margin: 14px 16px;
    }
    .port-host-list > .copy-targets-toolbar {
      padding: 0 0 12px;
    }
    .port-card > .artifact {
      margin: 14px 16px;
      border: 1px solid var(--line);
      border-radius: 8px;
    }
    .port-card .targets {
      padding: 12px 14px;
    }
    .target-panel, .result-panel {
      margin: 10px 16px;
    }
    .result-panel + .result-panel {
      margin-top: 12px;
    }
    .target-panel .targets {
      padding-top: 0;
    }
    pre {
      margin: 0;
      padding: 12px;
      max-height: 520px;
      overflow: auto;
      background: var(--code-bg);
      color: var(--code-text);
      font: 12px/1.45 "SFMono-Regular", Consolas, monospace;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .file-list {
      display: block;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      margin: 0;
      padding: 12px;
      font: 14px/1.7 "SFMono-Regular", Consolas, monospace;
      white-space: pre-wrap;
    }
    .file-list a {
      display: block;
    }
    .core-artifacts {
      margin-top: 10px;
    }
    .artifact-group {
      box-shadow: none;
      margin: 10px 14px;
    }
    .artifact-group .file-list {
      border: 0;
      border-radius: 0;
      box-shadow: none;
      margin: 0;
    }
    .empty {
      padding: 14px 16px;
    }
    a {
      color: var(--accent);
      text-decoration: none;
    }
    a:hover {
      text-decoration: underline;
    }
    @media (max-width: 640px) {
      .report-header {
        align-items: stretch;
        flex-direction: column;
      }
      .brand {
        align-items: flex-start;
      }
      .theme-toggle {
        width: 100%;
      }
    }
    .report-header { align-items: center; flex-direction: row; }
    .brand { min-width: 0; flex: 1; }
    .brand > div { min-width: 0; }
    .theme-toggle { flex: 0 0 auto; width: 42px; height: 42px; }
    .report-section, .notice[aria-label="Scan details"] {
      padding: 20px; margin: 20px 0; border-radius: 12px;
      border: 1px solid var(--line);
      border-top: 5px solid #6ea8ff;
      background: var(--panel);
    }
    .report-section > h2, .report-section .section-heading h2,
    .notice[aria-label="Scan details"] h2 { color: var(--text); }
    @media (max-width: 640px) {
      .report-header { flex-direction: row; align-items: center; gap: 10px; }
      .theme-toggle { width: 42px; }
      .report-section, .notice[aria-label="Scan details"] { padding: 14px; }
    }
  </style>
</head>
<body>
<main>
HTML
    printf '  <header class="report-header">\n'
    printf '    <div class="brand">\n'
    printf '      <svg class="report-mark" viewBox="0 0 256 320" role="img" aria-label="Bident logo"><defs><linearGradient id="reportRedSteel" x1="0" x2="1" y1="0" y2="1"><stop offset="0" stop-color="#2a0202"/><stop offset="0.42" stop-color="#7b0d0d"/><stop offset="1" stop-color="#190101"/></linearGradient><linearGradient id="reportHandleSteel" x1="0" x2="1" y1="0" y2="1"><stop offset="0" stop-color="#111318"/><stop offset="0.5" stop-color="#3a3d43"/><stop offset="1" stop-color="#050608"/></linearGradient></defs><path d="M83 292h90l-14-92c28-21 51-58 48-113-2-36-13-66-31-87 2 48-6 91-23 128-9 20-18 34-25 43-7-9-16-23-25-43C86 91 78 48 80 0 62 21 51 51 49 87c-3 55 20 92 48 113L83 292z" fill="#07080b" stroke="#030303" stroke-width="7" stroke-linejoin="round"/><path d="M87 184c-18-16-31-46-27-91 2-21 8-40 18-56-4 36 2 72 16 105 7 17 16 32 26 45-12 1-23 0-33-3z" fill="url(#reportRedSteel)" stroke="#120101" stroke-width="5" stroke-linejoin="round"/><path d="M169 184c18-16 31-46 27-91-2-21-8-40-18-56 4 36-2 72-16 105-7 17-16 32-26 45 12 1 23 0 33-3z" fill="url(#reportRedSteel)" stroke="#120101" stroke-width="5" stroke-linejoin="round"/><path d="M111 300h34l-5-82h-24l-5 82z" fill="url(#reportHandleSteel)" stroke="#030303" stroke-width="6" stroke-linejoin="round"/><path d="M100 204c9 11 19 17 28 17s19-6 28-17c-7 33-16 51-28 51s-21-18-28-51z" fill="#300202" stroke="#090101" stroke-width="5" stroke-linejoin="round"/><g transform="translate(98 194)"><path d="M30 2c18 0 30 14 30 31 0 11-5 18-13 23v17H13V56C5 51 0 44 0 33 0 16 12 2 30 2z" fill="#efefef" stroke="#080808" stroke-width="6" stroke-linejoin="round"/><path d="M14 34c0-6 4-11 10-11 5 0 9 4 9 10 0 7-5 11-11 11-5 0-8-4-8-10z" fill="#050505"/><path d="M36 33c0-6 4-10 9-10 6 0 10 5 10 11 0 6-3 10-8 10-6 0-11-4-11-11z" fill="#050505"/><path d="M30 42l-7 11h14l-7-11z" fill="#050505"/><path d="M18 63h24" fill="none" stroke="#050505" stroke-width="5" stroke-linecap="round"/><path d="M22 57v16M30 56v17M38 57v16" fill="none" stroke="#050505" stroke-width="4" stroke-linecap="round"/></g><path d="M93 292h70" fill="none" stroke="#050505" stroke-width="12" stroke-linecap="round"/></svg>\n'
    printf '      <div>\n'
    printf '        <h1>Bident Network Security Assessment Report</h1>\n'
    printf '        <p class="muted">Generated %s</p>\n' "$(html_escape_text "$generated_at")"
    printf '      </div>\n'
    printf '    </div>\n'
    printf '    <button class="theme-toggle" type="button" id="themeToggle" aria-label="Toggle dark mode" title="Toggle theme">☾</button>\n'
    printf '  </header>\n'
    printf '  <section class="notice disclaimer">\n'
    printf '    <strong class="disclaimer-heading"><svg class="disclaimer-icon" aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path stroke-linejoin="round" d="M10.3 4.9a2 2 0 0 1 3.4 0l7.2 12.5a2 2 0 0 1-1.7 3H4.8a2 2 0 0 1-1.7-3z"/><path d="M12 9v4M12 17h.01"/></svg>Disclaimer</strong>\n'
    printf '    <p>Some findings may be false positives and should be manually validated before action is taken. Use this tool only for authorized and legal security testing. The owner of this script is not liable for illegal, unauthorized, or harmful use.</p>\n'
    printf '  </section>\n'
    printf '  <section class="notice" aria-label="Scan details">\n'
    printf '    <h2>Scan Details</h2>\n'
    printf '    <div class="metrics">\n'
    printf '    <div class="metric metric-time"><span>Start Time</span><strong>%s</strong></div>\n' "$(html_escape_text "${SCAN_STARTED_AT:-Unavailable}")"
    printf '    <div class="metric metric-time"><span>Finish Time</span><strong>%s</strong></div>\n' "$(html_escape_text "${SCAN_FINISHED_AT:-Unavailable}")"
    printf '    <div class="metric metric-time"><span>Run Time (HH:MM:SS)</span><strong>%s</strong></div>\n' "$(html_escape_text "${SCAN_RUNTIME:-Unavailable}")"
    printf '    <div class="metric"><span>Scoped Hosts</span><strong>%s</strong></div>\n' "$scope_count"
    printf '    <div class="metric"><span>Live Hosts</span><strong>%s</strong></div>\n' "$live_count"
    printf '    <div class="metric"><span>Total Ports Open</span><strong>%s</strong></div>\n' "$open_rows"
    printf '    </div>\n'
    printf '  </section>\n'
  } > "$report_file"

  printf '  <section class="report-section" aria-label="Services"><h2>Services</h2>\n' >> "$report_file"
  if [[ ! -s "$services_tsv" || "$service_rows" -eq 0 ]]; then
    printf '  <div class="empty">No services were confirmed.</div>\n' >> "$report_file"
  else
    {
      printf '  <div class="table-tools">\n'
      printf '    <input class="service-search" id="serviceSearch" type="search" placeholder="Search services..." aria-label="Search services">\n'
      printf '    <div class="service-filter"><label for="filterHost">Hosts</label><select id="filterHost" data-column="0"><option value="">All Hosts</option></select></div>\n'
      printf '    <div class="service-filter"><label for="filterPortProtocol">Port/Protocol</label><select id="filterPortProtocol" data-column="1"><option value="">All Port/Protocol</option></select></div>\n'
      printf '    <div class="service-filter"><label for="filterName">Name</label><select id="filterName" data-column="2"><option value="">All Names</option></select></div>\n'
      printf '    <div class="service-filter"><label for="filterInfo">Info</label><select id="filterInfo" data-column="3"><option value="">All Info</option></select></div>\n'
      printf '  </div>\n'
      printf '  <div class="service-table-wrap">\n'
      printf '    <table class="service-table" id="servicesTable">\n'
      printf '      <thead><tr>\n'
      printf '        <th><button class="sort-button" type="button" data-column="0">Hosts</button></th>\n'
      printf '        <th><button class="sort-button" type="button" data-column="1">Port/Protocol</button></th>\n'
      printf '        <th><button class="sort-button" type="button" data-column="2">Name</button></th>\n'
      printf '        <th><button class="sort-button" type="button" data-column="3">Info</button></th>\n'
      printf '        <th><button class="sort-button" type="button" data-column="4">Host:Port</button></th>\n'
      printf '      </tr></thead>\n'
      printf '      <tbody>\n'
    } >> "$report_file"
    while IFS=$'\034' read -r target proto port name info target_port; do
      [[ -n "${target:-}" ]] || continue
      printf '        <tr><td>%s</td><td>%s/%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
        "$(html_escape_text "$target")" \
        "$(html_escape_text "$port")" \
        "$(html_escape_text "$proto")" \
        "$(html_escape_text "$(normalize_service_name "$proto" "$port" "$name")")" \
        "$(html_escape_text "$info")" \
        "$(html_escape_text "$target_port")" >> "$report_file"
    done < <(awk -F '\t' 'NR > 1 {print $1 "\034" $2 "\034" $3 "\034" $4 "\034" $5 "\034" $6}' "$services_tsv")
    {
      printf '      </tbody>\n'
      printf '    </table>\n'
      printf '  </div>\n'
    } >> "$report_file"
  fi

  printf '  </section>\n  <section class="report-section" aria-label="Open Ports Found"><h2>Open Ports Found</h2>\n' >> "$report_file"

  if [[ ! -s "$open_tsv" || "$open_rows" -eq 0 ]]; then
    printf '  <div class="empty">No open ports were confirmed.</div>\n' >> "$report_file"
  else
    printf '  <div class="open-ports-wrap">\n' >> "$report_file"
    while IFS=$'\t' read -r proto port target; do
      key="${proto}/${port}"
      if [[ "$key" != "$previous_key" ]]; then
        if [[ "$first_group" == false ]]; then
          printf '      </pre>\n' >> "$report_file"
          printf '      </div>\n' >> "$report_file"
          append_port_result_files "$report_file" "$previous_proto" "$previous_port"
          printf '    </details>\n' >> "$report_file"
        fi
        first_group=false
        previous_key="$key"
        previous_proto="$proto"
        previous_port="$port"
        display_label="$(port_card_label "$proto" "$port" "$services_tsv")"
        printf '    <details class="port-card">\n' >> "$report_file"
        printf '      <summary class="port-summary"><span class="port-title"><strong>%s</strong></span></summary>\n' \
          "$(html_escape_text "$display_label")" >> "$report_file"
        printf '      <div class="port-host-list" data-affected-targets>\n' >> "$report_file"
        print_copy_targets_button >> "$report_file"
        printf '      <pre class="targets">' >> "$report_file"
      fi
      printf '%s:%s\n' "$(html_escape_text "$target")" "$(html_escape_text "$port")" >> "$report_file"
    done < <(awk -F '\t' 'NR > 1 {print $2 "\t" $3 "\t" $1}' "$open_tsv" | sort -k2,2n -k1,1 -k3,3)

    if [[ "$first_group" == false ]]; then
      printf '      </pre>\n' >> "$report_file"
      printf '      </div>\n' >> "$report_file"
      append_port_result_files "$report_file" "$previous_proto" "$previous_port"
      printf '    </details>\n' >> "$report_file"
    fi
    printf '  </div>\n' >> "$report_file"
  fi

  printf '  </section>\n' >> "$report_file"
  append_findings_summary_section "$report_file"
  append_credential_summary_section "$report_file"

  {
    printf '  <section class="report-section" aria-label="Core Artifacts"><h2>Core Artifacts</h2>\n'
    printf '  <details class="artifact core-artifacts">\n'
    printf '    <summary>Core Artifacts</summary>\n'
  } >> "$report_file"
  append_core_artifact_group "$report_file" "Targets" \
    "$TARGETS_FILE" "$LIVE_TARGETS_FILE"
  append_core_artifact_group "$report_file" "Base Scan Outputs" \
    "${SCAN_DIR}/syn.nmap" "${SCAN_DIR}/con.nmap" "${SCAN_DIR}/udp.nmap" \
    "${SCAN_DIR}/syn.gnmap" "${SCAN_DIR}/con.gnmap" "${SCAN_DIR}/udp.gnmap" \
    "${SCAN_DIR}/syn.xml" "${SCAN_DIR}/con.xml" "${SCAN_DIR}/udp.xml"
  append_core_artifact_group "$report_file" "Open Port Tables" \
    targets_with_open_ports/services.tsv \
    targets_with_open_ports/open_ports_all.tsv \
    targets_with_open_ports/open_ports_mentioned.tsv \
    targets_with_open_ports/open_ports_by_target.txt
  append_core_artifact_group "$report_file" "Nmap Script Results" \
    "${NSE_DIR}"/*.txt
  append_tls_status_artifacts "$report_file"
  append_core_artifact_group "$report_file" "Ghostcat Retrieved Files" "${MSF_DIR}/loot"/*
  append_msf_failed_artifacts "$report_file"
  append_external_failed_artifacts "$report_file"
  append_core_artifact_group "$report_file" "External Tool Results" \
    "${TOOL_DIR}"/*.txt
  if [[ "${NO_MSF:-false}" != true ]]; then
    append_msf_output_artifacts "$report_file"
    append_core_artifact_group "$report_file" "Metasploit Command Files" \
      "${MSF_DIR}/metasploit_auxiliary.rc" \
      "${MSF_DIR}"/metasploit_auxiliary_*.rc
  fi
  {
    printf '  </details>\n'
    printf '  </section>\n'
    printf '  <footer class="report-footer">\n'
    printf '    <span><strong>Bident</strong> Network VAPT Toolkit</span>\n'
    printf '    <span>Generated %s</span>\n' "$(html_escape_text "$generated_at")"
    printf '  </footer>\n'
    cat <<'HTML'
</main>
<script>
  // REPORT_TOGGLES_START
  function toggleSectionDetails(selector, statusId, open) {
    const sections = document.querySelectorAll(selector);
    sections.forEach(section => { section.open = open; });
    document.getElementById(statusId).textContent = `${open ? 'Expanded' : 'Collapsed'} ${sections.length} sections.`;
  }
  document.getElementById('expandAll').addEventListener('click', () => toggleSectionDetails('#findingsSummary details', 'reportToggleStatus', true));
  document.getElementById('collapseAll').addEventListener('click', () => toggleSectionDetails('#findingsSummary details', 'reportToggleStatus', false));
  document.getElementById('expandCredentials').addEventListener('click', () => toggleSectionDetails('[data-credential-copy] details', 'credentialToggleStatus', true));
  document.getElementById('collapseCredentials').addEventListener('click', () => toggleSectionDetails('[data-credential-copy] details', 'credentialToggleStatus', false));
  // REPORT_TOGGLES_END
  // COPY_TARGETS_START
  async function copyAffectedTargets(button) {
    const container = button.closest('[data-affected-targets]');
    const status = container.querySelector('.copy-targets-status');
    const list = container.querySelector('pre.targets');
    const values = list
      ? list.textContent.split(/\r?\n/)
      : Array.from(container.querySelectorAll('tbody tr'), row => row.cells[0].textContent);
    const targets = [...new Set(values.map(value => value.trim()).filter(Boolean))];
    if (!targets.length) {
      status.textContent = 'No targets to copy.';
      return;
    }
    const text = targets.join('\n');
    const copied = await copyReportText(button, text);
    status.textContent = copied
      ? `Copied ${targets.length} host${targets.length === 1 ? '' : 's'}.`
      : 'Copy unavailable. Select the Host:Port values and copy manually.';
  }
  document.querySelectorAll('.copy-targets:not(.copy-credentials)').forEach(button => {
    button.addEventListener('click', () => copyAffectedTargets(button));
  });
  async function copyReportText(button, text) {
    let copied = false;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        copied = true;
      }
    } catch (_) { /* Local reports may require the fallback below. */ }
    if (!copied) {
      const field = document.createElement('textarea');
      field.value = text;
      field.setAttribute('readonly', '');
      field.style.position = 'fixed';
      field.style.opacity = '0';
      document.body.appendChild(field);
      field.select();
      try { copied = document.execCommand('copy'); } catch (_) { copied = false; }
      field.remove();
      button.focus();
    }
    return copied;
  }
  async function copyCredentialEntries(button) {
    const section = button.closest('[data-credential-copy]');
    const status = section.querySelector('.copy-targets-status');
    const targetsOnly = button.dataset.copyMode === 'targets';
    const values = Array.from(section.querySelectorAll('[data-credential-entry]'), entry => {
      const endpointNode = entry.querySelector('.credential-endpoint');
      const known = endpointNode.dataset.verified === 'true';
      const endpoint = known ? endpointNode.textContent.trim() : 'Not identified';
      const value = entry.querySelector('.credential-value').textContent.trim();
      return targetsOnly ? (known ? endpoint : '') : `${endpoint}\t${value}`;
    }).filter(Boolean);
    const unique = [...new Set(values)];
    if (!unique.length) {
      status.textContent = targetsOnly ? 'No verified Host:Port values to copy.' : 'No entries to copy.';
      return;
    }
    const copied = await copyReportText(button, unique.join('\n'));
    const label = targetsOnly ? 'target' : 'entry';
    status.textContent = copied
      ? `Copied ${unique.length} ${unique.length === 1 ? label : (targetsOnly ? 'hosts' : 'entries')}.`
      : 'Copy unavailable. Select the entries and copy manually.';
  }
  document.querySelectorAll('.copy-credentials').forEach(button => {
    button.addEventListener('click', () => copyCredentialEntries(button));
  });
  // COPY_TARGETS_END
  const root = document.documentElement;
  const toggle = document.getElementById('themeToggle');
  const savedTheme = localStorage.getItem('bident-theme') || 'light';

  function setTheme(theme) {
    root.dataset.theme = theme;
    toggle.textContent = theme === 'dark' ? '☀' : '☾';
    toggle.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
    localStorage.setItem('bident-theme', theme);
  }

  setTheme(savedTheme);

  toggle.addEventListener('click', () => {
    setTheme(root.dataset.theme === 'dark' ? 'light' : 'dark');
  });

  const serviceSearch = document.getElementById('serviceSearch');
  const servicesTable = document.getElementById('servicesTable');

  if (serviceSearch && servicesTable) {
    const tableBody = servicesTable.tBodies[0];
    const rows = Array.from(tableBody.rows);
    const serviceFilters = Array.from(document.querySelectorAll('.service-filter select'));

    function sortServices(column, direction) {
      const sortedRows = rows.slice().sort((a, b) => {
        const first = a.cells[column].textContent.trim();
        const second = b.cells[column].textContent.trim();
        let result;

        if (column === 1) {
          result = Number.parseInt(first, 10) - Number.parseInt(second, 10);
          if (result === 0) {
            result = first.localeCompare(second, undefined, { numeric: true, sensitivity: 'base' });
          }
        } else {
          result = first.localeCompare(second, undefined, { numeric: true, sensitivity: 'base' });
        }

        return direction === 'asc' ? result : -result;
      });

      sortedRows.forEach((row) => tableBody.appendChild(row));
    }

    function filterServices() {
      const query = serviceSearch.value.trim().toLowerCase();
      rows.forEach((row) => {
        const matchesSearch = row.textContent.toLowerCase().includes(query);
        const matchesFilters = serviceFilters.every((filter) => {
          if (!filter.value) {
            return true;
          }
          const column = Number(filter.dataset.column);
          return row.cells[column].textContent.trim() === filter.value;
        });
        row.style.display = matchesSearch && matchesFilters ? '' : 'none';
      });
    }

    function populateServiceFilters() {
      serviceFilters.forEach((filter) => {
        const column = Number(filter.dataset.column);
        const values = Array.from(new Set(rows.map((row) => row.cells[column].textContent.trim()).filter(Boolean)))
          .sort((first, second) => first.localeCompare(second, undefined, { numeric: true, sensitivity: 'base' }));
        values.forEach((value) => {
          const option = document.createElement('option');
          option.value = value;
          option.textContent = value;
          filter.appendChild(option);
        });
        filter.addEventListener('change', filterServices);
      });
    }

    serviceSearch.addEventListener('input', filterServices);
    populateServiceFilters();

    servicesTable.querySelectorAll('.sort-button').forEach((button) => {
      button.addEventListener('click', () => {
        const column = Number(button.dataset.column);
        const nextDirection = button.dataset.direction === 'asc' ? 'desc' : 'asc';

        servicesTable.querySelectorAll('.sort-button').forEach((other) => {
          if (other !== button) {
            other.removeAttribute('data-direction');
          }
        });
        button.dataset.direction = nextDirection;

        sortServices(column, nextDirection);
      });
    });

    const portProtocolSort = servicesTable.querySelector('.sort-button[data-column="1"]');
    if (portProtocolSort) {
      portProtocolSort.dataset.direction = 'asc';
      sortServices(1, 'asc');
    }
  }


</script>
</body>
</html>
HTML
  } >> "$report_file"

  printf '%sWrote HTML Report:%s %s\n' "$CLR_GREEN" "$CLR_RESET" "$report_file"
}
