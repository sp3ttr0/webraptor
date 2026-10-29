msf_module_slug() {
  local module="$1"
  local module_name="${1##*/}"

  case "$module" in
    auxiliary/scanner/ftp/anonymous)
      printf 'ftp_anonymous'
      return
      ;;
  esac

  printf '%s' "$module_name" | tr -c 'A-Za-z0-9_' '_'
}

msf_absolute_path() {
  local path="$1"

  case "$path" in
    /*) printf '%s' "$path" ;;
    *) printf '%s/%s' "$PWD" "$path" ;;
  esac
}

msf_quote_value() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"' "$value"
}

msf_append_module() {
  local rc_file="$1"
  local module="$2"
  local proto="$3"
  local port="$4"
  local ssl_mode="$5"
  local targets_file="$6"

  {
    printf 'use %s\n' "$module"
    printf 'setg VERBOSE false\n'
    printf 'setg ConnectTimeout %s\n' "$MSF_CONNECT_TIMEOUT"
    printf 'setg TCPTimeout %s\n' "$MSF_TCP_TIMEOUT"
    printf 'set RHOSTS %s\n' "$(msf_quote_value "file:$(msf_absolute_path "$targets_file")")"
    printf 'set RPORT %s\n' "$port"
    printf 'set THREADS %s\n' "$MSF_THREADS"
    if [[ "$module" == "auxiliary/scanner/snmp/snmp_login" ]]; then
      printf 'set PASS_FILE %s\n' "$(msf_quote_value "$(msf_absolute_path "$SNMP_COMMUNITY_FILE")")"
    fi
    if [[ "$ssl_mode" == true ]]; then
      printf 'set SSL true\n'
    fi
    if [[ "$module" == auxiliary/admin/http/tomcat_ghostcat ]]; then
      printf 'set FILENAME /WEB-INF/web.xml\n'
      while IFS= read -r ghostcat_host; do
        [[ -n "$ghostcat_host" ]] || continue
        printf 'set RHOST %s\nset RHOSTS %s\nrun\n' "$(msf_quote_value "$ghostcat_host")" "$(msf_quote_value "$ghostcat_host")"
      done < "$targets_file"
    else
      printf 'run\n'
    fi
    printf '\n'
  } >> "$rc_file"
}

msf_append_exit() {
  local rc_file="$1"

  {
    printf 'exit -y\n'
  } >> "$rc_file"
}

msf_add_port_modules() {
  local rc_file="$1"
  local proto="$2"
  local port="$3"
  local targets_file="$4"
  local ssl_mode=false

  case "${proto}/${port}" in
    tcp/21)
      msf_append_module "$rc_file" auxiliary/scanner/ftp/anonymous "$proto" "$port" "$ssl_mode" "$targets_file"
      ;;
    tcp/25|tcp/465|tcp/587)
      msf_append_module "$rc_file" auxiliary/scanner/smtp/smtp_relay "$proto" "$port" "$ssl_mode" "$targets_file"
      ;;
    tcp/139|tcp/445)
      msf_append_module "$rc_file" auxiliary/scanner/smb/smb_ms17_010 "$proto" "$port" "$ssl_mode" "$targets_file"
      ;;
    tcp/8009)
      msf_append_module "$rc_file" auxiliary/admin/http/tomcat_ghostcat "$proto" "$port" "$ssl_mode" "$targets_file"
      ;;
    tcp/3389)
      msf_append_module "$rc_file" auxiliary/scanner/rdp/rdp_scanner "$proto" "$port" "$ssl_mode" "$targets_file"
      msf_append_module "$rc_file" auxiliary/scanner/rdp/cve_2019_0708_bluekeep "$proto" "$port" "$ssl_mode" "$targets_file"
      ;;
    tcp/5800|tcp/5801|tcp/5900|tcp/5901)
      msf_append_module "$rc_file" auxiliary/scanner/vnc/vnc_none_auth "$proto" "$port" "$ssl_mode" "$targets_file"
      ;;
    udp/137)
      msf_append_module "$rc_file" auxiliary/scanner/netbios/nbname "$proto" "$port" "$ssl_mode" "$targets_file"
      ;;
    udp/161)
      msf_append_module "$rc_file" auxiliary/scanner/snmp/snmp_login "$proto" "$port" "$ssl_mode" "$targets_file"
      msf_append_module "$rc_file" auxiliary/scanner/snmp/snmp_enum "$proto" "$port" "$ssl_mode" "$targets_file"
      msf_append_module "$rc_file" auxiliary/scanner/snmp/snmp_enumusers "$proto" "$port" "$ssl_mode" "$targets_file"
      msf_append_module "$rc_file" auxiliary/scanner/snmp/snmp_enumshares "$proto" "$port" "$ssl_mode" "$targets_file"
      ;;
  esac
}

msf_write_targets_file() {
  local open_tsv="$1"
  local proto="$2"
  local port="$3"
  local target_file="$4"

  awk -F '\t' -v wanted_proto="$proto" -v wanted_port="$port" '
    NR > 1 && $2 == wanted_proto && $3 == wanted_port {
      print $1
    }
  ' "$open_tsv" | awk '!seen[$0]++' > "$target_file"
}

msf_print_modules_for_rc() {
  local rc_file="$1"
  local label="$2"
  local module_name

  while IFS= read -r module_name; do
    [[ -n "${module_name:-}" ]] || continue
    printf '%sRunning Metasploit Module:%s %s (%s)\n' "$CLR_CYAN" "$CLR_RESET" "$module_name" "$label"
  done < <(awk '/^use / {print $2}' "$rc_file")
}

run_msf_auxiliary_checks() {
  local open_tsv="targets_with_open_ports/open_ports_all.tsv"
  local index_rc_file="${MSF_DIR}/metasploit_auxiliary.rc"
  local rc_file
  local proto
  local port
  local key
  local previous_key=""
  local target_file
  local module_count=0
  local port_module_count=0
  local completed_modules=0
  local rc_files=()
  local rc_labels=()
  local rc_module_counts=()
  local index=0
  local status=0
  local module module_slug job_rc result_file
  local result_files=()

  if [[ ! -s "$open_tsv" ]]; then
    return
  fi

  if ! command_available msfconsole; then
    printf '%sSkipping Metasploit Auxiliary Checks:%s Command Not Found\n' "$CLR_YELLOW" "$CLR_RESET"
    return
  fi

  mkdir -p "$MSF_DIR" "$MSF_RESULT_DIR"
  rm -f "${MSF_DIR}"/metasploit_auxiliary_*.rc "${MSF_RESULT_DIR}"/*.txt 2>/dev/null || true
  : > "$index_rc_file"
  : > "${MSF_DIR}/msfconsole.log"
  : > "${MSF_DIR}/run_status.tsv"

  while IFS=$'\t' read -r proto port; do
    [[ -n "${proto:-}" && -n "${port:-}" ]] || continue
    key="${proto}/${port}"
    [[ "$key" == "$previous_key" ]] && continue
    previous_key="$key"

    case "$key" in
      tcp/21|tcp/25|tcp/465|tcp/587|tcp/139|tcp/445|tcp/3389|tcp/5800|tcp/5801|tcp/5900|tcp/5901|tcp/8009|udp/137|udp/161)
        target_file="${MSF_DIR}/targets_${proto}_${port}.txt"
        rc_file="${MSF_DIR}/metasploit_auxiliary_${proto}_${port}.rc"
        : > "$rc_file"
        msf_write_targets_file "$open_tsv" "$proto" "$port" "$target_file"
        if [[ -s "$target_file" ]]; then
          msf_add_port_modules "$rc_file" "$proto" "$port" "$target_file"
        fi
        port_module_count="$(grep -c '^run$' "$rc_file" 2>/dev/null || true)"
        if [[ "$port_module_count" -gt 0 ]]; then
          # Each process owns one module, so stdout/stderr cannot cross modules.
          while IFS= read -r module; do
            module_slug="$(msf_module_slug "$module")"
            job_rc="${MSF_DIR}/metasploit_auxiliary_${module_slug}_${proto}_${port}.rc"
            result_file="${MSF_RESULT_DIR}/${module_slug}_${proto}_${port}.txt"
            : > "$job_rc"
            msf_append_module "$job_rc" "$module" "$proto" "$port" false "$target_file"
            msf_append_exit "$job_rc"
            printf 'resource %s\n' "$(msf_quote_value "$(msf_absolute_path "$job_rc")")" >> "$index_rc_file"
            rc_files+=("$job_rc")
            result_files+=("$result_file")
            rc_labels+=("${proto}/${port} ${module_slug}")
            rc_module_counts+=(1)
            module_count=$((module_count + 1))
          done < <(awk '/^use / {print $2}' "$rc_file")
          msf_append_exit "$rc_file"
        else
          rm -f "$rc_file"
        fi
        ;;
    esac
  done < <(awk -F '\t' 'NR > 1 {print $2 "\t" $3}' "$open_tsv" | sort -k1,1 -k2,2n)

  if [[ ! -s "$index_rc_file" ]]; then
    return
  fi

  printf '%sRunning Metasploit Auxiliary Checks%s\n' "$CLR_CYAN" "$CLR_RESET"
  printf '%sMetasploit Module Runs:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$module_count"
  if [[ "$MSF_TIMEOUT" -gt 0 ]]; then
    if command_available timeout; then
      :
    else
      printf '%sMetasploit Timeout:%s Disabled because timeout command was not found\n' "$CLR_YELLOW" "$CLR_RESET"
    fi
  fi
  print_progress_bar "Metasploit Progress" "$completed_modules" "$module_count"
  [[ -t 1 ]] && printf '\n'

  for index in "${!rc_files[@]}"; do
    rc_file="${rc_files[$index]}"
    port_module_count="${rc_module_counts[$index]}"
    printf '%sRunning Metasploit Auxiliary For:%s %s (%s module(s))\n' "$CLR_CYAN" "$CLR_RESET" "${rc_labels[$index]}" "$port_module_count"
    msf_print_modules_for_rc "$rc_file" "${rc_labels[$index]}"
    status=0
    result_file="${result_files[$index]}"
    {
      printf '\n===== %s :: %s =====\n' "$(date '+%Y-%m-%d %H:%M:%S')" "${rc_labels[$index]}"
      if [[ "${MSF_TIMEOUT:-0}" =~ ^[0-9]+$ && "${MSF_TIMEOUT:-0}" -gt 0 ]] && command_available timeout; then
        timeout --preserve-status "$MSF_TIMEOUT" msfconsole -q -r "$rc_file"
      else
        msfconsole -q -r "$rc_file"
      fi
    } > "$result_file" 2>&1 || status=$?
    printf '\nBident Metasploit process exit: %s\n' "$status" >> "$result_file"
    if [[ "${rc_labels[$index]}" == 'tcp/8009 tomcat_ghostcat' ]]; then
      msf_collect_ghostcat_loot "$result_file" "${MSF_DIR}/targets_tcp_8009.txt"
    fi
    cat "$result_file" >> "${MSF_DIR}/msfconsole.log"
    printf '%s\t%s\n' "${rc_labels[$index]}" "$status" >> "${MSF_DIR}/run_status.tsv"
    msf_notify_result "$result_file" "$status"
    completed_modules=$((completed_modules + port_module_count))
    print_progress_bar "Metasploit Progress" "$completed_modules" "$module_count"
    if [[ -t 1 && "$completed_modules" -lt "$module_count" ]]; then
      printf '\n'
    fi
  done

  find "$MSF_RESULT_DIR" -type f -size 0 -delete 2>/dev/null || true
  printf '%sMetasploit Auxiliary Checks Finished%s\n' "$CLR_GREEN" "$CLR_RESET"
}

# Ghostcat may store an error response as loot. Promote only a valid web.xml
# from a scoped host, preserving a portable copy alongside the scan outputs.
msf_collect_ghostcat_loot() {
  local result_file="$1" scope_file="$2" saved_file
  if ! command -v python3 >/dev/null 2>&1; then
    printf 'Ghostcat: Incomplete: Python 3 is required to validate retrieved XML.\n'
    printf '\n[-] Auxiliary failed: Ghostcat XML validation requires Python 3.\n' >> "$result_file"
    return 0
  fi
  if ! python3 "${BIDENT_ROOT}/lib/ghostcat.py" collect "$result_file" "$scope_file"; then
    printf 'Ghostcat: Incomplete: could not validate or save retrieved files.\n'
    printf '\n[-] Auxiliary failed: Ghostcat loot validation or copy failed.\n' >> "$result_file"
  else
    while IFS= read -r saved_file; do
      [[ -n "$saved_file" ]] || continue
      printf '%s[+] Apache Tomcat AJP File Read (Ghostcat): Found and verified.%s\n' "${CLR_GREEN:-}" "${CLR_RESET:-}"
      printf '    Saved file: %s\n' "$saved_file"
    done < <(python3 "${BIDENT_ROOT}/lib/ghostcat.py" read "$result_file" "$scope_file" paths)
  fi
}

msf_finding_title() {
  case "${1##*/}" in
    ftp_anonymous_*) printf 'FTP Anonymous Enabled' ;;
    smtp_relay_*) printf 'SMTP Open Relay' ;;
    smb_ms17_010_*) printf 'Server Message Block (SMB) MS17-010 (EternalBlue) Vulnerability' ;;
    tomcat_ghostcat_*) printf 'Apache Tomcat AJP File Read (Ghostcat)' ;;
    rdp_scanner_*) printf 'Remote Desktop Protocol Detection' ;;
    cve_2019_0708_bluekeep_*) printf 'Remote Desktop Protocol (RDP) BlueKeep Vulnerability' ;;
    vnc_none_auth_*) printf 'Virtual Network Computing (VNC) None Authentication' ;;
    nbname_*) printf 'NetBIOS Information Disclosure' ;;
    snmp_login_*) printf 'SNMP Default/Weak Community String' ;;
    snmp_enumusers_*) printf 'SNMP Users Enumeration' ;;
    snmp_enumshares_*) printf 'SNMP Shares Enumeration' ;;
    snmp_enum_*) printf 'SNMP Information Disclosure' ;;
    *) printf 'Metasploit check' ;;
  esac
}

msf_notify_result() {
  local file="$1" status="${2:-0}" title endpoints failures reason
  title="$(msf_finding_title "$file")"
  # Reuse the report classifier; never print its endpoint list to the terminal.
  if [[ "${file##*/}" != tomcat_ghostcat_tcp_8009.txt ]]; then
    endpoints="$(msf_finding_lines "$file" endpoints)"
    if [[ -n "$endpoints" ]]; then
      printf '%s[+] %s: Found and verified.%s\n' "${CLR_GREEN:-}" "$title" "${CLR_RESET:-}"
    fi
  fi
  failures="$(msf_failure_lines "$file")"
  if [[ "$status" != 0 || -n "$failures" ]]; then
    if [[ "$status" == 124 || "$status" == 137 || "$status" == 143 ]]; then
      reason='check timed out'
    elif [[ "$status" != 0 ]]; then
      reason="process exited with status $status"
    else
      reason='module or connection error'
    fi
    printf '%s[!] %s: Incomplete: %s.%s\n' "${CLR_YELLOW:-}" "$title" "$reason" "${CLR_RESET:-}"
    printf '    Details: %s\n' "$file"
  fi
}
