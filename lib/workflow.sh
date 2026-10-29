main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi
  
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -f)
        [[ -n "${2:-}" ]] || die "-f requires a scope file"
        SCOPE_FILE="$2"
        shift 2
        ;;
      -t)
        [[ -n "${2:-}" ]] || die "-t requires a target"
        SINGLE_TARGET="$2"
        shift 2
        ;;
      --resume)
        [[ -n "${2:-}" ]] || die "--resume requires a results directory"
        RESUME_DIR="$2"
        RESULTS_DIR="$2"
        shift 2
        ;;
      -p-)
        PORT_FLAG="-p-"
        shift
        ;;
      --no-udp)
        NO_UDP=true
        shift
        ;;
      --no-msf)
        NO_MSF=true
        shift
        ;;
      --script-timeout)
        [[ -n "${2:-}" ]] || die "--script-timeout requires a duration"
        SCRIPT_TIMEOUT="$2"
        shift 2
        ;;
      --tool-timeout)
        [[ -n "${2:-}" ]] || die "--tool-timeout requires seconds"
        case "$2" in
          ''|*[!0-9]*)
            die "--tool-timeout must be a non-negative integer"
            ;;
        esac
        TOOL_TIMEOUT="$2"
        shift 2
        ;;
      --msf-timeout)
        [[ -n "${2:-}" ]] || die "--msf-timeout requires seconds"
        case "$2" in
          ''|*[!0-9]*)
            die "--msf-timeout must be a non-negative integer"
            ;;
        esac
        MSF_TIMEOUT="$2"
        shift 2
        ;;
      --msf-threads)
        [[ -n "${2:-}" ]] || die "--msf-threads requires a positive integer"
        case "$2" in
          ''|*[!0-9]*|0)
            die "--msf-threads must be a positive integer"
            ;;
        esac
        MSF_THREADS="$2"
        shift 2
        ;;
      --responder)
        RUN_RESPONDER=true
        shift
        ;;
      --check-deps)
        CHECK_DEPS=true
        shift
        ;;
      --install-deps)
        INSTALL_DEPS=true
        shift
        ;;
      -o|--output-dir|--results-dir)
        [[ -n "${2:-}" ]] || die "$1 requires a results directory"
        RESULTS_DIR="$2"
        shift 2
        ;;
      -T[1-5])
        TIMING="${1#-}"
        shift
        ;;
      -*)
        die "Unknown option: $1"
        ;;
      *)
        die "Unexpected positional argument: $1"
        ;;
    esac
  done
  
  if [[ "$CHECK_DEPS" == true || "$INSTALL_DEPS" == true ]]; then
    print_banner
    if [[ "$CHECK_DEPS" == true ]]; then
      print_dependency_status
    fi
    if [[ "$INSTALL_DEPS" == true ]]; then
      install_dependencies
    fi
    exit 0
  fi

  if [[ -z "$SCOPE_FILE" && -z "$SINGLE_TARGET" && -z "$RESUME_DIR" ]]; then
    die "Missing target input: use -f <scope-file> or -t <target>"
  fi
  
  if [[ -n "$RESUME_DIR" && ( -n "$SCOPE_FILE" || -n "$SINGLE_TARGET" ) ]]; then
    die "Use --resume by itself, not with -f or -t"
  fi
  
  if [[ -n "$SCOPE_FILE" && -n "$SINGLE_TARGET" ]]; then
    die "Use either -f <scope-file> or -t <target>, not both"
  fi
  
  case "$TIMING" in
    T[1-5])
      ;;
    *)
      die "Invalid timing value: $TIMING. Use -T1 through -T5"
      ;;
  esac

  case "$TOOL_TIMEOUT" in
    ''|*[!0-9]*)
      die "Invalid tool timeout: $TOOL_TIMEOUT. Use a non-negative integer"
      ;;
  esac
  
  case "$MSF_TIMEOUT" in
    ''|*[!0-9]*)
      die "Invalid Metasploit timeout: $MSF_TIMEOUT. Use a non-negative integer"
      ;;
  esac
  
  case "$MSF_THREADS" in
    ''|*[!0-9]*|0)
      die "Invalid Metasploit threads: $MSF_THREADS. Use a positive integer"
      ;;
  esac

  [[ "$SCRIPT_TIMEOUT" =~ ^[0-9]+([.][0-9]+)?(ms|s|m|h)?$ ]] || die "Invalid script timeout: $SCRIPT_TIMEOUT. Use 900, 15m, 1h, or 0"

  DISCOVERY_HOST_TIMEOUT_ARGS=(--host-timeout "$DISCOVERY_HOST_TIMEOUT")

  require_root_scan_run
  
  print_banner
  print_section 'Scan Configuration'
  printf '%sTiming Template:%s -%s\n' "$CLR_CYAN" "$CLR_RESET" "$TIMING"
  printf '%sNSE Script Timeout:%s %s (per script instance; 0 = unlimited)\n' "$CLR_CYAN" "$CLR_RESET" "$SCRIPT_TIMEOUT"
  printf '%sTLS Timeout Per Tool/Target:%s %s seconds\n' "$CLR_CYAN" "$CLR_RESET" "$TLS_TIMEOUT"
  printf '%sHost Discovery Timeout:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "${DISCOVERY_HOST_TIMEOUT_ARGS[1]}"
  if [[ "$TOOL_TIMEOUT" -gt 0 ]]; then
    if command_available timeout; then
      printf '%sTool Timeout:%s %s seconds\n' "$CLR_CYAN" "$CLR_RESET" "$TOOL_TIMEOUT"
    else
      printf '%sTool Timeout:%s Disabled because timeout command was not found\n' "$CLR_YELLOW" "$CLR_RESET"
    fi
  fi
  if [[ "$NO_MSF" != true && "$MSF_TIMEOUT" -gt 0 ]] && ! command_available timeout; then
    printf '%sMetasploit Timeout:%s Disabled because timeout command was not found\n' "$CLR_YELLOW" "$CLR_RESET"
  fi

  need_command awk
  need_command cat
  need_command cp
  need_command date
  need_command grep
  need_command mktemp
  need_command mkdir
  need_command nmap
  need_command rm
  need_command screen
  need_command sort
  need_command tee
  if [[ "$RUN_RESPONDER" == true ]]; then
    need_command responder
  fi
  
  prepare_privileged_execution
  trap confirm_cancel INT
  
  if [[ -n "$RESUME_DIR" ]]; then
    [[ -d "$RESUME_DIR" ]] || die "Resume folder not found: $RESUME_DIR"
  elif [[ -n "$SCOPE_FILE" ]]; then
    [[ -f "$SCOPE_FILE" ]] || die "Scope file not found: $SCOPE_FILE"
    [[ -s "$SCOPE_FILE" ]] || die "Scope file is empty: $SCOPE_FILE"
  fi
  
  if [[ -z "$RESULTS_DIR" ]]; then
    RESULTS_DIR="bident_results_$(date '+%Y%m%d_%H%M%S')"
  fi
  
  if [[ -n "$RESUME_DIR" ]]; then
    printf '%sResume Folder:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$RESULTS_DIR"
  else
    mkdir -p "$RESULTS_DIR"
    printf '%sResults Folder:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$RESULTS_DIR"
  fi
  
  if [[ -n "$RESUME_DIR" ]]; then
    :
  elif [[ -n "$SCOPE_FILE" ]]; then
    ORIGINAL_SCOPE_FILE="$SCOPE_FILE"
    SCOPE_BASENAME="${SCOPE_FILE##*/}"
    cp "$ORIGINAL_SCOPE_FILE" "${RESULTS_DIR}/${SCOPE_BASENAME}"
    printf '%sCopied Scope File:%s %s\n' "$CLR_GREEN" "$CLR_RESET" "${RESULTS_DIR}/${SCOPE_BASENAME}"
  else
    SCOPE_BASENAME="single_target_scope.txt"
    printf '%s\n' "$SINGLE_TARGET" > "${RESULTS_DIR}/${SCOPE_BASENAME}"
    printf '%sWrote Single Target Scope File:%s %s\n' "$CLR_GREEN" "$CLR_RESET" "${RESULTS_DIR}/${SCOPE_BASENAME}"
  fi
  
  cd "$RESULTS_DIR"
  RESULTS_DIR="$PWD"
  RESULTS_PERMISSIONS_FINALIZED=false
  BIDENT_OWNED_SCANS=()
  trap 'finalize_results_on_exit "$?"' EXIT
  trap 'exit 143' TERM
  if [[ -z "$RESUME_DIR" ]]; then
    SCOPE_FILE="$SCOPE_BASENAME"
  fi
  mkdir -p "$SCAN_DIR" "$NSE_DIR" "$TOOL_DIR" "$LOG_DIR"
  allow_unprivileged_output_writes
  start_scan_timing
  : > "${LOG_DIR}/nse_status.tsv"
  : > "${LOG_DIR}/external_status.tsv"
  check_external_tool_startup
  
  if [[ "$RUN_RESPONDER" == true ]]; then
    ensure_screen_sessions_available responder
    start_responder
  fi
  
  print_section 'Scope & Host Discovery'
  if [[ -n "$RESUME_DIR" && -s "$TARGETS_FILE" ]]; then
    printf '%sResuming With Scoped Targets File:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$TARGETS_FILE"
  else
    [[ -n "$SCOPE_FILE" ]] || die "Cannot resume discovery; ${TARGETS_FILE} is missing"
    printf '%sExpanding Scope From:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$SCOPE_FILE"
    nmap -sL -n "-${TIMING}" -iL "$SCOPE_FILE" \
      | awk '/Nmap scan report for/ {print $NF}' \
      | sort -u \
      > "$TARGETS_FILE"
  fi
  
  if [[ ! -s "$TARGETS_FILE" ]]; then
    die "No scoped targets found; ${TARGETS_FILE} was not created with any hosts"
  fi
  
  target_count="$(wc -l < "$TARGETS_FILE" | tr -d '[:space:]')"
  printf '%sTotal Hosts To Scan:%s %s\n' "$CLR_GREEN" "$CLR_RESET" "$target_count"
  printf '%sScoped Targets File:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$TARGETS_FILE"
  
  if [[ -n "$RESUME_DIR" && -s "$LIVE_TARGETS_FILE" ]]; then
    printf '%sResuming With Live Hosts File:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$LIVE_TARGETS_FILE"
  else
    printf '%sDiscovering Live Hosts From:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$TARGETS_FILE"
    : > "$LIVE_TARGETS_FILE"
    nmap -sn -n --reason "-${TIMING}" "${DISCOVERY_HOST_TIMEOUT_ARGS[@]}" -iL "$TARGETS_FILE" 2>&1 \
      | awk '
          /Nmap scan report for/ {
            ip = $NF
          }
          /Host is up/ {
            print ip >> live_targets_file
            fflush(live_targets_file)
          }
        ' live_targets_file="$LIVE_TARGETS_FILE"
  fi
  
  if [[ ! -s "$LIVE_TARGETS_FILE" ]]; then
    printf '%sNo Live Hosts Was Found.%s\n' "$CLR_YELLOW" "$CLR_RESET"
    printf '%sLive Targets File:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$LIVE_TARGETS_FILE"
    printf '%sNothing More To Scan. Exiting.%s\n' "$CLR_YELLOW" "$CLR_RESET"
    finish_scan_timing
    generate_html_report
    allow_unprivileged_output_writes
    RESULTS_PERMISSIONS_FINALIZED=true
    print_scan_timing
    print_completion
    exit 0
  fi
  
  live_target_count="$(wc -l < "$LIVE_TARGETS_FILE" | tr -d '[:space:]')"
  printf '%sTotal Live Hosts:%s %s\n' "$CLR_GREEN" "$CLR_RESET" "$live_target_count"
  printf '%sLive Targets File:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$LIVE_TARGETS_FILE"
  printf '%sLive Hosts:%s\n' "$CLR_CYAN" "$CLR_RESET"
  awk '{print "  " $0}' "$LIVE_TARGETS_FILE"
  if [[ -n "$PORT_FLAG" ]]; then
    printf '%sPort Mode:%s All Ports (-p- Enabled)\n' "$CLR_CYAN" "$CLR_RESET"
  else
    printf '%sPort Mode:%s Default Nmap Ports (-p- Disabled)\n' "$CLR_CYAN" "$CLR_RESET"
  fi
  if [[ "$NO_UDP" == true ]]; then
    printf '%sUDP Mode:%s Disabled (--no-udp Enabled)\n' "$CLR_CYAN" "$CLR_RESET"
  else
    printf '%sUDP Mode:%s Enabled\n' "$CLR_CYAN" "$CLR_RESET"
  fi
  if [[ "$NO_MSF" == true ]]; then
    printf '%sMetasploit Mode:%s Disabled (--no-msf Enabled)\n' "$CLR_CYAN" "$CLR_RESET"
  else
    printf '%sMetasploit Mode:%s Enabled\n' "$CLR_CYAN" "$CLR_RESET"
  fi
  
  print_section 'Base Port Scans'
  BASE_SCAN_SESSIONS=(syn con)
  BASE_SCAN_OUTPUTS=("${SCAN_DIR}/syn.gnmap" "${SCAN_DIR}/con.gnmap")
  if [[ "$NO_UDP" != true ]]; then
    BASE_SCAN_SESSIONS+=(udp)
    BASE_SCAN_OUTPUTS+=("${SCAN_DIR}/udp.gnmap")
  fi

  START_SCAN_SESSIONS=()
  for scan_index in "${!BASE_SCAN_SESSIONS[@]}"; do
    if [[ -s "${BASE_SCAN_OUTPUTS[$scan_index]}" ]]; then
      printf '%sReusing Base Scan Output:%s %s\n' "$CLR_GREEN" "$CLR_RESET" "${BASE_SCAN_OUTPUTS[$scan_index]}"
    else
      START_SCAN_SESSIONS+=("${BASE_SCAN_SESSIONS[$scan_index]}")
    fi
  done
  
  if [[ "${#START_SCAN_SESSIONS[@]}" -gt 0 ]]; then
    ensure_screen_sessions_available "${START_SCAN_SESSIONS[@]}"
    
    for session_name in "${START_SCAN_SESSIONS[@]}"; do
      case "$session_name" in
        syn)
          start_screen_scan "syn" \
            "${PRIVILEGED_CMD_PREFIX} nmap -sV -sS -v --reason ${PORT_FLAG} --min-rate ${MIN_RATE} -${TIMING} --script-timeout ${SCRIPT_TIMEOUT} -oA ${SCAN_DIR}/syn -iL ${LIVE_TARGETS_FILE} --open"
          ;;
        con)
          start_screen_scan "con" \
            "nmap -sV -sT -v --reason ${PORT_FLAG} --min-rate ${MIN_RATE} -${TIMING} --script-timeout ${SCRIPT_TIMEOUT} -oA ${SCAN_DIR}/con -iL ${LIVE_TARGETS_FILE} --open"
          ;;
        udp)
          start_screen_scan "udp" \
            "${PRIVILEGED_CMD_PREFIX} nmap -n -sU -v --reason --max-rtt-timeout=100ms --max-retries=0 --min-rate ${MIN_RATE} -${TIMING} ${PORT_FLAG} -oA ${SCAN_DIR}/udp -iL ${LIVE_TARGETS_FILE} --open"
          ;;
      esac
    done
    
    printf '%sBase Scans Sessions Launched.%s\n' "$CLR_GREEN" "$CLR_RESET"
    
    wait_for_screen_scans "${START_SCAN_SESSIONS[@]}"
  else
    printf '%sAll Base Scan Outputs Found:%s Skipping Base Scan Stage.\n' "$CLR_GREEN" "$CLR_RESET"
  fi
  
  for base_output in "${BASE_SCAN_OUTPUTS[@]}"; do
    [[ -f "$base_output" ]] || die "Expected base scan output not found: $base_output"
  done
  
  generate_open_port_reports
  
  printf '%sBase Scans Finished.%s\n' "$CLR_GREEN" "$CLR_RESET"
  print_section 'Vulnerability Checks'
  
  run_if_open "FTP NSE" tcp "21" \
    nmap -d -n -sV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" --script 'ftp-* and not dos' -p 21 -oN ${NSE_DIR}/s_ftp.txt -iL "$(open_targets_file_for_ports tcp 21 ftp)" --open
  
  run_if_open "SSH NSE" tcp "22" \
    nmap -d -n -sV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" --script 'ssh* and not dos' -p 22 -oN ${NSE_DIR}/s_ssh.txt -iL "$(open_targets_file_for_ports tcp 22 ssh)" --open
  
  run_ssh_audit_check
  
  run_if_open "Telnet NSE" tcp "23" \
    nmap -d -n -sV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" --script '*telnet* and not dos' -p 23 -oN ${NSE_DIR}/s_telnet.txt -iL "$(open_targets_file_for_ports tcp 23 telnet)" --open
  
  run_if_open "SMTP NSE" tcp "25,465,587" \
    nmap -d -n -sV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" --script 'smtp-* and not dos' -p 25,465,587 -oN ${NSE_DIR}/s_smtp.txt -iL "$(open_targets_file_for_ports tcp 25,465,587 smtp)" --open
  
  if [[ "$NO_UDP" == true ]]; then
    run_if_open "DNS NSE" tcp "53" \
      run_privileged nmap -d -n -sS -sV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" --script '((default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport) and not dos' -p 53 -oN ${NSE_DIR}/s_dns.txt -iL "$(open_targets_file_for_ports tcp 53 dns)" --open
  else
    run_if_open "DNS NSE" any "53" \
      run_privileged nmap -d -n -sS -sU -sV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" --script '((default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport) and not dos' -p 53 -oN ${NSE_DIR}/s_dns.txt -iL "$(open_targets_file_for_ports any 53 dns)" --open
  fi
  
  run_dns_dig_checks
  
  run_if_open "HTTP/HTTPS NSE" tcp "80,81,443,8000,8080,8443" \
    nmap -d -n -sV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" --script 'http* and not (dos or http-slowloris*)' -p 80,81,443,8000,8080,8443 -oN ${NSE_DIR}/s_http.txt -iL "$(open_targets_file_for_ports tcp 80,81,443,8000,8080,8443 http_https)" --open
  
  run_if_open "AJP NSE" tcp "8009" \
    nmap -d -n -sV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" --script 'ajp-* and not dos' -p 8009 -oN ${NSE_DIR}/s_ajp.txt -iL "$(open_targets_file_for_ports tcp 8009 ajp)" --open
  
  run_if_open "Kerberos NSE" tcp "88" \
    nmap -d -n -sV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" --script krb5-enum-users -p 88 -oN ${NSE_DIR}/s_kerberos.txt -iL "$(open_targets_file_for_ports tcp 88 kerberos)" --open
  
  run_if_open "POP3 NSE" tcp "110,995" \
    nmap -d -n -sV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" --script 'pop3-capabilities or pop3-ntlm-info' -p 110,995 -oN ${NSE_DIR}/s_pop3.txt -iL "$(open_targets_file_for_ports tcp 110,995 pop3)" --open
  
  if [[ "$NO_UDP" == true ]]; then
    run_if_open "RPCBind NSE" tcp "111" \
      run_privileged nmap -d -n -sV -sS "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" -p 111 -oN ${NSE_DIR}/s_rpcbind.txt -iL "$(open_targets_file_for_ports tcp 111 rpcbind)" --open
  else
    run_if_open "RPCBind NSE" any "111" \
      run_privileged nmap -d -n -sV -sSUC "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" -p 111 -oN ${NSE_DIR}/s_rpcbind.txt -iL "$(open_targets_file_for_ports any 111 rpcbind)" --open
  fi
  
  if [[ "$NO_UDP" != true ]]; then
    run_if_open "NTP NSE" udp "123" \
      run_privileged nmap -d -n -sU -sV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" --script 'ntp* and (discovery or vuln) and not (dos or brute)' -p 123 -oN ${NSE_DIR}/s_ntp.txt -iL "$(open_targets_file_for_ports udp 123 ntp)" --open
  fi
  
  run_rpc_135_checks
  
  if [[ "$NO_UDP" != true ]]; then
    run_if_open "NetBIOS NSE" udp "137" \
      run_privileged nmap -d -n -sU -sV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" --script nbstat -p 137 -oN ${NSE_DIR}/s_netbios.txt -iL "$(open_targets_file_for_ports udp 137 netbios)" --open
  fi
  
  run_if_open "SMB NSE" tcp "139,445" \
    nmap -d -n -sV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" --script '((smb-vuln* and not dos) or smb-enum* or smb-protocols or smb-security-mode or smb2-security-mode)' -p 139,445 -oN ${NSE_DIR}/s_smb.txt -iL "$(open_targets_file_for_ports tcp 139,445 smb)" --open
  
  run_smb_external_checks
  
  if [[ "$NO_UDP" != true ]]; then
    run_if_open "SNMP NSE" udp "161,162" \
      run_privileged nmap -d -n -sUV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" --script 'snmp-* and not dos' -p 161,162 -oN ${NSE_DIR}/s_snmp.txt -iL "$(open_targets_file_for_ports udp 161,162 snmp)" --open
  fi
  
  run_if_open "LDAP NSE" tcp "389,636,3268,3269" \
    nmap -d -n -sV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" --script 'ldap* and not (brute or dos)' -p 389,636,3268,3269 -oN ${NSE_DIR}/s_ldap.txt -iL "$(open_targets_file_for_ports tcp 389,636,3268,3269 ldap)" --open
  
  run_ldapsearch_checks
  
  if [[ "$NO_UDP" != true ]]; then
    run_if_open "IKE scan" udp "500" \
      run_privileged nmap -d -n -sUV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" -p 500 -oN ${NSE_DIR}/s_ike.txt -iL "$(open_targets_file_for_ports udp 500 ike)" --open
  
    run_ike_weak_encryption_check
  
    run_if_open "IPMI NSE" udp "623" \
      run_privileged nmap -d -n -sU -sV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" --script 'ipmi-* and not dos' -p 623 -oN ${NSE_DIR}/s_ipmi.txt -iL "$(open_targets_file_for_ports udp 623 ipmi)" --open
  fi
  
  run_if_open "MSSQL NSE" tcp "1433" \
    nmap -d -n -sV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" --script ms-sql-info,ms-sql-empty-password,ms-sql-brute,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -p 1433 -oN ${NSE_DIR}/db_mssql.txt -iL "$(open_targets_file_for_ports tcp 1433 mssql)" --open
  
  run_if_open "Oracle NSE" tcp "1521" \
    nmap -d -n -sV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" --script oracle-tns-version,oracle-sid-brute -p 1521 -oN ${NSE_DIR}/s_oracle.txt -iL "$(open_targets_file_for_ports tcp 1521 oracle)"
  
  run_if_open "NFS NSE" tcp "2049" \
    nmap -d -n -sV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" --script nfs-ls,nfs-showmount,nfs-statfs -p 2049 -oN ${NSE_DIR}/s_nfs.txt -iL "$(open_targets_file_for_ports tcp 2049 nfs)" --open
  
  run_if_open "MySQL NSE" tcp "3306" \
    nmap -d -n -sV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 -p 3306 -oN ${NSE_DIR}/db_mysql.txt -iL "$(open_targets_file_for_ports tcp 3306 mysql)" --open
  
  run_if_open "RDP NSE" tcp "3389" \
    nmap -d -n -sV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" --script 'rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info' -p 3389 -oN ${NSE_DIR}/s_rdp.txt -iL "$(open_targets_file_for_ports tcp 3389 rdp)" --open
  
  if [[ "$NO_UDP" != true ]]; then
    run_if_open "SIP NSE" udp "5060" \
      run_privileged nmap -d -n -sU -sV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" --script 'sip-* and not dos' -p 5060 -oN ${NSE_DIR}/s_sip.txt -iL "$(open_targets_file_for_ports udp 5060 sip)" --open
  fi
  
  run_if_open "VNC NSE" tcp "5800,5801,5900,5901" \
    nmap -d -n -sV "-${TIMING}" --script-timeout "$SCRIPT_TIMEOUT" --min-rate "$NSE_MIN_RATE" --script 'vnc-* and not dos' -p 5800,5801,5900,5901 -oN ${NSE_DIR}/s_vnc.txt -iL "$(open_targets_file_for_ports tcp 5800,5801,5900,5901 vnc)" --open

  print_section 'SSL/TLS Checks'
  run_ssl_checks

  print_section 'Metasploit Checks'
  if [[ "$NO_MSF" == true ]]; then
    printf '%sSkipping Metasploit Auxiliary Checks:%s --no-msf Enabled\n' "$CLR_YELLOW" "$CLR_RESET"
  else
    run_msf_auxiliary_checks
  fi
  
  finish_scan_timing
  print_section 'Report Generation'
  generate_services_report
  generate_html_report
  generate_json_summary
  allow_unprivileged_output_writes
  RESULTS_PERMISSIONS_FINALIZED=true
  
  print_final_summary
  print_scan_timing
  print_completion
  exit 0
  
}
