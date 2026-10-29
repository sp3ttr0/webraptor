# Emit unique endpoint/cipher pairs from ssh-audit encryption findings only.
# The optional endpoint identifies live per-target output without a header.
ssh_weak_cipher_rows() {
  local file="$1" default_endpoint="${2:-}"
  awk -v endpoint="$default_endpoint" '
    BEGIN { esc = sprintf("%c", 27) }
    function flush(j, key) {
      if (!failed) for (j=1; j<=count; j++) {
        key=endpoint SUBSEP pending[j]
        if (!seen[key]++) print endpoint "\t" pending[j]
      }
      for (j in pending) delete pending[j]
      count=0; failed=0
    }
    function set_endpoint(target, port) {
      gsub(/\\/, "", target)
      if (target ~ /^\[[^]]+\]:[0-9]+$/ || target ~ /^[^:]+:[0-9]+$/) return target
      if (target ~ /:/ && target !~ /^\[/) return "[" target "]:" port
      return target ":" port
    }
    {
      gsub(esc "\\[[0-?]*[ -/]*[@-~]", "")
      gsub(/\[[0-9;]*m/, "")
      if ($0 ~ /^===== /) { flush(); endpoint = ""; cipher = ""; next }
      if ($0 ~ /^Command:/) {
        flush()
        endpoint = ""; cipher = ""; target = ""; port = "22"; command_seen = 0
        for (i = 2; i <= NF; i++) {
          if ($i ~ /(^|\/)ssh-audit$/) { command_seen = 1; continue }
          if (!command_seen) continue
          if ($i == "-p" || $i == "--port") { port = $(++i); continue }
          if ($i ~ /^--port=/) { port = $i; sub(/^--port=/, "", port); continue }
          if ($i !~ /^-/) target = $i
        }
        if (command_seen && target != "" && port ~ /^[0-9]+$/ && port > 0 && port <= 65535) endpoint = set_endpoint(target, port)
        next
      }
      if (tolower($0) ~ /connection refused|connection reset|no route to host|timed out|unable to connect|error:|traceback/) failed=1
      if ($0 ~ /^\(enc\)[[:space:]]+/) cipher = $2
      else if ($0 ~ /^\(/ || $0 ~ /^#/) cipher = ""
      if (endpoint != "" && cipher != "" && $0 ~ /\[(fail|warn)\]/) {
        pending[++count] = cipher
      }
    }
    END {flush()}
  ' "$file"
}

start_scan_timing() {
  SCAN_STARTED_AT="$(date '+%Y-%m-%d %H:%M:%S %Z (%z)')"
  SCAN_START_SECONDS=$SECONDS
}

finish_scan_timing() {
  local elapsed=$((SECONDS - SCAN_START_SECONDS))
  SCAN_FINISHED_AT="$(date '+%Y-%m-%d %H:%M:%S %Z (%z)')"
  printf -v SCAN_RUNTIME '%02d:%02d:%02d' \
    "$((elapsed / 3600))" "$((elapsed % 3600 / 60))" "$((elapsed % 60))"
}

print_scan_timing() {
  print_section 'Scan Timing'
  print_summary_row 'Start Time:' "$SCAN_STARTED_AT"
  print_summary_row 'Finish Time:' "$SCAN_FINISHED_AT"
  print_summary_row 'Run Time (HH:MM:SS):' "$SCAN_RUNTIME" "${CLR_BOLD}${CLR_MAGENTA}"
}

die() {
  printf '%sError:%s %s\n' "$CLR_RED" "$CLR_RESET" "$*" >&2
  exit 1
}

need_command() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

command_available() {
  command -v "$1" >/dev/null 2>&1
}

command_available_for_user() {
  local command_name="$1"
  local user_path="$PATH"
  local user_home=""

  if [[ "$BIDENT_DROP_PRIVILEGES" == true && -n "${BIDENT_RUN_USER:-}" ]]; then
    user_home="$(cd ~"$BIDENT_RUN_USER" 2>/dev/null && pwd || true)"
    if [[ -n "$user_home" ]]; then
      user_path="${user_home}/.local/bin:${user_home}/bin:${user_path}"
    fi
    user_path="/opt/homebrew/bin:/usr/local/bin:${user_path}"
    "$SUDO_CMD" -H -u "$BIDENT_RUN_USER" env PATH="$user_path" bash -lc "command -v $(printf '%q' "$command_name")" >/dev/null 2>&1
  else
    command_available "$command_name"
  fi
}

resolve_command() {
  local command_name="$1"
  local candidate
  local user_path="$PATH"
  local user_home=""

  if [[ "$BIDENT_DROP_PRIVILEGES" == true && -n "${BIDENT_RUN_USER:-}" ]]; then
    user_home="$(cd ~"$BIDENT_RUN_USER" 2>/dev/null && pwd || true)"
    if [[ -n "$user_home" ]]; then
      user_path="${user_home}/.local/bin:${user_home}/bin:${user_path}"
    fi
    user_path="/opt/homebrew/bin:/usr/local/bin:${user_path}"
    if candidate="$("$SUDO_CMD" -H -u "$BIDENT_RUN_USER" env PATH="$user_path" bash -lc "command -v $(printf '%q' "$command_name")" 2>/dev/null)"; then
      if [[ -n "$candidate" ]]; then
        printf '%s\n' "$candidate"
        return 0
      fi
    fi
  fi

  if command -v "$command_name" >/dev/null 2>&1; then
    command -v "$command_name"
    return 0
  fi

  for candidate in \
    "/usr/local/bin/${command_name}" \
    "/opt/homebrew/bin/${command_name}" \
    "/usr/bin/${command_name}" \
    "/bin/${command_name}" \
    "/usr/sbin/${command_name}" \
    "/sbin/${command_name}"; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

run_unprivileged() {
  local user_path="$PATH"
  local user_home=""

  if [[ "$BIDENT_DROP_PRIVILEGES" == true && -n "${BIDENT_RUN_USER:-}" ]]; then
    user_home="$(cd ~"$BIDENT_RUN_USER" 2>/dev/null && pwd || true)"
    if [[ -n "$user_home" ]]; then
      user_path="${user_home}/.local/bin:${user_home}/bin:${user_path}"
    fi
    user_path="/opt/homebrew/bin:/usr/local/bin:${user_path}"
    "$SUDO_CMD" -H -u "$BIDENT_RUN_USER" env PATH="$user_path" "$@"
  else
    "$@"
  fi
}

run_privileged() {
  if [[ -n "${PRIVILEGED_CMD_PREFIX:-}" ]]; then
    "$SUDO_CMD" "$@"
  else
    "$@"
  fi
}

run_with_timeout() {
  if [[ "${TOOL_TIMEOUT:-0}" =~ ^[0-9]+$ && "${TOOL_TIMEOUT:-0}" -gt 0 ]] && command_available timeout; then
    if [[ "$BIDENT_DROP_PRIVILEGES" == true && -n "${BIDENT_RUN_USER:-}" ]]; then
      local user_path="$PATH"
      local user_home=""

      user_home="$(cd ~"$BIDENT_RUN_USER" 2>/dev/null && pwd || true)"
      if [[ -n "$user_home" ]]; then
        user_path="${user_home}/.local/bin:${user_home}/bin:${user_path}"
      fi
      user_path="/opt/homebrew/bin:/usr/local/bin:${user_path}"
      timeout --preserve-status "${TOOL_TIMEOUT}" "$SUDO_CMD" -H -u "$BIDENT_RUN_USER" env PATH="$user_path" "$@"
    else
      timeout --preserve-status "${TOOL_TIMEOUT}" "$@"
    fi
  else
    run_unprivileged "$@"
  fi
}

print_progress_bar() {
  local label="$1"
  local current="$2"
  local total="$3"
  local width=28
  local percent=0
  local filled=0
  local bar=""
  local i

  if ((total > 0)); then
    percent=$((current * 100 / total))
    filled=$((percent * width / 100))
  fi

  for ((i = 0; i < width; i++)); do
    if ((i < filled)); then
      bar+="#"
    else
      bar+="."
    fi
  done

  if [[ -t 1 ]]; then
    printf '\r%s%s:%s [%s] %s/%s (%s%%)' "$CLR_CYAN" "$label" "$CLR_RESET" "$bar" "$current" "$total" "$percent"
    if ((current >= total)); then
      printf '\n'
    fi
  else
    printf '%s%s:%s [%s] %s/%s (%s%%)\n' "$CLR_CYAN" "$label" "$CLR_RESET" "$bar" "$current" "$total" "$percent"
  fi
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    printf '%sRun This Command With Sudo:%s\n' "$CLR_YELLOW" "$CLR_RESET" >&2
    printf '  sudo ./bident.sh --install-deps\n' >&2
    exit 1
  fi
}

require_root_scan_run() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    printf '%sRun Bident With Sudo:%s\n' "$CLR_YELLOW" "$CLR_RESET" >&2
    printf '  sudo ./bident.sh (-f <scope-file> | -t <target>)\n' >&2
    exit 1
  fi
}

prepare_privileged_execution() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    PRIVILEGED_CMD_PREFIX=""
    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER:-root}" != "root" ]]; then
      need_command "$SUDO_CMD"
      BIDENT_DROP_PRIVILEGES=true
      BIDENT_RUN_USER="$SUDO_USER"
      printf '%sBident Is Running As Root%s\n' "$CLR_CYAN" "$CLR_RESET"
    else
      BIDENT_DROP_PRIVILEGES=false
      printf '%sBident Is Running As Root%s\n' "$CLR_YELLOW" "$CLR_RESET"
    fi
  else
    require_root_scan_run
  fi
}

allow_unprivileged_output_writes() {
  local failed=false
  if [[ "${BIDENT_DROP_PRIVILEGES:-false}" == true && -n "${BIDENT_RUN_USER:-}" && -n "${RESULTS_DIR:-}" && -d "$RESULTS_DIR" ]]; then
    # Do not follow symlinks outside the results folder. Keep existing group
    # and other permissions; only grant the owning user the required access.
    find -P "$RESULTS_DIR" -exec chown -h "$BIDENT_RUN_USER" {} + || failed=true
    find -P "$RESULTS_DIR" -type d -exec chmod u+rwx {} + || failed=true
    find -P "$RESULTS_DIR" -type f -exec chmod u+rw {} + || failed=true
    if [[ "$failed" == true ]]; then
      printf '%sWarning: Could not fully restore results access for %s: %s%s\n' "$CLR_YELLOW" "$BIDENT_RUN_USER" "$RESULTS_DIR" "$CLR_RESET" >&2
      return 1
    fi
  fi
  return 0
}

finalize_results_on_exit() {
  local exit_status="$1" session_name
  if [[ "$exit_status" -ne 0 ]]; then
    # Stop only scanner sessions started by this run before restoring access.
    for session_name in "${BIDENT_OWNED_SCANS[@]-}"; do
      [[ -n "$session_name" ]] || continue
      if screen_session_exists "$session_name"; then screen -S "$session_name" -X quit || true; fi
    done
  fi
  if [[ "${RESULTS_PERMISSIONS_FINALIZED:-false}" != true ]]; then
    allow_unprivileged_output_writes || true
  fi
  return 0
}

count_files_in_dir() {
  local dir="$1"

  if [[ -d "$dir" ]]; then
    find "$dir" -type f 2>/dev/null | wc -l | tr -d '[:space:]'
  else
    printf '0'
  fi
}

print_final_summary() {
  local scoped_hosts=0
  local live_hosts=0
  local open_rows=0
  local nse_files=0
  local tool_files=0
  local msf_files=0

  [[ -f "$TARGETS_FILE" ]] && scoped_hosts="$(wc -l < "$TARGETS_FILE" | tr -d '[:space:]')"
  [[ -f "$LIVE_TARGETS_FILE" ]] && live_hosts="$(wc -l < "$LIVE_TARGETS_FILE" | tr -d '[:space:]')"
  if [[ -f targets_with_open_ports/open_ports_all.tsv ]]; then
    open_rows="$(awk 'NR > 1 {count++} END {print count + 0}' targets_with_open_ports/open_ports_all.tsv)"
  fi
  nse_files="$(count_files_in_dir "$NSE_DIR")"
  tool_files="$(count_files_in_dir "$TOOL_DIR")"
  if [[ "${NO_MSF:-false}" == true ]]; then
    msf_files=0
  else
    msf_files="$(count_files_in_dir "$MSF_RESULT_DIR")"
  fi

  print_section 'Scan Summary'
  print_summary_row 'Results Folder:' "$PWD"
  print_summary_row 'Scoped Hosts:' "$scoped_hosts" "$CLR_YELLOW"
  print_summary_row 'Live Hosts:' "$live_hosts" "$CLR_GREEN"
  print_summary_row 'Total Ports Open:' "$open_rows" "${CLR_BOLD}${CLR_MAGENTA}"
  print_summary_row 'Nmap Script Result Files:' "$nse_files" "$CLR_GREEN"
  print_summary_row 'External Tool Result Files:' "$tool_files" "$CLR_GREEN"
  print_summary_row 'Metasploit Result Files:' "$msf_files" "$CLR_GREEN"
  if [[ -f report.html ]]; then
    print_summary_row 'HTML Report:' 'report.html' "$CLR_BLUE"
  fi
  if [[ -f summary.json ]]; then
    print_summary_row 'JSON Summary:' 'summary.json' "$CLR_BLUE"
  fi
}
