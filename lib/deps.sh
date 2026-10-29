print_dependency_status() {
  local tool
  local missing_core=0
  local missing_optional=0

  printf '%sCore Tools%s\n' "$CLR_BOLD" "$CLR_RESET"
  for tool in "${CORE_TOOLS[@]}"; do
    if command_available "$tool"; then
      printf '  %s[OK]%s %s\n' "$CLR_GREEN" "$CLR_RESET" "$tool"
    else
      printf '  %s[MISSING]%s %s\n' "$CLR_YELLOW" "$CLR_RESET" "$tool"
      missing_core=$((missing_core + 1))
    fi
  done

  printf '%sOptional Tools%s\n' "$CLR_BOLD" "$CLR_RESET"
  for tool in "${OPTIONAL_TOOLS[@]}"; do
    if command_available "$tool"; then
      printf '  %s[OK]%s %s\n' "$CLR_GREEN" "$CLR_RESET" "$tool"
    else
      printf '  %s[MISSING]%s %s\n' "$CLR_YELLOW" "$CLR_RESET" "$tool"
      missing_optional=$((missing_optional + 1))
    fi
  done

  printf '%sMissing Core:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$missing_core"
  printf '%sMissing Optional:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$missing_optional"
}

detect_package_manager() {
  if command_available apt-get; then
    printf 'apt'
  else
    printf 'unknown'
  fi
}

apt_package_available() {
  apt-cache show "$1" >/dev/null 2>&1
}

install_apt_dependencies() {
  local packages=(
    nmap screen dnsutils ldap-utils smbclient samba-common-bin sslscan
    ike-scan ssh-audit python3-impacket responder metasploit-framework
    testssl.sh netexec
  )
  local candidate
  local installable_packages=()

  for candidate in "${packages[@]}"; do
    if apt_package_available "$candidate"; then
      installable_packages+=("$candidate")
    else
      printf '%sSkipping Package:%s %s is not available in configured apt repositories.\n' "$CLR_YELLOW" "$CLR_RESET" "$candidate"
    fi
  done

  if [[ "${#installable_packages[@]}" -eq 0 ]]; then
    die "No supported Bident packages were found in configured apt repositories."
  fi

  apt-get update
  apt-get install -y "${installable_packages[@]}"
}

install_dependencies() {
  local package_manager

  package_manager="$(detect_package_manager)"
  printf '%sDetected Package Manager:%s %s\n' "$CLR_CYAN" "$CLR_RESET" "$package_manager"

  case "$package_manager" in
    apt)
      require_root
      install_apt_dependencies
      ;;
    *)
      die "--install-deps currently supports Kali/Parrot-style apt repositories only."
      ;;
  esac

  printf '%sDependency Installation Finished.%s\n' "$CLR_GREEN" "$CLR_RESET"
  print_dependency_status
}

check_external_tool_startup() {
  local output
  local TOOL_TIMEOUT=20
  NETEXEC_STARTUP_OK=false
  RPCDUMP_STARTUP_OK=false
  output="$(mktemp "${TMPDIR:-/tmp}/bident_startup.XXXXXX")"
  # Listing modules loads the SMB implementation; --help can exit before
  # importing the dependencies used during a real SMB check. No targets given.
  if run_external_capture 'NetExec SMB startup check' "$output" netexec smb -L; then
    NETEXEC_STARTUP_OK=true
  else
    printf '  %s[INCOMPLETE]%s NetExec SMB checks will be skipped for this run.\n' "$CLR_YELLOW" "$CLR_RESET"
  fi
  if run_external_capture 'impacket-rpcdump startup check' "$output" impacket-rpcdump -h; then
    RPCDUMP_STARTUP_OK=true
  else
    printf '  %s[INCOMPLETE]%s impacket-rpcdump checks will be skipped for this run.\n' "$CLR_YELLOW" "$CLR_RESET"
  fi
  rm -f "$output"
}
