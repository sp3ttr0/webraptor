usage() {
  printf '%s\n' \
    'Usage: sudo ./bident.sh (-f <scope-file> | -t <target> | --resume <results-dir>) [-o <results-dir>] [-p-] [--no-udp] [--no-msf] [--script-timeout T] [--tool-timeout N] [--msf-timeout N] [--msf-threads N] [--responder] [-T1|-T2|-T3|-T4|-T5]' \
    '       ./bident.sh --check-deps' \
    '       sudo ./bident.sh --install-deps' \
    '' \
    'Bident is a network VAPT helper that expands scope, discovers live hosts,' \
    'runs TCP/UDP port scans, launches targeted follow-up checks, and generates' \
    'organized text outputs plus an HTML report.' \
    '' \
    'Target input:' \
    '  -f <scope-file>   Scope file to scan.' \
    '  -t <target>       Single host to test.' \
    '  --resume <dir>    Resume from an existing Bident results folder.' \
    '' \
    'Options:' \
    '  -o <results-dir>  Write all results into this folder.' \
    '  -p-               Scan all TCP/UDP ports.' \
    '  --check-deps      Show installed and missing tools.' \
    '  --install-deps    Install supported dependencies from Kali/Parrot apt repos.' \
    '                    Package installation may require sudo.' \
    '  --no-msf          Skip Metasploit auxiliary checks.' \
    '  --msf-timeout N   Timeout for each Metasploit port group, in seconds. Default: 120.' \
    '  --msf-threads N   THREADS value for Metasploit scanner modules. Default: 16.' \
    '  --no-udp          Skip UDP scans and UDP follow-up checks.' \
    '  --responder       Start Responder on eth0 in a separate screen session.' \
    '  --script-timeout T NSE limit per instance: 30m default; 0 unlimited.' \
    '  --tool-timeout N  Timeout for external tools, in seconds. Default: disabled.' \
    '  -T1..-T5          Set the Nmap timing template. Default: -T4.' \
    '' \
    'Examples:' \
    '  sudo ./bident.sh -f scope.txt -p- -T4' \
    '  sudo ./bident.sh -f scope.txt --msf-timeout 120 --msf-threads 24' \
    '  sudo ./bident.sh -f scope.txt --no-msf --tool-timeout 300' \
    '  sudo ./bident.sh -t 192.0.2.10 --no-udp -T4' \
    '  ./bident.sh --check-deps' \
    '  sudo ./bident.sh --install-deps' \
    '  sudo ./bident.sh --resume bident_results_20260928_120000'
}

print_section() {
  printf '\n%s%s== %s ==%s\n' "$CLR_BOLD" "$CLR_BRIGHT_RED" "$1" "$CLR_RESET"
  printf '%s------------------------------------------------------------%s\n' "$CLR_GRAY" "$CLR_RESET"
}

print_summary_row() {
  local value_color="${3:-$CLR_WHITE}"
  printf '  %s%-29s%s %s%s%s\n' "$CLR_CYAN" "$1" "$CLR_RESET" "$value_color" "$2" "$CLR_RESET"
}

print_completion() {
  printf '\n%s%s[+] Scan Completed.%s\n\n' "$CLR_BOLD" "$CLR_GREEN" "$CLR_RESET"
}

print_banner() {
  local line=""
  local banner_width=42

  banner_art() {
    cat <<'BIDENT_ART'
           "                "
          ".                '"
         ` ;                ?''
          :!                [_
         .-]               '[]
         ^[{^              ^}]^
         ,{)?              i]-^
         ")((`            ^[]_'
         `)|)] `        ''??_I
          ?)1}l.`      ''_]_l^
           ![]-: `    '._]-l^
           .:!!I,.   "'?[-l`
             ''''. "".^"^'
                ,}rCLj}"
               _$$$$$$$$i
               z$$,"$j dc
               |$$$W$$$$1
               "]B$W8$@~,
               "')|tt|1`"
              ,"""}[+! """
                  """"
                 ,,
BIDENT_ART
  }

  banner_colored_line() {
    local text="$1"
    local i=0
    local ch=""

    while [[ "$i" -lt "${#text}" ]]; do
      ch="${text:i:1}"
      case "$ch" in
        '['|']'|'{'|'}'|'('|')'|'?'|'!'|'1'|'l'|'I'|'_'|'-')
          printf '%s%s%s' "$CLR_BRIGHT_RED" "$ch" "$CLR_RESET"
          ;;
        '$'|'W'|'8'|'B'|'@'|'|')
          printf '%s%s%s' "$CLR_WHITE" "$ch" "$CLR_RESET"
          ;;
        ' ')
          printf ' '
          ;;
        *)
          printf '%s%s%s' "$CLR_GRAY" "$ch" "$CLR_RESET"
          ;;
      esac
      i=$((i + 1))
    done
    printf '\n'
  }

  banner_label_line() {
    local color="$1"
    local text="$2"
    local text_length="${#text}"
    local padding=0

    if ((banner_width > text_length)); then
      padding=$(((banner_width - text_length) / 2))
      padding=$((padding > 3 ? padding - 3 : 0))
    fi
    padding=$((padding + 2))

    printf '%*s%s%s%s\n' "$padding" "" "$color" "$text" "$CLR_RESET"
  }

  printf '\n'
  while IFS= read -r line; do
    banner_colored_line "$line"
  done < <(banner_art)
  printf '\n'
  banner_label_line "${CLR_BOLD}${CLR_BRIGHT_RED}" "Bident"
  banner_label_line "${CLR_BOLD}${CLR_BRIGHT_RED}" "Network VAPT Toolkit"
  banner_label_line "$CLR_GRAY" "by sp3ttr0"
  printf '\n'
}
