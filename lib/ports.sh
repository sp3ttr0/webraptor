has_open_port() {
  local proto="$1"
  shift
  local files=()
  local file
  local port

  case "$proto" in
    tcp)
      files=("${SCAN_DIR}/syn.gnmap" "${SCAN_DIR}/con.gnmap")
      ;;
    udp)
      files=("${SCAN_DIR}/udp.gnmap")
      ;;
    any)
      files=("${SCAN_DIR}/syn.gnmap" "${SCAN_DIR}/con.gnmap" "${SCAN_DIR}/udp.gnmap")
      ;;
    *)
      die "Unknown protocol for port check: $proto"
      ;;
  esac

  for port in "$@"; do
    for file in "${files[@]}"; do
      [[ -s "$file" ]] || continue
      if awk -v wanted_port="$port" -v wanted_proto="$proto" '
        /Ports: / {
          ports = $0
          sub(/^.*Ports: /, "", ports)
          sub(/\t.*/, "", ports)
          count = split(ports, entries, ", ")
          for (i = 1; i <= count; i++) {
            split(entries[i], fields, "/")
            if (fields[1] == wanted_port && fields[2] == "open" &&
                (wanted_proto == "any" || fields[3] == wanted_proto)) {
              found = 1
            }
          }
        }
        END {
          if (found) {
            exit 0
          }
          exit 1
        }
      ' "$file"; then
        return 0
      fi
    done
  done

  return 1
}

has_any_open_port() {
  local file

  for file in "${SCAN_DIR}/syn.gnmap" "${SCAN_DIR}/con.gnmap" "${SCAN_DIR}/udp.gnmap"; do
    [[ -s "$file" ]] || continue
    if awk '
      /Ports: / {
        ports = $0
        sub(/^.*Ports: /, "", ports)
          sub(/\t.*/, "", ports)
        count = split(ports, entries, ", ")
        for (i = 1; i <= count; i++) {
          split(entries[i], fields, "/")
          if (fields[2] == "open") {
            found = 1
          }
        }
      }
      END {
        if (found) {
          exit 0
        }
        exit 1
      }
    ' "$file"; then
      return 0
    fi
  done

  return 1
}

open_target_ports() {
  local proto="$1"
  shift
  local files=()
  local file
  local port_args

  case "$proto" in
    tcp)
      files=("${SCAN_DIR}/syn.gnmap" "${SCAN_DIR}/con.gnmap")
      ;;
    udp)
      files=("${SCAN_DIR}/udp.gnmap")
      ;;
    any)
      files=("${SCAN_DIR}/syn.gnmap" "${SCAN_DIR}/con.gnmap" "${SCAN_DIR}/udp.gnmap")
      ;;
    *)
      die "Unknown protocol for target-port extraction: $proto"
      ;;
  esac

  port_args="$*"
  for file in "${files[@]}"; do
    [[ -s "$file" ]] || continue
    awk -v wanted_proto="$proto" -v wanted_ports="$port_args" '
      BEGIN {
        split(wanted_ports, raw_ports, " ")
        for (i in raw_ports) {
          wanted[raw_ports[i]] = 1
        }
      }
      /Ports: / {
        target = $2
        ports = $0
        sub(/^.*Ports: /, "", ports)
          sub(/\t.*/, "", ports)
        count = split(ports, entries, ", ")
        for (i = 1; i <= count; i++) {
          split(entries[i], fields, "/")
          if (wanted[fields[1]] && fields[2] == "open" &&
              (wanted_proto == "any" || fields[3] == wanted_proto)) {
            print target, fields[1]
          }
        }
      }
    ' "$file"
  done | awk '!seen[$1 ":" $2]++'
}

open_targets_file_for_ports() {
  local proto="$1"
  local ports_csv="$2"
  local label="$3"
  local report_dir="targets_with_open_ports/nse_targets"
  local safe_ports
  local outfile
  local ports=()

  mkdir -p "$report_dir"
  safe_ports="$(printf '%s' "$ports_csv" | tr ',' '_')"
  outfile="${report_dir}/${proto}_${safe_ports}.txt"

  IFS=',' read -r -a ports <<< "$ports_csv"
  open_target_ports "$proto" "${ports[@]}" | awk '{print $1}' | awk '!seen[$0]++' > "$outfile"
  [[ -s "$outfile" ]] || rm -f "$outfile"
  printf '%s' "$outfile"
}

port_has_targeted_followup() {
  local proto="$1"
  local port="$2"

  case "${proto}/${port}" in
    tcp/21|tcp/22|tcp/23|tcp/25|tcp/53|udp/53|tcp/80|tcp/81|tcp/88|tcp/110|tcp/111|udp/111|udp/123|tcp/135|udp/137|tcp/139|tcp/389|tcp/443|tcp/445|tcp/465|tcp/587|tcp/636|udp/161|udp/162|udp/500|udp/623|tcp/993|tcp/995|tcp/1433|tcp/1521|tcp/2049|tcp/3268|tcp/3269|tcp/3306|tcp/3389|tcp/5800|tcp/5801|tcp/5900|tcp/5901|tcp/8000|tcp/8009|tcp/8080|tcp/8443|udp/5060)
      return 0
      ;;
  esac

  return 1
}

all_open_target_ports() {
  local file

  for file in "${SCAN_DIR}/syn.gnmap" "${SCAN_DIR}/con.gnmap" "${SCAN_DIR}/udp.gnmap"; do
    [[ -s "$file" ]] || continue
    awk '
      /Ports: / {
        target = $2
        ports = $0
        sub(/^.*Ports: /, "", ports)
          sub(/\t.*/, "", ports)
        count = split(ports, entries, ", ")
        for (i = 1; i <= count; i++) {
          split(entries[i], fields, "/")
          if (fields[2] == "open") {
            print target, fields[3], fields[1]
          }
        }
      }
    ' "$file"
  done | awk '!seen[$1 ":" $2 ":" $3]++'
}

generate_services_report() {
  local report_dir="targets_with_open_ports"
  local services_tsv="${report_dir}/services.tsv"
  local file

  mkdir -p "$report_dir"

  {
    printf 'target\tprotocol\tport\tname\tinfo\ttarget_port\n'
    for file in "${SCAN_DIR}/syn.gnmap" "${SCAN_DIR}/con.gnmap" "${SCAN_DIR}/udp.gnmap"; do
      [[ -s "$file" ]] || continue
      awk '
        function trim(value) {
          gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
          return value
        }
        /Ports: / {
          target = $2
          ports = $0
          sub(/^.*Ports: /, "", ports)
          sub(/\t.*/, "", ports)
          count = split(ports, entries, ", ")
          for (i = 1; i <= count; i++) {
            field_count = split(entries[i], fields, "/")
            if (fields[2] != "open") {
              continue
            }
            port = fields[1]
            proto = fields[3]
            name = trim(fields[5])
            info = ""
            for (j = 7; j <= field_count; j++) {
              if (fields[j] == "") {
                continue
              }
              info = info ? info "/" fields[j] : fields[j]
            }
            info = trim(info)
            if (name == "") {
              name = "unknown"
            }
            print target "\t" proto "\t" port "\t" name "\t" info "\t" target ":" port
          }
        }
      ' "$file"
    done | awk -F '\t' '
      {
        key = $1 FS $2 FS $3
        if (!(key in seen)) {
          order[++order_count] = key
          seen[key] = 1
          row[key] = $0
          info[key] = $5
        } else if (info[key] == "" && $5 != "") {
          row[key] = $0
          info[key] = $5
        }
      }
      END {
        for (i = 1; i <= order_count; i++) {
          print row[order[i]]
        }
      }
    ' | sort -t "$(printf '\t')" -k3,3n -k2,2 -k1,1
  } > "$services_tsv"
}

generate_open_port_reports() {
  local report_dir="targets_with_open_ports"
  local report_tsv="${report_dir}/open_ports_all.tsv"
  local legacy_report_tsv="${report_dir}/open_ports_mentioned.tsv"
  local report_txt="${report_dir}/open_ports_by_target.txt"
  local proto
  local port
  local port_file

  mkdir -p "$report_dir"

  {
    printf 'target\tprotocol\tport\n'
    all_open_target_ports | awk '{print $1 "\t" $2 "\t" $3}'
  } | awk 'NR == 1 || !seen[$0]++' | sort -t "$(printf '\t')" -k3,3n -k2,2 -k1,1 > "$report_tsv"

  cp "$report_tsv" "$legacy_report_tsv"

  awk -F '\t' 'NR > 1 {print $2 "\t" $3}' "$report_tsv" | sort -u -k2,2n -k1,1 |
    while IFS=$'\t' read -r proto port; do
      [[ -n "${proto:-}" && -n "${port:-}" ]] || continue
      port_file="${report_dir}/${proto}_${port}.txt"
      awk -F '\t' -v wanted_proto="$proto" -v wanted_port="$port" \
        'NR > 1 && $2 == wanted_proto && $3 == wanted_port {print $1}' "$report_tsv" > "$port_file"
      [[ -s "$port_file" ]] || rm -f "$port_file"
    done

  awk '
    NR == 1 {
      next
    }
    {
      key = $1
      entry = $2 "/" $3
      if (!seen[key, entry]++) {
        ports[key] = ports[key] ? ports[key] ", " entry : entry
      }
    }
    END {
      for (target in ports) {
        print target ": " ports[target]
      }
    }
  ' "$report_tsv" | sort > "$report_txt"

  generate_services_report
}

json_escape_text() {
  printf '%s' "$1" | awk '
    {
      gsub(/\\/, "\\\\")
      gsub(/"/, "\\\"")
      gsub(/\t/, "\\t")
      gsub(/\r/, "\\r")
      gsub(/\n/, "\\n")
      printf "%s", $0
    }
  '
}

generate_json_summary() {
  local summary_file="summary.json"
  local open_tsv="targets_with_open_ports/open_ports_all.tsv"
  local services_tsv="targets_with_open_ports/services.tsv"
  local scope_count=0
  local live_count=0
  local open_rows=0
  local service_rows=0
  local generated_at
  local first=true
  local target
  local proto
  local port
  local name
  local info
  local target_port

  [[ -f "$TARGETS_FILE" ]] && scope_count="$(wc -l < "$TARGETS_FILE" | tr -d '[:space:]')"
  [[ -f "$LIVE_TARGETS_FILE" ]] && live_count="$(wc -l < "$LIVE_TARGETS_FILE" | tr -d '[:space:]')"
  [[ -f "$open_tsv" ]] && open_rows="$(awk 'NR > 1 {count++} END {print count + 0}' "$open_tsv")"
  [[ -f "$services_tsv" ]] && service_rows="$(awk 'NR > 1 {count++} END {print count + 0}' "$services_tsv")"
  generated_at="$(date '+%Y-%m-%dT%H:%M:%S%z')"

  {
    printf '{\n'
    printf '  "generated_at": "%s",\n' "$(json_escape_text "$generated_at")"
    printf '  "counts": {\n'
    printf '    "scoped_hosts": %s,\n' "$scope_count"
    printf '    "live_hosts": %s,\n' "$live_count"
    printf '    "open_target_port_rows": %s,\n' "$open_rows"
    printf '    "services": %s\n' "$service_rows"
    printf '  },\n'
    printf '  "files": {\n'
    printf '    "html_report": "report.html",\n'
    printf '    "targets": "%s",\n' "$(json_escape_text "$TARGETS_FILE")"
    printf '    "live_targets": "%s",\n' "$(json_escape_text "$LIVE_TARGETS_FILE")"
    printf '    "open_ports": "%s",\n' "$(json_escape_text "$open_tsv")"
    printf '    "services": "%s"\n' "$(json_escape_text "$services_tsv")"
    printf '  },\n'
    printf '  "open_ports": [\n'
    first=true
    if [[ -s "$open_tsv" ]]; then
      while IFS=$'\t' read -r target proto port; do
        [[ -n "${target:-}" ]] || continue
        if [[ "$first" == true ]]; then
          first=false
        else
          printf ',\n'
        fi
        printf '    {"host": "%s", "protocol": "%s", "port": %s, "host_port": "%s:%s"}' \
          "$(json_escape_text "$target")" "$(json_escape_text "$proto")" "$port" "$(json_escape_text "$target")" "$(json_escape_text "$port")"
      done < <(awk -F '\t' 'NR > 1' "$open_tsv")
    fi
    printf '\n  ],\n'
    printf '  "services": [\n'
    first=true
    if [[ -s "$services_tsv" ]]; then
      while IFS=$'\034' read -r target proto port name info target_port; do
        [[ -n "${target:-}" ]] || continue
        if [[ "$first" == true ]]; then
          first=false
        else
          printf ',\n'
        fi
        printf '    {"host": "%s", "protocol": "%s", "port": %s, "name": "%s", "info": "%s", "host_port": "%s"}' \
          "$(json_escape_text "$target")" "$(json_escape_text "$proto")" "$port" "$(json_escape_text "$name")" "$(json_escape_text "$info")" "$(json_escape_text "$target_port")"
      done < <(awk -F '\t' 'NR > 1 {print $1 "\034" $2 "\034" $3 "\034" $4 "\034" $5 "\034" $6}' "$services_tsv")
    fi
    printf '\n  ]\n'
    printf '}\n'
  } > "$summary_file"

  printf '%sWrote JSON Summary:%s %s\n' "$CLR_GREEN" "$CLR_RESET" "$summary_file"
}
