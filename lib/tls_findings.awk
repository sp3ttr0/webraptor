# Parse explicit TLS observations, scoped to one endpoint at a time.
# Output: finding ID, endpoint, source line, evidence (FS = ASCII 28).
BEGIN {
  esc = sprintf("%c", 27)
  sep = sprintf("%c", 28)
  today_utc = substr(now_utc, 1, 8) "000000"
  split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", names, " ")
  for (i = 1; i <= 12; i++) months[tolower(names[i])] = i
}
function trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
function record(id, text, detail, key) {
  if (endpoint == "") return
  key = id SUBSEP text
  if (!seen[key]++) {
    ids[++count] = id; texts[count] = text; lines[count] = NR; certs[count] = certificate_id; details[count] = detail
  }
}
function flush(i) {
  for (i = 1; i <= count; i++) {
    # A demonstrated TLS 1.3 success suppresses contradictory negatives even
    # when an unrelated later check in the same invocation fails.
    if (fatal && ids[i] != 11) continue
    # A negative protocol result also needs evidence of a working TLS service.
    if (ids[i] == 5 && (!working || tls13_uncertain || client_tls13_issue)) continue
    if (ids[i] == 10 && certificate_valid[certs[i]]) continue
    output[++output_count] = ids[i] sep endpoint sep lines[i] sep texts[i] sep details[i]
    output_ids[output_count] = ids[i]
  }
  for (i in seen) delete seen[i]
  for (i in ids) delete ids[i]
  for (i in texts) delete texts[i]
  for (i in lines) delete lines[i]
  for (i in certs) delete certs[i]
  for (i in details) delete details[i]
  for (i in certificate_valid) delete certificate_valid[i]
  count = 0; cipher_section = 0; fatal = 0; working = 0; endpoint = ""; proto = 0; proto_heading = ""; script = ""; chain = 0
  tls13_uncertain = 0; leaf_seen = 0; certificate_id = 0
}
function protocol_id(s) {
  gsub(/[[:space:]]/, "", s)
  if (s == "sslv2" || s == "sslv2.0") return 1
  if (s == "sslv3" || s == "sslv3.0") return 2
  if (s == "tls1" || s == "tlsv1" || s == "tls1.0" || s == "tlsv1.0") return 3
  if (s == "tls1.1" || s == "tlsv1.1") return 4
  if (s == "tls1.3" || s == "tlsv1.3") return 11
  if (s == "tls1.2" || s == "tlsv1.2") return 12
  return 0
}
function weak_cipher(s) {
  return s ~ /_cbc_|-cbc|(^|-)(aes|camellia|aria)(128|256)-sha(256|384)?$/ || s ~ /(^|[^a-z])(rc4|rc2|3des|des-cbc3|des-cbc|des-cbc-sha|idea|null|export|adh-|aecd[h]?[-_])|_with_(des|3des|rc4|rc2|null|idea)|_anon_/
}
function expiry_time(s, a, n, t, stamp, year, month, day, hh, mm, ss, days, leap) {
  sub(/^.*not valid after:[[:space:]]*/, "", s)
  if (s ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]t[0-9][0-9]:[0-9][0-9]:[0-9][0-9]z?$/) {
    year = substr(s, 1, 4); month = substr(s, 6, 2); day = substr(s, 9, 2)
    hh = substr(s, 12, 2); mm = substr(s, 15, 2); ss = substr(s, 18, 2)
  } else {
    n = split(trim(s), a, /[[:space:]]+/)
    if (n != 5 || a[5] != "gmt" || !(a[1] in months) || a[4] !~ /^[0-9][0-9][0-9][0-9]$/ || a[2] !~ /^[0-9][0-9]?$/ || a[3] !~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/) return ""
    month = months[a[1]]; day = a[2]; year = a[4]
    if (split(a[3], t, ":") != 3) return ""
    hh = t[1]; mm = t[2]; ss = t[3]
  }
  if ((year + 0) < 1970 || (month + 0) < 1 || (month + 0) > 12 || (day + 0) < 1 || (day + 0) > 31 || (hh + 0) > 23 || (mm + 0) > 59 || (ss + 0) > 59) return ""
  leap = (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))
  days = 31
  if (month + 0 == 2) days = leap ? 29 : 28
  else if (month + 0 == 4 || month + 0 == 6 || month + 0 == 9 || month + 0 == 11) days = 30
  if (day + 0 > days) return ""
  stamp = sprintf("%04d%02d%02d%02d%02d%02d", year, month, day, hh, mm, ss)
  return stamp
}
{
  line = $0
  gsub(esc "\\[[0-?]*[ -/]*[@-~]", "", line)
  gsub(/\[[0-9;]*m/, "", line)
  gsub(/\r/, "", line)
  # Local TLS 1.3 capability warnings can precede the endpoint banner. They
  # invalidate negative conclusions throughout this saved tool output.
  diagnostic = tolower(line)
  if (diagnostic ~ /tls[[:space:]]*v?1[.]3/ && diagnostic ~ /client|openssl|local|build|compiled/ && diagnostic ~ /cannot|unable|unavailable|unsupported|not support|not compiled|lacks/) client_tls13_issue = 1
  if (line ~ /^===== /) { flush(); next }
  if (line ~ /^Command:/) {
    flush()
    # Bident logs one external-tool invocation per endpoint. The target must
    # be explicit: a scope file or a missing output block is never evidence.
    if (line ~ /(^|[\/[:space:]])(testssl([.]sh)?|sslscan)[[:space:]]/) {
      n = split(trim(line), args, /[[:space:]]+/)
      endpoint = args[n]; sub(/^https:\/\//, "", endpoint); sub(/\/$/, "", endpoint)
      if (endpoint !~ /:[0-9]+$/) endpoint = ""
    }
    next
  }
  if (kind == "nse" && line ~ /^Nmap scan report for /) {
    flush(); n = split(line, a, /[[:space:]]+/); host = a[n]; gsub(/[()]/, "", host); next
  }
  if (kind == "nse" && line ~ /^[0-9]+\/(tcp|udp)[[:space:]]/) {
    flush()
    if (line !~ /^[0-9]+\/tcp[[:space:]]+open[[:space:]]/) next
    port = line; sub(/\/.*/, "", port)
    endpoint = (host ~ /:/ ? "[" host "]" : host) ":" port
    next
  }
  if (kind == "nse" && line ~ /^Host script results:/) { flush(); next }
  if (kind == "testssl" && line ~ /-->>[[:space:]]+[^[:space:]]+:[0-9]+/) {
    # testssl may emit multiple resolved-IP blocks for one hostname.
    flush(); peer = line; sub(/^.*-->>[[:space:]]*/, "", peer); sub(/[[:space:]].*$/, "", peer); endpoint = peer
    next
  }
  if (kind == "sslscan" && line ~ /^Testing SSL server /) {
    flush(); n = split(line, a, /[[:space:]]+/)
    endpoint = (a[4] ~ /:/ && a[4] !~ /^\[/ ? "[" a[4] "]" : a[4]) ":" a[7]
    next
  }
  if (endpoint == "") next
  original = trim(line)
  # Strip NSE tree decoration only after preserving the source line number.
  sub(/^\|[_ ]*/, "", line)
  lower = tolower(trim(line))
  if (lower ~ /^bident tls result: incomplete/ || (kind == "nse" && lower ~ /error:.*(script execution failed|timed out|timeout)/)) fatal = 1
  if (lower ~ /^(fatal|error|warning:.*(connect|socket))|connection refused|unable to connect|could not connect|connection failed|no route to host|scan aborted|no ssl\/tls support|nse:.*(timed out|timeout)/) fatal = 1
  if (lower ~ /timed out|timeout|handshake failed|could not test|cannot test|unable to test|test.*inconclusive|test.*unavailable/) tls13_uncertain = 1
  if (lower ~ /ssl certificate chain|certificate chain:/) chain = 1
  if (lower ~ /^ssl certificate:/) { chain = 0; leaf_seen = 1; certificate_id++ }
  if (kind == "testssl" && lower ~ /^certificate #[0-9]+/) { chain = 0; certificate_id++ }

  if (kind != "nse") {
    if (match(lower, /^(sslv[23]([.]0)?|tlsv?[[:space:]]*1([.][0-3])?)[[:space:]]+/)) {
      token = substr(lower, 1, RLENGTH); rest = substr(lower, RLENGTH + 1); id = protocol_id(token)
      if (rest ~ /^(enabled|offered)([^a-z]|$)/ && rest !~ /not offered|unknown|cannot|could not|failed|local problem/) {
        working = 1
        if (id > 0 && id != 12) record(id, original)
      }
      if (id == 11 && rest ~ /^(disabled|not offered)([[:space:]]|$)/ && rest !~ /likely|unknown|unable|cannot|could not|client|openssl|failed|plaintext|downgrad|error|inconclusive/) record(5, original)
    }
    # sslscan enumerates accepted/preferred suites; rejected suites are not findings.
    if (lower ~ /^(accepted|preferred)[[:space:]]+/ && lower !~ /not accepted|rejected|not offered|failed|unknown/) {
      split(lower, accepted, /[[:space:]]+/)
      if (!protocol_id(accepted[2])) next
      working = 1
      if (protocol_id(accepted[2]) == 11) record(11, original)
      suite = ""
      split(trim(line), suite_fields, /[[:space:]]+/)
      for (field in suite_fields) if (tolower(suite_fields[field]) == "bits") suite = suite_fields[field + 1]
      if (suite != "" && weak_cipher(tolower(suite))) record(6, original, suite)
    }
    # Only successful remote enumeration tables establish individual suites.
    # Local cipher catalogues and client simulation tables are not observations.
    if (kind == "testssl") {
      if (lower ~ /^testing .*ciphers.*against the server/) cipher_section = 1
      else if (lower ~ /^(testing |running |done )/) cipher_section = 0
      if (cipher_section && lower ~ /^(0x|x)[0-9a-f,]+[[:space:]]/ && lower !~ /not offered|rejected|failed|not accepted/) {
        cipher_field_count=split(trim(line), cipher_fields, /[[:space:]]+/)
        suite=""; fallback_suite=""
        for (field=2; field<=cipher_field_count; field++) {
          if (cipher_fields[field] ~ /^(TLS|SSL)_[A-Z0-9_]+$/) suite=cipher_fields[field]
          if (field == 2) fallback_suite=cipher_fields[field]
        }
        if (suite == "") suite=fallback_suite
        if (suite != "" && weak_cipher(tolower(suite))) record(6, original, suite)
      }
    }
    # testssl category rows must affirm that a weak suite/category was offered.
    if (kind == "testssl" && lower ~ /^(null ciphers|anonymous null ciphers|export ciphers|low:|triple des ciphers|obsolete[d]? .*ciphers|rc4)/ && lower ~ /[[:space:]]offered([^a-z]|$)/ && lower !~ /not offered|not vulnerable|unknown|could not|cannot|failed/) {
      category = trim(line); sub(/[[:space:]]+offered.*$/, "", category)
      record(6, original, "Category only: " category)
    }
    if (kind == "testssl" && lower ~ /^breach[[:space:](]/ && (lower ~ /(gzip|deflate|compress|br):[[:space:]]*yes/ || lower ~ /(gzip|deflate|compress|br).*http compression detected/) && lower !~ /not vulnerable|no .*compression|failed|unknown|stalled/) record(7, original)
  } else {
    if (lower ~ /^(ssl-cert|ssl-enum-ciphers):/ || original ~ /^\|[_ ]?sslv2:/) {
      script = lower; sub(/:.*/, "", script); proto = 0; proto_heading = ""
      sub(/^[^:]*:[[:space:]]*/, "", lower)
    }
    if (script == "ssl-enum-ciphers" && lower ~ /^(sslv[23]([.]0)?|tlsv?1([.][0-3])?):$/) { token = lower; sub(/:$/, "", token); proto = protocol_id(token); proto_heading = original }
    if (script == "sslv2" && lower ~ /sslv2 supported/) { record(1, original); working = 1 }
    if (script == "ssl-enum-ciphers" && lower ~ /^tls_[a-z0-9_]+[[:space:]]+.* - [a-f]$/) {
      working = 1
      if (proto && proto != 12) record(proto, proto_heading " | " original)
      split(trim(line), suite_fields, /[[:space:]]+/)
      if (weak_cipher(tolower(suite_fields[1])) || lower ~ / - [df]$/) record(6, proto_heading " | " original, suite_fields[1])
    }
    # Missing TLS 1.3 headings never establish that TLS 1.3 is disabled.
  }

  cert = !chain && (kind != "nse" || script == "ssl-cert") && (kind != "sslscan" || leaf_seen)
  wildcard_field = (lower ~ /^(common name|subject alternative name|altnames|x509v3 subject alternative name)/ || (lower ~ /^subject:/ && lower ~ /(commonname|cn)[[:space:]]*=[^\/,]*\*/))
  if (cert && wildcard_field && lower ~ /\*/) record(8, original)
  if (cert && lower ~ /^signature algorithm[[:space:]:]/ && lower ~ /(^|[^a-z0-9])(md5|md2|sha-?1)(with|[[:space:]-]|$)/) record(9, original)
  if (cert && lower ~ /^certificate validity[[:space:]]/ && lower !~ /unknown|cannot|unable|failed/) {
    # testssl prints a validity range; the final ISO date is the expiry date.
    remaining = lower; end_date = ""
    while (match(remaining, /[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]/)) {
      end_date = substr(remaining, RSTART, RLENGTH)
      remaining = substr(remaining, RSTART + RLENGTH)
    }
    if (end_date != "") {
      expires = expiry_time(end_date "t00:00:00z")
      if (expires != "") {
        if (expires + 0 < today_utc + 0) record(10, original)
        else certificate_valid[certificate_id] = 1
      }
    }
  }
  if (cert && lower ~ /^not valid after:/) {
    expires = expiry_time(lower)
    if (expires != "") {
      if (expires + 0 < today_utc + 0) record(10, original)
      else certificate_valid[certificate_id] = 1
    }
  }
}
END {
  flush()
  # A scanner capability warning can appear after earlier endpoint blocks.
  for (i = 1; i <= output_count; i++) if (output_ids[i] != 5 || !client_tls13_issue) print output[i]
}
