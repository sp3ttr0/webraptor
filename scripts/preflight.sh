#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

bash -n bident.sh

for file in lib/*.sh; do
  bash -n "$file"
done

awk -v kind=testssl -v now_utc=20260101000000 -f lib/tls_findings.awk /dev/null

printf 'Preflight checks passed.\n'
