#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
for dependency in bash python3 node; do
  command -v "$dependency" >/dev/null || { printf 'Tests require %s.\n' "$dependency" >&2; exit 1; }
done
bash scripts/preflight.sh
for suite in findings metasploit report runtime tls; do
  bash "tests/test_${suite}.sh"
done
node tests/test_copy_targets.js
printf 'All test suites passed.\n'
