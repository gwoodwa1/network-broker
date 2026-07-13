#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

failures=()

run_check() {
  local name="$1"
  shift

  echo "==> ${name}"
  if "$@"; then
    echo "PASS: ${name}"
  else
    echo "FAIL: ${name}"
    failures+=("${name}")
  fi
}

run_check "golangci-lint configuration" golangci-lint config verify
run_check "golangci-lint" golangci-lint run
run_check "unit and race tests" go test -race -count=1 ./...
run_check "gosec" gosec ./...
run_check "govulncheck" govulncheck ./...

if (( ${#failures[@]} > 0 )); then
  echo "Quality checks failed:"
  printf ' - %s\n' "${failures[@]}"
  exit 1
fi

echo "All quality and security checks passed."
