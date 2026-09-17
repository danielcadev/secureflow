#!/usr/bin/env bash
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
output_dir=$(mktemp -d)
trap 'rm -rf "$output_dir"' EXIT

case_path="$output_dir/security-case.json"
sarif_path="$output_dir/security-case.sarif"

cd "$root_dir"
cargo run -q -p secureflow -- case-create \
  --run-manifest tests/fixtures/minimal-run-with-finding.json \
  --output "$case_path"
cargo run -q -p secureflow -- case-validate "$case_path"
cargo run -q -p secureflow -- case-list "$case_path" --format json
cargo run -q -p secureflow -- case-export-sarif \
  --case "$case_path" \
  --output "$sarif_path"

printf 'Security Case demo passed: no target transport, no agent transport, and no final human decision were performed.\n'
