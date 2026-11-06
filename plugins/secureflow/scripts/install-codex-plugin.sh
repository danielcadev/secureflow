#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
plugin_dir=$(cd -- "$script_dir/.." && pwd -P)
repo_root=$(cd -- "$plugin_dir/../.." && pwd -P)

command -v codex >/dev/null 2>&1 || {
  echo "secureflow: Codex CLI is required" >&2
  exit 1
}
command -v secureflow >/dev/null 2>&1 || {
  echo "secureflow: install the matching secureflow binary on PATH first" >&2
  exit 1
}
command -v node >/dev/null 2>&1 || {
  echo "secureflow: Node.js is required to check the plugin version" >&2
  exit 1
}
expected_version=$(node -e 'process.stdout.write(require(process.argv[1]).version)' "$plugin_dir/.codex-plugin/plugin.json")
actual_version=$(secureflow --version)
if [[ "$actual_version" != "secureflow $expected_version" ]]; then
  echo "secureflow: CLI/plugin version mismatch: expected $expected_version, got $actual_version" >&2
  exit 1
fi
marketplace_name=$(node -e 'process.stdout.write(require(process.argv[1]).name)' "$repo_root/.agents/plugins/marketplace.json")

if ! codex plugin marketplace list --json | grep -Fq "\"source\": \"$repo_root\""; then
  codex plugin marketplace add "$repo_root"
fi
codex plugin add "secureflow@$marketplace_name"
echo "SecureFlow installed. Start a new Codex task to load its skill and MCP tools."
