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
  echo "secureflow: install the secureflow 1.0.0-rc.2 binary on PATH first" >&2
  exit 1
}

if ! codex plugin marketplace list --json | grep -Fq "\"source\": \"$repo_root\""; then
  codex plugin marketplace add "$repo_root"
fi
codex plugin add secureflow@personal
echo "SecureFlow installed. Start a new Codex task to load its skill and MCP tools."
