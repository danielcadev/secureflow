#!/usr/bin/env bash
set -euo pipefail

port=3001
session_port=""
open_system_browser=0
app_dir="${SECUREFLOW_REVIEW_ROOM_DIR:-}"
case_paths=()

usage() {
  echo "usage: open-review-room.sh [--app-dir PATH] [--port PORT] [--session-port PORT] [--case PATH]... [--system-browser]" >&2
}

while (($#)); do
  case "$1" in
    --app-dir)
      (($# >= 2)) || { usage; exit 2; }
      app_dir=$2
      shift 2
      ;;
    --port)
      (($# >= 2)) || { usage; exit 2; }
      port=$2
      shift 2
      ;;
    --session-port)
      (($# >= 2)) || { usage; exit 2; }
      session_port=$2
      shift 2
      ;;
    --case)
      (($# >= 2)) || { usage; exit 2; }
      case_paths+=("$2")
      shift 2
      ;;
    --system-browser)
      open_system_browser=1
      shift
      ;;
    --no-open)
      # Retained for compatibility. Not opening an external browser is now the
      # safe default so Codex can present the URL in its own browser panel.
      open_system_browser=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ ! "$port" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
  echo "secureflow: port must be an integer from 1 to 65535" >&2
  exit 2
fi
if [[ -z "$session_port" ]]; then
  ((port < 65535)) || {
    echo "secureflow: --session-port is required when --port is 65535" >&2
    exit 2
  }
  session_port=$((port + 1))
fi
if [[ ! "$session_port" =~ ^[0-9]+$ ]] ||
  ((session_port < 1 || session_port > 65535 || session_port == port)); then
  echo "secureflow: session port must be a different integer from 1 to 65535" >&2
  exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
plugin_dir=$(cd -- "$script_dir/.." && pwd -P)
repo_root=$(cd -- "$plugin_dir/../.." && pwd -P)
if [[ -z "$app_dir" ]]; then
  app_dir="$repo_root/apps/review-room"
fi
if [[ ! -f "$app_dir/package.json" ]]; then
  echo "secureflow: Review Room not found at $app_dir" >&2
  echo "Set SECUREFLOW_REVIEW_ROOM_DIR or pass --app-dir from a SecureFlow source checkout." >&2
  exit 1
fi
if [[ ! -f "$app_dir/dist/server/wrangler.json" ]]; then
  echo "secureflow: Review Room has not been built" >&2
  echo "Run 'npm ci && npm run build' in $app_dir before opening it." >&2
  exit 1
fi
command -v npm >/dev/null 2>&1 || {
  echo "secureflow: npm is required to run Review Room" >&2
  exit 1
}
if ((${#case_paths[@]})); then
  command -v node >/dev/null 2>&1 || {
    echo "secureflow: Node.js is required to load Review Room cases" >&2
    exit 1
  }
  command -v secureflow >/dev/null 2>&1 || {
    echo "secureflow: the secureflow CLI is required to validate Review Room cases" >&2
    exit 1
  }
  for case_path in "${case_paths[@]}"; do
    secureflow case-validate "$case_path" >/dev/null
  done
  session_args=(--app-dir "$app_dir" --port "$port" --session-port "$session_port")
  if ((open_system_browser)); then
    session_args+=(--system-browser)
  fi
  for case_path in "${case_paths[@]}"; do
    session_args+=(--case "$case_path")
  done
  exec node "$plugin_dir/scripts/run-review-session.mjs" "${session_args[@]}"
fi

url="http://127.0.0.1:$port/"
echo "SecureFlow Review Room: $url" >&2
if ((open_system_browser)); then
  if command -v xdg-open >/dev/null 2>&1; then
    (sleep 2; xdg-open "$url" >/dev/null 2>&1 || true) &
  elif command -v open >/dev/null 2>&1; then
    (sleep 2; open "$url" >/dev/null 2>&1 || true) &
  else
    echo "Open $url in a browser after the server is ready." >&2
  fi
fi

cd -- "$app_dir"
WRANGLER_SEND_METRICS=false npm start -- --local --ip 127.0.0.1 --port "$port"
