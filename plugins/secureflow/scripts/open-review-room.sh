#!/usr/bin/env bash
set -euo pipefail

port=3001
open_browser=1
app_dir="${SECUREFLOW_REVIEW_ROOM_DIR:-}"

usage() {
  echo "usage: open-review-room.sh [--app-dir PATH] [--port PORT] [--no-open]" >&2
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
    --no-open)
      open_browser=0
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

url="http://127.0.0.1:$port/"
echo "SecureFlow Review Room: $url" >&2
if ((open_browser)); then
  if command -v xdg-open >/dev/null 2>&1; then
    (sleep 2; xdg-open "$url" >/dev/null 2>&1 || true) &
  elif command -v open >/dev/null 2>&1; then
    (sleep 2; open "$url" >/dev/null 2>&1 || true) &
  else
    echo "Open $url in a browser after the server is ready." >&2
  fi
fi

cd -- "$app_dir"
exec npm start -- --ip 127.0.0.1 --port "$port"
