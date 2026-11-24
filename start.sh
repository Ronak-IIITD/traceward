#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
command -v uv >/dev/null || { echo "Install uv from https://docs.astral.sh/uv/"; exit 1; }
command -v node >/dev/null || { echo "Install Node.js 22 or later."; exit 1; }
command -v bun >/dev/null || { echo "Install Bun 1.4.4 or later from https://bun.com/"; exit 1; }
uv sync --locked --extra api --python 3.12
(cd apps/web && bun install --frozen-lockfile --ignore-scripts)
api_pid=""
web_pid=""
cleanup() {
  trap - EXIT INT TERM
  [[ -z "$api_pid" ]] || kill "$api_pid" 2>/dev/null || true
  [[ -z "$web_pid" ]] || kill -- "-$web_pid" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM
.venv/bin/uvicorn traceward_api.app:app --host 127.0.0.1 --port 8000 --no-access-log &
api_pid=$!
setsid bun run --cwd "$PWD/apps/web" dev &
web_pid=$!
echo "TraceWard workspace: http://127.0.0.1:3000"
echo "Press Ctrl+C to stop the workspace and scanner."
wait -n "$api_pid" "$web_pid"
