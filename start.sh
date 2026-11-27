#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
command -v uv >/dev/null || { echo "Install uv from https://docs.astral.sh/uv/"; exit 1; }
command -v node >/dev/null || { echo "Install Node.js 22 or later."; exit 1; }
command -v bun >/dev/null || { echo "Install Bun 1.4.4 or later from https://bun.com/"; exit 1; }
generated_key=false
workspace_key=${TRACEWARD_WORKSPACE_KEY:-}
unset TRACEWARD_WORKSPACE_KEY
if [[ -z "$workspace_key" ]]; then
  if [[ ! -t 1 ]]; then
    echo "Set TRACEWARD_WORKSPACE_KEY to a random private key before starting TraceWard without a terminal." >&2
    exit 1
  fi
  workspace_key=$(node -p 'require("node:crypto").randomBytes(32).toString("hex")')
  generated_key=true
fi
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
TRACEWARD_WORKSPACE_KEY="$workspace_key" setsid bun run --cwd "$PWD/apps/web" dev &
web_pid=$!
echo "TraceWard: http://127.0.0.1:3000"
if [[ "$generated_key" == true ]]; then
  printf 'Workspace key: %s\n' "$workspace_key"
fi
echo "Press Ctrl+C to stop the workspace and scanner."
wait -n "$api_pid" "$web_pid"
