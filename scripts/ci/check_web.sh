#!/usr/bin/env bash
set -euo pipefail

bun run format:check &
format_pid=$!
bun run lint &
lint_pid=$!
bun run typecheck &
typecheck_pid=$!

failed=0
for pid in "$format_pid" "$lint_pid" "$typecheck_pid"; do
  wait "$pid" || failed=1
done
exit "$failed"
