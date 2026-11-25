#!/usr/bin/env bash
set -euo pipefail

if [[ ! ${TRACEWARD_CI_SETUP_STARTED:-} =~ ^[1-9][0-9]*$ ]]; then
  echo '::error::CI setup timer is missing or invalid.'
  exit 1
fi

elapsed=$((EPOCHSECONDS - TRACEWARD_CI_SETUP_STARTED))
echo "CI setup took ${elapsed}s."
if (( elapsed < 0 || elapsed >= 30 )); then
  echo '::error::CI setup must finish in under 30 seconds.'
  exit 1
fi
