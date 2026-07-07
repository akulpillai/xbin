#!/usr/bin/env bash
# One-shot end-to-end run: preflight -> full-stack driver (boots its own
# orchestrator headless). Headless/server-friendly; tees a timestamped log.
#
# Usage: scripts/e2e.sh [smoke|full|heavy]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
TIER="${1:-smoke}"

PY="$REPO_ROOT/.venv/bin/python"
[[ -x "$PY" ]] || { echo "[x] no .venv found. Run: make setup" >&2; exit 1; }

STAMP="$(date +%Y%m%d_%H%M%S)"
RUN_LOG="$REPO_ROOT/e2e_${TIER}_${STAMP}.log"
ORCH_LOG="$REPO_ROOT/orchestrator_${TIER}_${STAMP}.log"

echo "[*] preflight (tier=$TIER)"
if ! "$HERE/preflight.sh" --tier "$TIER"; then
  echo "[x] preflight failed." >&2
  if [[ "$TIER" == "heavy" ]]; then
    echo "    If QEMU is missing from bind:latest, run: scripts/rebuild_bind_base.sh" >&2
  fi
  exit 1
fi

echo "[*] running e2e driver (tier=$TIER); tee -> $RUN_LOG"
"$PY" "$HERE/e2e_driver.py" --"$TIER" --orch-log "$ORCH_LOG" 2>&1 | tee "$RUN_LOG"
