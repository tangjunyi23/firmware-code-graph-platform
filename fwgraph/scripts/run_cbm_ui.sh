#!/usr/bin/env bash
# Start the CBM web UI (codebase-memory-mcp --ui) detached.
#
# The binary is a stdio MCP server: it shuts down when stdin hits EOF, so we
# keep stdin open forever with `tail -f /dev/null`. It binds 127.0.0.1 only
# and validates the Host header by design; external access goes through the
# orchestrator's /cbmui reverse proxy (see orchestrator/app/webui.py).
#
# Usage: fwgraph/scripts/run_cbm_ui.sh
set -euo pipefail

FWGRAPH_ROOT="${FWGRAPH_ROOT:-/home/tankuku/firmware-graph/fwgraph}"
cd "$FWGRAPH_ROOT"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

# CBM_BIN 未设置时先查 PATH，再兜底 ~/.local/bin
CBM_BIN="${CBM_BIN:-$(command -v codebase-memory-mcp || echo "$HOME/.local/bin/codebase-memory-mcp")}"
PORT="${CBM_UI_PORT:-9749}"
PID_FILE="data/cbm_ui.pid"
LOG_FILE="data/cbm_ui.log"

mkdir -p data
if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "cbm ui already running (pid $(cat "$PID_FILE"))"
  exit 0
fi

# stdin/stdout/stderr fully detached so an SSH exec channel is never held open
setsid bash -c "tail -f /dev/null | '$CBM_BIN' --ui=true --port=$PORT >>'$FWGRAPH_ROOT/$LOG_FILE' 2>&1" </dev/null >/dev/null 2>&1 &
sleep 2
CBM_PID="$(pgrep -f "codebase-memory-mcp --ui=true --port=$PORT" | head -1 || true)"
if [[ -z "$CBM_PID" ]]; then
  echo "cbm ui failed to start, see $LOG_FILE" >&2
  exit 1
fi
echo "$CBM_PID" > "$PID_FILE"
echo "cbm ui started (pid $CBM_PID), http://127.0.0.1:$PORT, log: $LOG_FILE"
