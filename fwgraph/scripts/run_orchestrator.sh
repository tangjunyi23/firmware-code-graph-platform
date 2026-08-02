#!/usr/bin/env bash
# Start the fwgraph orchestrator (M1) in the background.
# Usage: fwgraph/scripts/run_orchestrator.sh
set -euo pipefail

FWGRAPH_ROOT="${FWGRAPH_ROOT:-/home/tankuku/firmware-graph/fwgraph}"
cd "$FWGRAPH_ROOT"

# load ORCH_HOST / ORCH_PORT / ... from .env if present; variables already
# set in the environment win (same precedence as main.py's load_dotenv), so
# callers can override e.g. AI_MAX_FUNCS_PER_BIN for a one-off run.
if [[ -f .env ]]; then
  while IFS='=' read -r key value; do
    key="${key//[[:space:]]/}"
    [[ -z "$key" || "$key" == \#* ]] && continue
    [[ -z "${!key+x}" ]] && export "$key=$value"
  done < .env
fi

HOST="${ORCH_HOST:-0.0.0.0}"
PORT="${ORCH_PORT:-8000}"
PID_FILE="data/orchestrator.pid"
LOG_FILE="data/orchestrator.log"

mkdir -p data
if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "orchestrator already running (pid $(cat "$PID_FILE"))"
  exit 0
fi

nohup .venv/bin/python -m uvicorn orchestrator.app.main:app \
  --host "$HOST" --port "$PORT" >>"$LOG_FILE" 2>&1 &
echo $! >"$PID_FILE"
echo "orchestrator started (pid $(cat "$PID_FILE")), http://$HOST:$PORT, log: $LOG_FILE"
