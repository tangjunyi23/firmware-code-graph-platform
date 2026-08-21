#!/usr/bin/env bash
# Start the fwgraph orchestrator (M1) in the background.
# Usage: fwgraph/scripts/run_orchestrator.sh
set -euo pipefail

FWGRAPH_ROOT="${FWGRAPH_ROOT:-/home/tankuku/firmware-graph/fwgraph}"
cd "$FWGRAPH_ROOT"

# load ORCH_HOST / ORCH_PORT / ... from .env if present; variables already
# set in the environment win (same precedence as main.py's load_dotenv), so
# callers can override e.g. IDA_WORKERS for a one-off run.
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

# S2: TLS on by default (ORCH_SSL=0 falls back to plain HTTP). First run
# self-signs data/tls/{cert,key}.pem (CN/SAN 由 ORCH_CERT_CN/ORCH_CERT_SANS
# 控制，默认 localhost / IP:127.0.0.1,DNS:localhost)；有正式证书时直接替换。
SCHEME="http"
UVICORN_TLS=()
if [[ "${ORCH_SSL:-1}" != "0" ]]; then
  TLS_DIR="data/tls"
  CERT="$TLS_DIR/cert.pem"
  KEY="$TLS_DIR/key.pem"
  CERT_CN="${ORCH_CERT_CN:-localhost}"
  CERT_SANS="${ORCH_CERT_SANS:-IP:127.0.0.1,DNS:localhost}"
  if [[ ! -f "$CERT" || ! -f "$KEY" ]]; then
    mkdir -p "$TLS_DIR"
    openssl req -x509 -newkey rsa:4096 -nodes \
      -keyout "$KEY" -out "$CERT" -days 3650 \
      -subj "/CN=$CERT_CN" \
      -addext "subjectAltName=$CERT_SANS"
    chmod 600 "$KEY"
    echo "generated self-signed TLS cert: $CERT (CN=$CERT_CN)"
  fi
  UVICORN_TLS=(--ssl-keyfile "$KEY" --ssl-certfile "$CERT")
  SCHEME="https"
fi

nohup .venv/bin/python -m uvicorn orchestrator.app.main:app \
  --host "$HOST" --port "$PORT" "${UVICORN_TLS[@]}" >>"$LOG_FILE" 2>&1 &
echo $! >"$PID_FILE"
echo "orchestrator started (pid $(cat "$PID_FILE")), $SCHEME://$HOST:$PORT, log: $LOG_FILE"

# CBM UI powers /jobs/{id}/graph/layout and the /cbmui proxy; start it
# alongside the orchestrator (idempotent, best-effort).
bash scripts/run_cbm_ui.sh || true
