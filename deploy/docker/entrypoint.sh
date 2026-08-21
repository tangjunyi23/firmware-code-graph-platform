#!/usr/bin/env bash
# fwgraph 编排器容器入口（Phase 3）：自签 TLS 证书 -> 后台 cbm-ui（可选）
# -> 前台 uvicorn。对齐宿主机 scripts/run_orchestrator.sh 的语义，但不用
# nohup/pid 文件模式（容器以前台进程为准）。
set -euo pipefail

FWGRAPH_ROOT="${FWGRAPH_ROOT:-/app/fwgraph}"
DATA="${FWGRAPH_DATA:-/data}"
HOST="${ORCH_HOST:-0.0.0.0}"
PORT="${ORCH_PORT:-8000}"
cd "$FWGRAPH_ROOT"

mkdir -p "$DATA"

# TLS（ORCH_SSL=0 回退明文 HTTP）。证书放 /data/certs 随数据卷持久化，
# 重启不重签；CN/SAN 由 ORCH_CERT_CN/ORCH_CERT_SANS 控制（同宿主脚本）。
SCHEME="http"
UVICORN_TLS=()
if [[ "${ORCH_SSL:-1}" != "0" ]]; then
  TLS_DIR="$DATA/certs"
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
    echo "[entrypoint] generated self-signed TLS cert: $CERT (CN=$CERT_CN)"
  fi
  UVICORN_TLS=(--ssl-keyfile "$KEY" --ssl-certfile "$CERT")
  SCHEME="https"
fi

# cbm-ui（/cbmui 反代的上游，可选）：二进制经 cbmbin 构建上下文进镜像，
# 缺失或无法运行（如 glibc 不兼容）时打警告跳过，编排器照常启动。
# cbm 是 stdio MCP server：stdin 到 EOF 即退出，用 tail 保持 stdin 常开。
CBM_PORT="${CBM_UI_PORT:-9749}"
# .env 里的 CBM_BIN 是宿主侧路径，容器内可能不存在；不可执行时回退 PATH 查找
CBM_BIN="${CBM_BIN:-}"
if [[ -z "$CBM_BIN" || ! -x "$CBM_BIN" ]]; then
  CBM_BIN="$(command -v codebase-memory-mcp || true)"
fi
if [[ -n "$CBM_BIN" && -x "$CBM_BIN" ]]; then
  tail -f /dev/null | "$CBM_BIN" --ui=true --port="$CBM_PORT" \
    >>"$DATA/cbm_ui.log" 2>&1 &
  CBM_PID=$!   # 后台管道中 $! 是管道末端（cbm）的 pid
  sleep 2
  if kill -0 "$CBM_PID" 2>/dev/null; then
    echo "[entrypoint] cbm ui started (pid $CBM_PID), http://127.0.0.1:$CBM_PORT"
  else
    echo "[entrypoint] 警告：cbm ui 启动失败（见 $DATA/cbm_ui.log），/cbmui 不可用" >&2
  fi
else
  echo "[entrypoint] 警告：未找到 codebase-memory-mcp（构建时未传 cbmbin 上下文），/cbmui 不可用" >&2
fi

echo "[entrypoint] starting orchestrator on $SCHEME://$HOST:$PORT"
exec python -m uvicorn orchestrator.app.main:app \
  --host "$HOST" --port "$PORT" "${UVICORN_TLS[@]}"
