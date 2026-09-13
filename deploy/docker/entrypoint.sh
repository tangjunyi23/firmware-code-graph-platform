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

mkdir -p "$DATA" "$DATA/vulnagent/sessions" "$DATA/vulnagent/findings"

# 数据卷里的 .env（迁移镜像 seed 写入）补充 LLM key；不覆盖已注入的容器路径
if [[ -f "$DATA/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "$DATA/.env"
  set +a
  export FWGRAPH_ROOT="${FWGRAPH_ROOT:-/app/fwgraph}"
  export FWGRAPH_DATA="${DATA}"
  export VULNAGENT_HOME="${VULNAGENT_HOME:-/data/vulnagent}"
fi

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

IDA_RESOLVED="$(python - <<'PY'
from orchestrator.app import config
p = config.ida_dir()
print(p if p else "")
PY
)"
if [[ -n "$IDA_RESOLVED" ]]; then
  export IDA_DIR="$IDA_RESOLVED"
  echo "[entrypoint] 识别到 IDA：$IDA_DIR"
else
  unset IDA_DIR
  echo "[entrypoint] 投放目录 /opt/ida-drop 尚无 IDA；ELF 反编译走内置 rootfs_elf"
fi
if [[ -f "${ROOTFS_ELF_WORKER:-/app/tools/ida-no-mcp/rootfs_elf/ida_worker.py}" ]]; then
  echo "[entrypoint] rootfs_elf worker: ${ROOTFS_ELF_WORKER:-/app/tools/ida-no-mcp/rootfs_elf/ida_worker.py}"
else
  echo "[entrypoint] 警告：rootfs_elf worker 缺失，反编译不可用" >&2
fi

EMBA_IMAGE="${EMBA_IMAGE:-embeddedanalyzer/emba:2.0.3a}"
if docker image inspect "$EMBA_IMAGE" >/dev/null 2>&1; then
  echo "[entrypoint] EMBA image ready: $EMBA_IMAGE"
else
  echo "[entrypoint] 警告：未找到 $EMBA_IMAGE，解包不可用。先执行：" >&2
  echo "[entrypoint]   docker compose -f deploy/docker/docker-compose.yml --profile tools pull" >&2
fi

HOST_PREFIX="$(python - <<'PY'
from pipeline.sandbox.docker_backend import resolved_host_data_prefix
print(resolved_host_data_prefix() or "")
PY
)"
if [[ -n "$HOST_PREFIX" ]]; then
  echo "[entrypoint] sandbox host data prefix (auto): $HOST_PREFIX"
else
  echo "[entrypoint] sandbox host data prefix: unset (host paths used as-is)"
fi

echo "[entrypoint] starting orchestrator on $SCHEME://$HOST:$PORT"
exec python -m uvicorn orchestrator.app.main:app \
  --host "$HOST" --port "$PORT" "${UVICORN_TLS[@]}"
