#!/usr/bin/env bash
# fwgraph 一键安装（一条命令做完）。
#   docker load 编排器 / 沙箱 / 第一层数据镜像 → 命名卷播种 → 启动 :8000
#   → 联网拉 EMBA、装 qemu-user（AFL 已在沙箱镜像内）
#
#   bash install.sh                 # 装到 ~/fwgraph 并一次做完
#   bash install.sh /opt/fwgraph    # 指定 compose 目录（只拷薄栈，无绝对路径）
#   SKIP_TOOLS=1 bash install.sh    # 只导入镜像启动，不联网装工具
#   bash install.sh tools           # 以后补装 EMBA / qemu
#   INSTALL_DSH=1 bash install.sh   # 顺带装工作台挖掘引擎（需 Node 22）
set -euo pipefail

BUNDLE="$(cd "$(dirname "$0")" && pwd)"
STACK=""
if [[ -f "$BUNDLE/stack/docker-compose.yml" ]]; then
  STACK="$BUNDLE/stack"
elif [[ -f "$BUNDLE/docker-compose.yml" ]]; then
  STACK="$BUNDLE"
fi

DEST=""
MODE="install"
for a in "$@"; do
  case "$a" in
    tools|tool) MODE="tools" ;;
    --offline|offline) SKIP_TOOLS=1 ;;
    status) MODE="status" ;;
    -h|--help)
      sed -n '2,15p' "$0"
      exit 0
      ;;
    *)
      if [[ -z "$DEST" ]]; then DEST="$a"; else
        echo "未知参数: $a" >&2; exit 2
      fi
      ;;
  esac
done
DEST="${DEST:-${FWGRAPH_HOME:-$HOME/fwgraph}}"

need() { command -v "$1" >/dev/null 2>&1; }

rewrite_env() {
  local env="$1"
  python3 - "$env" <<'PY'
import pathlib, sys
env = pathlib.Path(sys.argv[1])
text = env.read_text(encoding="utf-8") if env.is_file() else ""
# 容器内固定路径，禁止写入本机绝对路径
repl = {
    "FWGRAPH_ROOT": "/app/fwgraph",
    "FWGRAPH_DATA": "/data",
    "VULNAGENT_HOME": "/data/vulnagent",
    "EMBA_BACKEND": "docker",
    "EMBA_IMAGE": "embeddedanalyzer/emba:2.0.3a",
    "SANDBOX_BACKEND": "docker",
    "IDA_DROP_DIR": "/opt/ida-drop",
}
drop = {"SANDBOX_HOST_PREFIX"}
lines, seen = [], set()
for line in text.splitlines():
    if not line.strip() or line.lstrip().startswith("#") or "=" not in line:
        lines.append(line)
        continue
    k, _, _ = line.partition("=")
    if k in drop:
        continue
    if k in repl:
        lines.append(f"{k}={repl[k]}")
        seen.add(k)
    else:
        lines.append(line)
for k, v in repl.items():
    if k not in seen:
        lines.append(f"{k}={v}")
env.write_text("\n".join(lines) + "\n", encoding="utf-8")
print("rewrote", env)
PY
}

DOCKER="${DOCKER:-docker}"

compose() {
  local dest="$1"
  shift
  local bin=(docker)
  [[ "$DOCKER" == "sudo docker" ]] && bin=(sudo docker)
  local files=(-f "$dest/docker-compose.yml")
  if "${bin[@]}" compose version >/dev/null 2>&1; then
    "${bin[@]}" compose "${files[@]}" "$@"
  else
    if [[ "$DOCKER" == "sudo docker" ]]; then
      sudo docker-compose "${files[@]}" "$@"
    else
      docker-compose "${files[@]}" "$@"
    fi
  fi
}

ensure_docker() {
  if ! need docker; then
    echo "==> 安装 Docker"
    if need apt-get; then
      sudo apt-get update -qq
      sudo apt-get install -y -qq docker.io docker-compose-v2 || \
        sudo apt-get install -y -qq docker.io docker-compose
    else
      echo "请先安装 docker" >&2
      exit 1
    fi
  fi
  if ! docker info >/dev/null 2>&1; then
    sudo usermod -aG docker "$USER" 2>/dev/null || true
    echo "当前用户还不能访问 docker。执行: sudo usermod -aG docker $USER && newgrp docker" >&2
    echo "或用 sudo 再跑本脚本。" >&2
    if ! sudo docker info >/dev/null 2>&1; then
      exit 1
    fi
    DOCKER="sudo docker"
  else
    DOCKER="docker"
  fi
}

install_stack() {
  if [[ -z "$STACK" ]]; then
    echo "当前目录不是迁移包（没有 stack/docker-compose.yml）。" >&2
    exit 1
  fi
  echo "==> 安装到 $DEST（仅 compose / .env / ida-drop，数据在 Docker 卷）"
  mkdir -p "$DEST"
  DEST="$(cd "$DEST" && pwd)"
  mkdir -p "$DEST/ida-drop"
  cp -a "$STACK/docker-compose.yml" "$DEST/docker-compose.yml"
  if [[ -f "$STACK/.env" ]]; then
    cp -a "$STACK/.env" "$DEST/.env"
  elif [[ -f "$BUNDLE/stack/.env" ]]; then
    cp -a "$BUNDLE/stack/.env" "$DEST/.env"
  fi
  if [[ -d "$STACK/ida-drop" ]]; then
    cp -a "$STACK/ida-drop/." "$DEST/ida-drop/"
  fi
  if [[ -f "$DEST/.env" ]]; then
    rewrite_env "$DEST/.env"
  fi
  if [[ -d "$BUNDLE/extras/ida" ]]; then
    rsync -a "$BUNDLE/extras/ida/" "$DEST/ida-drop/"
  fi
  if [[ -d "$BUNDLE/extras/dsh-profiles/fwgraph-web" ]]; then
    mkdir -p "$HOME/.dsh/profiles"
    rsync -a "$BUNDLE/extras/dsh-profiles/fwgraph-web/" \
      "$HOME/.dsh/profiles/fwgraph-web/"
  elif [[ -d "$BUNDLE/core/host/dsh-profiles/fwgraph-web" ]]; then
    mkdir -p "$HOME/.dsh/profiles"
    rsync -a "$BUNDLE/core/host/dsh-profiles/fwgraph-web/" \
      "$HOME/.dsh/profiles/fwgraph-web/"
  fi
  echo "$DEST" > "$BUNDLE/.installed-root"
  echo "$DEST" > "$DEST/.fwgraph-home"
}

load_images() {
  ensure_docker
  local img
  for img in \
      "$BUNDLE/images/fwgraph-runtime.tar.gz" \
      "$BUNDLE/images/fwgraph-data.tar.gz" \
      "$BUNDLE/images/emba-2.0.3a.tar.gz"; do
    if [[ -f "$img" ]]; then
      echo "==> 导入 $(basename "$img")"
      gunzip -c "$img" | $DOCKER load
    fi
  done
  if ! $DOCKER image inspect fwgraph-orchestrator:local >/dev/null 2>&1; then
    echo "没有 fwgraph-orchestrator:local。包里应有 images/fwgraph-runtime.tar.gz" >&2
    exit 1
  fi
}

start_stack() {
  ensure_docker
  if $DOCKER image inspect fwgraph-data:local >/dev/null 2>&1; then
    echo "==> 播种数据卷 fwgraph-data（相对路径 / 命名卷，无本机绝对路径）"
    compose "$DEST" --profile migrate run --rm seed
  else
    echo "警告: 没有 fwgraph-data:local，将使用空数据卷" >&2
  fi
  echo "==> 启动编排器"
  compose "$DEST" up -d orchestrator
  echo
  echo "已启动。浏览器打开 https://<本机>:8000 （自签证书，用 -k / 继续访问）"
  echo "现场再装 EMBA / qemu:  bash $BUNDLE/install.sh $DEST tools"
}

install_tools() {
  DEST="$(cd "$DEST" && pwd)"
  ensure_docker
  echo "==> 现场联网安装工具"
  if need apt-get; then
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
      qemu-user qemu-user-binfmt ca-certificates curl || true
  fi
  echo "==> 拉取 EMBA 官方镜像（约 36GB，视网速）"
  $DOCKER pull embeddedanalyzer/emba:2.0.3a
  if [[ "${INSTALL_DSH:-0}" == "1" ]]; then
    echo "工作台挖掘引擎需 Node 22；本包以容器交付，dsh 可后补。"
  fi
  echo "工具安装完成。EMBA 已就位；AFL++ 已在沙箱镜像 fwgraph-sandbox:local 内。"
}

show_status() {
  echo "BUNDLE=$BUNDLE"
  echo "DEST=$DEST"
  docker images --format '{{.Repository}}:{{.Tag}} {{.Size}}' \
    | grep -E 'fwgraph|emba' || true
  if [[ -f "$DEST/docker-compose.yml" ]]; then
    compose "$DEST" ps || true
  fi
}

case "$MODE" in
  install)
    install_stack
    load_images
    start_stack
    if [[ "${SKIP_TOOLS:-0}" == "1" ]]; then
      echo "已跳过联网工具（SKIP_TOOLS=1）。以后补装: bash $0 $DEST tools"
    else
      install_tools
    fi
    ;;
  tools)
    if [[ ! -f "$DEST/docker-compose.yml" && -f "$BUNDLE/.installed-root" ]]; then
      DEST="$(cat "$BUNDLE/.installed-root")"
    fi
    if [[ ! -f "$DEST/docker-compose.yml" ]]; then
      echo "找不到已安装目录 $DEST，先跑: bash install.sh $DEST" >&2
      exit 1
    fi
    install_tools
    ;;
  status) show_status ;;
esac
