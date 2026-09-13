#!/usr/bin/env bash
# 打一键迁移包：第一层全部是 Docker 镜像（编排器 + 沙箱 + 业务数据）。
# compose 只用相对路径和命名卷，不写本机绝对路径。
# EMBA（~36GB）不打进包，新机器用 install.sh tools 联网装。
#
#   bash deploy/migrate/pack.sh /path/to/out
#   bash deploy/migrate/pack.sh /path/to/out --no-images
#   bash deploy/migrate/pack.sh /path/to/out --with-emba
#   bash deploy/migrate/pack.sh /path/to/out --zip
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${1:-}"
if [[ -z "$OUT" || "$OUT" == --* ]]; then
  echo "用法: $0 <输出目录> [--no-images] [--with-emba] [--with-ida] [--zip]" >&2
  exit 2
fi
shift || true
WITH_IMAGES=1 WITH_EMBA=0 WITH_IDA=0 WITH_ZIP=0
for a in "$@"; do
  case "$a" in
    --no-images) WITH_IMAGES=0 ;;
    --with-images) WITH_IMAGES=1 ;;
    --with-emba) WITH_EMBA=1 ;;
    --with-ida) WITH_IDA=1 ;;
    --zip) WITH_ZIP=1 ;;
    *) echo "未知参数: $a" >&2; exit 2 ;;
  esac
done

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BUNDLE="$OUT/fwgraph-migrate-$STAMP"
mkdir -p "$BUNDLE"/{stack/ida-drop,extras,images}

echo "==> 薄栈（compose / .env / ida-drop）→ $BUNDLE/stack"
cp "$ROOT/deploy/docker/docker-compose.release.yml" "$BUNDLE/stack/docker-compose.yml"
cp "$ROOT/deploy/docker/ida-drop/README.txt" "$BUNDLE/stack/ida-drop/" 2>/dev/null || true
if [[ -f "$ROOT/fwgraph/.env" ]]; then
  install -m 600 "$ROOT/fwgraph/.env" "$BUNDLE/stack/.env"
  python3 - "$BUNDLE/stack/.env" <<'PY'
import pathlib, sys
env = pathlib.Path(sys.argv[1])
text = env.read_text(encoding="utf-8")
repl = {
    "FWGRAPH_ROOT": "/app/fwgraph",
    "FWGRAPH_DATA": "/data",
    "VULNAGENT_HOME": "/data/vulnagent",
    "EMBA_BACKEND": "docker",
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
PY
fi
install -m 755 "$ROOT/deploy/migrate/install.sh" "$BUNDLE/install.sh"
install -m 755 "$ROOT/deploy/migrate/restore.sh" "$BUNDLE/restore.sh"
install -m 644 "$ROOT/deploy/migrate/DEPLOY.md" "$BUNDLE/DEPLOY.md"

if [[ -d "$HOME/.dsh/profiles/fwgraph-web" ]]; then
  mkdir -p "$BUNDLE/extras/dsh-profiles"
  rsync -a --exclude=node_modules "$HOME/.dsh/profiles/fwgraph-web/" \
    "$BUNDLE/extras/dsh-profiles/fwgraph-web/"
fi
if [[ "$WITH_IDA" -eq 1 ]]; then
  echo "==> IDA（体积大，按你本机安装拷）"
  IDA_SRC="${IDA_DIR:-/opt/ida-pro-9.1}"
  if [[ -d "$IDA_SRC" ]]; then
    rsync -a "$IDA_SRC/" "$BUNDLE/extras/ida/"
  else
    echo "警告: 找不到 $IDA_SRC，跳过 IDA" >&2
  fi
fi

if [[ "$WITH_IMAGES" -eq 1 ]]; then
  echo "==> 构建编排器与沙箱镜像"
  docker compose -f "$ROOT/deploy/docker/docker-compose.yml" --profile build \
    build orchestrator sandbox

  echo "==> 构建第一层数据镜像 fwgraph-data:local"
  CTX="$(mktemp -d "$OUT/fwgraph-data-ctx.XXXXXX")"
  cleanup_ctx() { rm -rf "$CTX"; }
  trap cleanup_ctx EXIT
  mkdir -p "$CTX/data" "$CTX/sessions" "$CTX/findings"
  install -m 755 "$ROOT/deploy/docker/seed.sh" "$CTX/seed.sh"
  cp "$ROOT/deploy/docker/Dockerfile.data" "$CTX/Dockerfile"
  # rootfs 里的 /dev 节点和个别 root 目录拷不走，跳过即可
  rsync -a --no-specials --no-devices --info=stats1 \
    --exclude='**/squashfs-root/dev/' \
    --exclude='**/.upload_tmp/' \
    "$ROOT/fwgraph/data/" "$CTX/data/" \
    || echo "警告: 部分 data 文件无权限，已跳过（不影响主任务）" >&2
  rsync -a "$ROOT/vulnagent/sessions/" "$CTX/sessions/" 2>/dev/null || true
  rsync -a "$ROOT/vulnagent/findings/" "$CTX/findings/" 2>/dev/null || true
  if [[ -f "$BUNDLE/stack/.env" ]]; then
    install -m 600 "$BUNDLE/stack/.env" "$CTX/env"
  elif [[ -f "$ROOT/fwgraph/.env" ]]; then
    install -m 600 "$ROOT/fwgraph/.env" "$CTX/env"
  else
    : > "$CTX/env"
  fi
  docker build -t fwgraph-data:local -f "$CTX/Dockerfile" "$CTX"
  cleanup_ctx
  trap - EXIT

  echo "==> docker save 编排器 + 沙箱"
  docker save fwgraph-orchestrator:local fwgraph-sandbox:local \
    | gzip > "$BUNDLE/images/fwgraph-runtime.tar.gz"
  echo "==> docker save 第一层数据"
  docker save fwgraph-data:local | gzip > "$BUNDLE/images/fwgraph-data.tar.gz"
fi
if [[ "$WITH_EMBA" -eq 1 ]]; then
  echo "==> docker save EMBA（约 36GB，确认磁盘够）"
  docker save embeddedanalyzer/emba:2.0.3a | gzip > "$BUNDLE/images/emba-2.0.3a.tar.gz"
fi

{
  echo "packed_at=$STAMP"
  echo "source_host=$(hostname)"
  echo "source_root=$ROOT"
  echo "delivery=docker-images"
  echo "with_images=$WITH_IMAGES with_emba=$WITH_EMBA with_ida=$WITH_IDA"
  du -sh "$BUNDLE"/* 2>/dev/null | sed 's/^/size /'
} | tee "$BUNDLE/MANIFEST.txt"

if [[ "$WITH_ZIP" -eq 1 ]]; then
  echo "==> 打包 zip"
  # 顶层再放一份 install.sh / DEPLOY.md，解压即可跑
  cp "$BUNDLE/install.sh" "$OUT/install.sh"
  cp "$BUNDLE/DEPLOY.md" "$OUT/DEPLOY.md"
  (cd "$OUT" && zip -r -9 "fwgraph-deploy.zip" \
    "fwgraph-migrate-$STAMP" install.sh DEPLOY.md)
  echo "zip: $OUT/fwgraph-deploy.zip"
fi

echo
echo "打好了: $BUNDLE"
echo "新机器一条命令:  bash $BUNDLE/install.sh"
echo "数据在镜像 fwgraph-data:local，compose 使用命名卷 fwgraph-data，无绝对路径。"
