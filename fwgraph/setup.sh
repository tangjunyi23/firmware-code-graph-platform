#!/usr/bin/env bash
# fwgraph M0 环境安装脚本（Ubuntu 26.04，在 ~/firmware-graph/fwgraph 下运行）
# 用法: bash setup.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "== fwgraph root: $ROOT"

echo "== [1/5] apt 依赖（python3-venv / pip / 常用工具）"
# 不再内置明文 sudo 密码：需要 root 的步骤改为提示用户手动执行
echo "   请先手动执行: sudo apt-get update -qq && sudo apt-get install -y -qq python3-venv python3-pip curl git"

echo "== [2/5] Python venv"
python3 -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/pip" install -q --upgrade pip
"$ROOT/.venv/bin/pip" install -q -r "$ROOT/requirements.txt"
echo "   venv ok: $("$ROOT/.venv/bin/python" --version)"

echo "== [3/5] codebase-memory-mcp (CBM)"
if ! command -v codebase-memory-mcp >/dev/null 2>&1; then
  curl -fsSL https://raw.githubusercontent.com/DeusData/codebase-memory-mcp/main/install.sh | bash -s -- --ui
fi
export PATH="$HOME/.local/bin:$PATH"
codebase-memory-mcp --version | head -1 || true

echo "== [4/5] 数据目录"
mkdir -p "$ROOT/data"/{firmware,extracted,idb,pseudocode,cbm}
echo "   data/ ok"

echo "== [5/5] 环境自检"
ok=1
command -v docker >/dev/null && echo "   docker: $(docker --version)" || { echo "   docker MISSING"; ok=0; }
if [ -n "${IDA_DIR:-}" ]; then
  [ -x "$IDA_DIR/idat" ] && echo "   idat: found" || { echo "   idat MISSING ($IDA_DIR/idat)"; ok=0; }
else
  echo "   idat: 未检查（未设置 IDA_DIR，请在 .env 或环境中配置）"
fi
command -v codebase-memory-mcp >/dev/null && echo "   cbm: found" || echo "   cbm MISSING(重开 shell 或检查 ~/.local/bin)"
[ -f "$ROOT/.env" ] && echo "   .env: found" || echo "   .env MISSING(从 .env.example 复制并填 key)"
[ $ok -eq 1 ] && echo "== setup 完成" || echo "== setup 完成但有缺失项"
