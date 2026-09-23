#!/usr/bin/env bash
# Set up the DeepSeek Harness (dsh) engine for vulnagent on the VM.
#
#   bash vulnagent/dsh/setup.sh
#
# Steps: clone dsh (pinned) -> pnpm install + build -> create the `fwgraph`
# profile with our zero-dep tools plugin -> smoke-check the composition.
# Re-running is idempotent. Requires: node >= 22, pnpm 11 (via corepack
# cache or npm), git.
set -euo pipefail

DSH_REPO="${DSH_REPO:-$HOME/deepseek-harness}"
DSH_REF="${DSH_REF:-master}"
VULNAGENT_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN_SRC="$VULNAGENT_HOME/dsh/plugin"
DSH_HOME="${DSH_HOME:-$HOME/.dsh}"
PROFILE_DIR="$DSH_HOME/profiles/fwgraph"
# pnpm 11.7.0 解析顺序：环境变量 > PATH 上的 pnpm（npm -g 装的）> corepack 缓存
# （corepack 缓存曾在磁盘清理中被删，PATH 优先更稳）
if [ -z "${PNPM:-}" ]; then
  if command -v pnpm >/dev/null 2>&1; then
    PNPM="pnpm"
  elif [ -f "$HOME/.cache/node/corepack/pnpm/11.7.0/bin/pnpm.cjs" ]; then
    PNPM="node $HOME/.cache/node/corepack/pnpm/11.7.0/bin/pnpm.cjs"
  else
    PNPM="node $(npm prefix -g)/lib/node_modules/pnpm/bin/pnpm.cjs"
  fi
fi

echo "== [1/5] deepseek-harness checkout: $DSH_REPO ($DSH_REF)"
if [ ! -d "$DSH_REPO/.git" ]; then
  # 本机 github.com HTTPS 常被中断，SSH 可达则优先 SSH 克隆
  # （ssh -T 对 github 成功时退出码仍为 1，须按输出判断认证成功）
  if ssh -o ConnectTimeout=6 -o BatchMode=yes -T git@github.com 2>&1 \
     | grep -q "successfully authenticated"; then
    git clone git@github.com:deepseek-ai/deepseek-harness "$DSH_REPO"
  else
    git clone https://github.com/deepseek-ai/deepseek-harness "$DSH_REPO"
  fi
fi
git -C "$DSH_REPO" fetch --depth 1 origin "$DSH_REF" || true
git -C "$DSH_REPO" checkout -q "$DSH_REF" 2>/dev/null || true

# 引擎本地补丁（opencode go 网关 2026-09 起强制 x-opencode-session 头，
# 上游尚未提供自定义头配置；补丁幂等重放）
for patch_file in "$VULNAGENT_HOME"/dsh/patches/*.patch; do
  [ -f "$patch_file" ] || continue
  if git -C "$DSH_REPO" apply --check "$patch_file" 2>/dev/null; then
    git -C "$DSH_REPO" apply "$patch_file"
    echo "  engine patch applied: $(basename "$patch_file")"
  else
    echo "  engine patch already applied or stale: $(basename "$patch_file")"
  fi
done

echo "== [2/5] pnpm install (long on first run)"
cd "$DSH_REPO"
$PNPM install
# tsdown (build tool) needs unrun resolvable from the root; pnpm's strict
# layout hides it, so add it as a root dev dependency (observed 2026-08-14)
$PNPM add -Dw unrun

echo "== [3/5] build"
$PNPM run build

echo "== [4/5] fwgraph profile: $PROFILE_DIR"
mkdir -p "$PROFILE_DIR"
cat > "$PROFILE_DIR/package.json" <<EOF
{
  "name": "dsh-profile-fwgraph",
  "private": true,
  "dependencies": {
    "@fwgraph/dsh-fwgraph-tools": "file:$PLUGIN_SRC",
    "@fwgraph/dsh-fwgraph-events": "file:$VULNAGENT_HOME/dsh/plugin-events"
  },
  "dsh": { "profile": { "bundles": ["@deepseek-ai/dsh-base", "@deepseek-ai/dsh-headless"] } }
}
EOF
cat > "$PROFILE_DIR/pnpm-workspace.yaml" <<'EOF'
packages:
  - .

nodeLinker: hoisted
autoInstallPeers: false
EOF
cp "$VULNAGENT_HOME/dsh/cordis.patch.yml" "$PROFILE_DIR/cordis.patch.yml"
cd "$PROFILE_DIR"
$PNPM install --ignore-workspace 2>/dev/null || $PNPM install

# fwgraph-web profile: dsh web host（工作台多轮会话/queue/steer/审批走这里）。
# 与一次性 CLI 的 fwgraph profile 只差 surface bundle：headless 与 web-app 是
# 互斥的同级表面（各自持有应用命令行），所以拆成两个 profile。
PROFILE_WEB_DIR="$DSH_HOME/profiles/fwgraph-web"
mkdir -p "$PROFILE_WEB_DIR"
cat > "$PROFILE_WEB_DIR/package.json" <<EOF
{
  "name": "dsh-profile-fwgraph-web",
  "private": true,
  "dependencies": {
    "@fwgraph/dsh-fwgraph-tools": "file:$PLUGIN_SRC",
    "@fwgraph/dsh-fwgraph-events": "file:$VULNAGENT_HOME/dsh/plugin-events"
  },
  "dsh": { "profile": { "bundles": ["@deepseek-ai/dsh-base", "@deepseek-ai/dsh-web-app"] } }
}
EOF
cp "$PROFILE_DIR/pnpm-workspace.yaml" "$PROFILE_WEB_DIR/pnpm-workspace.yaml"
cp "$VULNAGENT_HOME/dsh/cordis.patch.yml" "$PROFILE_WEB_DIR/cordis.patch.yml"
cd "$PROFILE_WEB_DIR"
$PNPM install --ignore-workspace 2>/dev/null || $PNPM install

# ── 固件模拟 agent（fwgraph-emul）：与挖掘平行的独立组合 ─────────────
# emul profile 开 web 行（联网查知识）+ 子代理 spawn provider（广度/总量
# 由插件守卫封）；工具面换成 @fwgraph/dsh-fwgraph-emul-tools。
EMUL_PLUGIN_SRC="$VULNAGENT_HOME/dsh/plugin-emul"
_profile_emul() {
  local dir="$1" bundles="$2" name="$3"
  mkdir -p "$dir"
  cat > "$dir/package.json" <<EOF
{
  "name": "dsh-profile-$name",
  "private": true,
  "dependencies": {
    "@fwgraph/dsh-fwgraph-emul-tools": "file:$EMUL_PLUGIN_SRC",
    "@fwgraph/dsh-fwgraph-events": "file:$VULNAGENT_HOME/dsh/plugin-events"
  },
  "dsh": { "profile": { "bundles": ["@deepseek-ai/dsh-base", "$bundles"] } }
}
EOF
  cp "$PROFILE_DIR/pnpm-workspace.yaml" "$dir/pnpm-workspace.yaml"
  cp "$VULNAGENT_HOME/dsh/cordis.patch-emul.yml" "$dir/cordis.patch.yml"
  cd "$dir"
  $PNPM install --ignore-workspace 2>/dev/null || $PNPM install
}
_profile_emul "$DSH_HOME/profiles/fwgraph-emul" \
              "@deepseek-ai/dsh-headless" "fwgraph-emul"
_profile_emul "$DSH_HOME/profiles/fwgraph-emul-web" \
              "@deepseek-ai/dsh-web-app" "fwgraph-emul-web"

mkdir -p "$DSH_HOME/.agent-presets/fwgraph-emul"
cp "$VULNAGENT_HOME/dsh/agent-preset.fwgraph-emul.cordis.yml" \
   "$DSH_HOME/.agent-presets/fwgraph-emul/agent.cordis.yml"

# fwgraph agent preset（web host 模式的会话组合：standard preset 引用 tool-web，
# 会因宿主 web 服务被禁用而挂载失败，必须用这张只挂无危险面行的 preset）
mkdir -p "$DSH_HOME/.agent-presets/fwgraph"
cp "$VULNAGENT_HOME/dsh/agent-preset.fwgraph.cordis.yml" \
   "$DSH_HOME/.agent-presets/fwgraph/agent.cordis.yml"

# skills 全量部署：vulnagent/dsh/skills/ 下每个 <name>/SKILL.md 目录整体同步到
# $DSH_HOME/skills/<name>/（含 references/scripts/assets 子目录）
for skill_src in "$VULNAGENT_HOME"/dsh/skills/*/; do
  skill_name="$(basename "$skill_src")"
  [ -f "$skill_src/SKILL.md" ] || continue
  mkdir -p "$DSH_HOME/skills/$skill_name"
  cp -r "$skill_src." "$DSH_HOME/skills/$skill_name/"
  echo "  skill deployed: $skill_name"
done

echo "== [5/5] composition smoke check"
cd "$DSH_REPO"
node --import tsx/esm apps/cli/src/bin.ts --profile fwgraph --dump-config \
  | head -5 || true

# 工具面自检：实 boot profile（不跑任务、不调 LLM），打印注册工具清单并断言
# 无 web/子代理；沙箱 bash/write 在场；fw_* 系列齐全
echo "== tool surface lockdown check"
node "$VULNAGENT_HOME/dsh/verify_tools.mjs"

cat <<MSG

dsh engine ready. Run a hunt task through it:
  cd $DSH_REPO
  FWGRAPH_BASE_URL=http://127.0.0.1:8000 FWGRAPH_TOKEN=<token> \\
  FWGRAPH_JOB_ID=<job> DEEPSEEK_API_KEY=<opencode-key> \\
  DEEPSEEK_BASE_URL=https://opencode.ai/zen/go/v1 \\
  node --import tsx/esm apps/cli/src/bin.ts --profile fwgraph "对 verified 路径做漏洞挖掘"

or via vulnagent:  node src/cli.js run "<task>" --engine dsh
MSG
