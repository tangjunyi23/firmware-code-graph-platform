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
PNPM="${PNPM:-node $HOME/.cache/node/corepack/pnpm/11.7.0/bin/pnpm.cjs}"

echo "== [1/5] deepseek-harness checkout: $DSH_REPO ($DSH_REF)"
if [ ! -d "$DSH_REPO/.git" ]; then
  git clone https://github.com/deepseek-ai/deepseek-harness "$DSH_REPO"
fi
git -C "$DSH_REPO" fetch --depth 1 origin "$DSH_REF" || true
git -C "$DSH_REPO" checkout -q "$DSH_REF" 2>/dev/null || true

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

# fwgraph agent preset（web host 模式的会话组合：standard preset 引用 tool-web，
# 会因宿主 web 服务被禁用而挂载失败，必须用这张只挂无危险面行的 preset）
mkdir -p "$DSH_HOME/.agent-presets/fwgraph"
cp "$VULNAGENT_HOME/dsh/agent-preset.fwgraph.cordis.yml" \
   "$DSH_HOME/.agent-presets/fwgraph/agent.cordis.yml"

mkdir -p "$DSH_HOME/skills/fwgraph-firmware-hunt"
cp "$VULNAGENT_HOME/dsh/skills/fwgraph-firmware-hunt/SKILL.md" \
   "$DSH_HOME/skills/fwgraph-firmware-hunt/SKILL.md"

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
