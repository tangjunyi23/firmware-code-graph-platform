#!/usr/bin/env bash
# 兼容入口：转到一键安装脚本。
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
exec bash "$DIR/install.sh" "$@"
