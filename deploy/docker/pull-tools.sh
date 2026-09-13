#!/usr/bin/env bash
# 拉取交付所需的配套镜像（EMBA 官方分析镜像约 36GB）。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
COMPOSE="$ROOT/deploy/docker/docker-compose.yml"
IMAGE="${EMBA_IMAGE:-embeddedanalyzer/emba:2.0.3a}"
echo "pull $IMAGE"
docker compose -f "$COMPOSE" --profile tools pull emba
docker image inspect "$IMAGE" >/dev/null
echo "ok $IMAGE"
