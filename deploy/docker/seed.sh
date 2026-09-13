#!/bin/sh
# 把镜像内种子灌进空的 fwgraph-data 卷。已播种则跳过，避免覆盖现场新数据。
set -e
if [ -f /data/.seeded ]; then
  echo "[seed] /data already seeded, skip"
  exit 0
fi

mkdir -p /data /data/vulnagent
if [ -d /seed/data ]; then
  cp -a /seed/data/. /data/
fi
if [ -d /seed/vulnagent ]; then
  mkdir -p /data/vulnagent
  cp -a /seed/vulnagent/. /data/vulnagent/
fi
if [ -f /seed/env ] && [ ! -f /data/.env ]; then
  cp /seed/env /data/.env
fi

if [ -f /data/.env ]; then
  # 去掉宿主绝对路径，改成容器内固定路径
  sed -i \
    -e 's|^FWGRAPH_ROOT=.*|FWGRAPH_ROOT=/app/fwgraph|' \
    -e 's|^FWGRAPH_DATA=.*|FWGRAPH_DATA=/data|' \
    -e 's|^VULNAGENT_HOME=.*|VULNAGENT_HOME=/data/vulnagent|' \
    -e 's|^EMBA_BACKEND=.*|EMBA_BACKEND=docker|' \
    -e 's|^SANDBOX_BACKEND=.*|SANDBOX_BACKEND=docker|' \
    -e '/^SANDBOX_HOST_PREFIX=/d' \
    /data/.env
  grep -q '^FWGRAPH_ROOT=' /data/.env || echo 'FWGRAPH_ROOT=/app/fwgraph' >> /data/.env
  grep -q '^FWGRAPH_DATA=' /data/.env || echo 'FWGRAPH_DATA=/data' >> /data/.env
  grep -q '^VULNAGENT_HOME=' /data/.env || echo 'VULNAGENT_HOME=/data/vulnagent' >> /data/.env
  grep -q '^EMBA_BACKEND=' /data/.env || echo 'EMBA_BACKEND=docker' >> /data/.env
fi

mkdir -p /data/vulnagent/sessions /data/vulnagent/findings /data/certs
touch /data/.seeded
echo "[seed] populated fwgraph-data volume"
