# syntax=docker/dockerfile:1
# fwgraph 编排器镜像（Phase 3）：FastAPI 编排服务 + webui SPA + vulnagent CLI。
# 构建（仓库根目录）：
#   docker build -f deploy/docker/Dockerfile -t fwgraph-orchestrator:local .
# 可选构建上下文（不传也能构建，对应功能缺席）：
#   --build-context ida=<IDA 安装目录>       含 idat 的 IDA Pro 目录
#   --build-context cbmbin=<含 codebase-memory-mcp 真实二进制的目录>

# --- webui 前端构建：产出 fwgraph/webui/dist ---
FROM node:22-slim AS webui
WORKDIR /build/webui
COPY fwgraph/webui/package.json fwgraph/webui/package-lock.json ./
RUN npm ci
COPY fwgraph/webui/ ./
RUN npx vite build

# --- 可选上下文的空兜底：未传同名 --build-context 时 COPY --from 用此空 stage，
#     镜像照常构建；传入真实目录时同名构建上下文优先于本 stage ---
FROM scratch AS ida
FROM scratch AS cbmbin

# --- 运行时 ---
FROM python:3.12-slim

# docker CLI 静态客户端：编排器经挂载的 /var/run/docker.sock 让宿主 daemon
# 起兄弟沙箱容器（只装客户端，不装 daemon）
ARG DOCKER_CLI_VERSION=27.5.1

# qemu-user: trace 的 qemu-<arch> 存在性检查；curl/xz-utils/openssl: 健康检查、
# 证书自签与解包；gcc/make: fuzz hook 临场编译；git: cbm 图仓库；libstdc++6:
# node 二进制运行所需；procps: trace 回退路径（userns/root）的 pkill 清理
RUN apt-get update && apt-get install -y --no-install-recommends \
        qemu-user ca-certificates curl xz-utils openssl gcc make git \
        libstdc++6 procps \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_CLI_VERSION}.tgz" \
       | tar -xz --strip-components=1 -C /usr/local/bin docker/docker

# node 运行时（vulnagent_api spawn `node src/cli.js`）：与构建 stage 同版本，
# 直接拷贝二进制，免装 npm
COPY --from=webui /usr/local/bin/node /usr/local/bin/node

# Python 依赖；requirements.txt 未含 frida / tree-sitter 系（宿主 venv 单独
# 实装）——pipeline/frida/runner.py 需要 frida，pipeline/graphext/ast.py
# 硬依赖 tree_sitter。版本对齐 venv 实装与沙箱镜像 frida-server 默认值
COPY fwgraph/requirements.txt /app/fwgraph/requirements.txt
RUN pip install --no-cache-dir -r /app/fwgraph/requirements.txt \
    && pip install --no-cache-dir \
        frida==17.17.0 tree-sitter==0.26.0 tree-sitter-c==0.24.2

COPY fwgraph/ /app/fwgraph/
COPY --from=webui /build/webui/dist /app/fwgraph/webui/dist
COPY vulnagent/ /app/vulnagent/

# 可选组件：IDA 反编译器与 cbm 二进制（上下文缺失时为空目录，功能缺席不阻断）
RUN mkdir -p /opt/ida /opt/cbmbin
COPY --from=ida . /opt/ida/
COPY --from=cbmbin . /opt/cbmbin/
# 符号链接进 PATH，避免镜像里存两份 ~300MB 二进制
RUN if [ -f /opt/cbmbin/codebase-memory-mcp ]; then \
        chmod 755 /opt/cbmbin/codebase-memory-mcp \
        && ln -sf /opt/cbmbin/codebase-memory-mcp /usr/local/bin/codebase-memory-mcp; \
    fi

COPY deploy/docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV FWGRAPH_ROOT=/app/fwgraph \
    FWGRAPH_DATA=/data \
    IDA_DIR=/opt/ida \
    SANDBOX_BACKEND=docker \
    QEMU_BIN_DIR=/usr/bin \
    ORCH_HOST=0.0.0.0 \
    ORCH_PORT=8000

EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
