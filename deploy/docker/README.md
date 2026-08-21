# fwgraph 容器化部署（Phase 3）

两个镜像：`fwgraph-orchestrator`（编排器 + webui + vulnagent，本目录
`Dockerfile`）与 `fwgraph-sandbox`（不可信固件动态分析沙箱，
`Dockerfile.sandbox`，运行时由编排器经 docker.sock 按需起兄弟容器）。

## 1. 准备 .env

```bash
cp fwgraph/.env.example fwgraph/.env   # 至少填 LLM_API_KEY、ORCH_TOKEN
```

`.env` 不进镜像（.dockerignore 已排除），运行时由 compose env_file 注入。

## 2. 构建

```bash
cd <仓库根>
# 沙箱镜像（build-only 服务，--profile build 才参与）
docker compose -f deploy/docker/docker-compose.yml --profile build build sandbox
# 编排器镜像
docker compose -f deploy/docker/docker-compose.yml build orchestrator
```

可选组件（不传也能构建，对应功能缺席）：

- IDA：把 compose `additional_contexts.ida` 指向 IDA 安装目录（含 idat），
  或命令行 `--build-context ida=<目录>`；
- cbm 二进制：`additional_contexts.cbmbin` 指向含真实二进制的目录（符号
  链接需先 `cp -L` 解引用），或命令行 `--build-context cbmbin=<目录>`。

注意：实测 buildkit 对 `COPY --from=<命名上下文>` 的缓存键不含上下文
内容——先按真实目录构建、再改回空占位重建时会复用到含旧内容的层；
撤销/更换可选上下文后请加 `--no-cache` 重建（或先 `docker buildx prune`）。

## 3. 启动与验证

```bash
# SANDBOX_HOST_PREFIX 必须等于本机 deploy/docker/data 的绝对路径
SANDBOX_HOST_PREFIX=$PWD/deploy/docker/data \
  docker compose -f deploy/docker/docker-compose.yml up -d
docker compose -f deploy/docker/docker-compose.yml ps    # healthy 即就绪
curl -k https://127.0.0.1:8000/login -o /dev/null -w '%{http_code}\n'   # 200
```

首启在 `data/certs/` 自签 TLS 证书（`ORCH_CERT_CN/SANS` 控制，持久化不
重签）；cbm 二进制缺失或无法运行时入口脚本打警告跳过，`/cbmui` 不可用，
其余功能不受影响。

## 4. 迁移 / 备份

拷贝 `deploy/docker/data/`（全部任务数据与证书）与 `fwgraph/.env` 即可；
新机器上重复 1–3，并把 compose 中 `./data` 卷与 `SANDBOX_HOST_PREFIX`
一起改成新路径（两处必须一致，原因见 compose 文件头注释）。

## 已知限制

- **uid 对齐**：编排器容器以 root 运行，`data/` 下产物在宿主上属 root；
  沙箱容器以 uid 1000 运行，其可写挂载点（fuzz work、trace /out）已
  chmod 777 兼容。宿主目录若需非 root 属主，自行 chown。
- **glibc 兼容**：fuzz 的 afl-qemu-trace / fuzzhook.so 与 cbm 二进制均为
  宿主编译产物，挂入/拷入容器后依赖容器 glibc 版本；宿主与镜像
  （ubuntu:24.04 / debian slim）差距过大时需按目标镜像工具链重建。
- **frida 本地沙箱**：`pipeline/frida/runner.py` 自行构造 `docker run`，
  其 `-v` 不经过 `SANDBOX_HOST_PREFIX` 改写，编排器容器化时本地 frida
  插桩暂不可用（remote 模式不受影响）。
- EMBA 解包（`EMBA_DIR`）与 dsh 引擎（`DSH_REPO`）默认不在镜像内，
  对应功能缺席；需要时自行挂卷并配置 env。
