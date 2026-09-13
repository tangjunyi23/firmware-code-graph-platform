# fwgraph 容器化部署（Phase 3）

三个镜像：

- `fwgraph-orchestrator`（编排器 + webui + vulnagent，本目录 `Dockerfile`）
- `fwgraph-sandbox`（不可信固件动态分析沙箱，`Dockerfile.sandbox`，运行时由编排器经 docker.sock 按需起兄弟容器）
- `fwgraph-data`（第一层业务数据，`Dockerfile.data`，由 `pack.sh` 构建；命名卷 `fwgraph-data`）

**不要写本机绝对路径，也不要设置 `SANDBOX_HOST_PREFIX`。** 编排器启动时自动探测 `/data` 卷在宿主上的 Source。

## 1. 准备 .env

```bash
cp fwgraph/.env.example fwgraph/.env   # 至少填 LLM_API_KEY、ORCH_TOKEN
```

`.env` 不进编排器镜像（`.dockerignore` 已排除），运行时由 compose env_file 注入。

## 2. 构建

```bash
cd <仓库根>
# 沙箱镜像（build-only 服务，--profile build 才参与）
docker compose -f deploy/docker/docker-compose.yml --profile build build sandbox
# 编排器镜像
docker compose -f deploy/docker/docker-compose.yml build orchestrator
```

可选组件（不传也能构建，对应功能缺席）：

- **rootfs_elf** 已打进编排器镜像（`/app/tools/ida-no-mcp/rootfs_elf`），ELF 反编译不要求 Hex-Rays 许可文件。
- **自己的 IDA**：整目录拷到 `deploy/docker/ida-drop/`（见该目录 README），重启 orchestrator 即识别。
  也可放数据卷 `ida/`。不必改镜像。`idat` / `libidalib.so` 在根下或下一层子目录均可。
- cbm 二进制：`additional_contexts.cbmbin` 指向含真实二进制的目录（符号
  链接需先 `cp -L` 解引用），或命令行 `--build-context cbmbin=<目录>`。
- **EMBA 解包镜像**（约 36GB，不打进编排器镜像）：

```bash
bash deploy/docker/pull-tools.sh
# 等价：docker compose -f deploy/docker/docker-compose.yml --profile tools pull
```

离线交付先在有网机器 `docker save embeddedanalyzer/emba:2.0.3a | gzip > emba-2.0.3a.tar.gz`，
对方机器 `gunzip -c emba-2.0.3a.tar.gz | docker load`。
编排器设 `EMBA_BACKEND=docker`，解包时经 docker.sock 起特权兄弟容器（需允许 privileged）。

注意：实测 buildkit 对 `COPY --from=<命名上下文>` 的缓存键不含上下文
内容——先按真实目录构建、再改回空占位重建时会复用到含旧内容的层；
撤销/更换可选上下文后请加 `--no-cache` 重建（或先 `docker buildx prune`）。

## 3. 启动与验证

```bash
docker compose -f deploy/docker/docker-compose.yml up -d
docker compose -f deploy/docker/docker-compose.yml ps    # healthy 即就绪
curl -k https://127.0.0.1:8000/login -o /dev/null -w '%{http_code}\n'   # 200
```

数据在命名卷 `fwgraph-data`（容器内 `/data`）。首启在 `/data/certs/` 自签 TLS
证书（`ORCH_CERT_CN/SANS` 控制，持久化不重签）；cbm 二进制缺失或无法运行时
入口脚本打警告跳过，`/cbmui` 不可用，其余功能不受影响。

查看卷：

```bash
docker run --rm -v fwgraph-data:/data busybox ls /data
```

## 4. 迁移 / 备份

用 `bash deploy/migrate/pack.sh <目录> --zip` 打迁移包：第一层（代码 + 任务数据 +
会话）都是 Docker 镜像，compose 只有相对路径和命名卷。新机器 `bash install.sh`。

手册见 [../migrate/DEPLOY.md](../migrate/DEPLOY.md)。

## 已知限制

- **uid 对齐**：编排器容器以 root 运行，卷内产物属 root；
  沙箱容器以 uid 1000 运行，其可写挂载点（fuzz work、trace /out）已
  chmod 777 兼容。
- **glibc 兼容**：fuzz 的 afl-qemu-trace / fuzzhook.so 与 cbm 二进制均为
  宿主编译产物，挂入/拷入容器后依赖容器 glibc 版本；宿主与镜像
  （ubuntu:24.04 / debian slim）差距过大时需按目标镜像工具链重建。
- **frida 本地沙箱**：`pipeline/frida/runner.py` 自行构造 `docker run`，
  其 `-v` 不经过 `host_mount_path` 改写，编排器容器化时本地 frida
  插桩暂不可用（remote 模式不受影响）。
- dsh 引擎（`DSH_REPO`）默认不在镜像内，对应功能缺席；需要时自行挂卷。
- EMBA 以官方镜像 `embeddedanalyzer/emba:2.0.3a` 打包交付（`EMBA_BACKEND=docker`），
  不把 36GB 分析环境打进编排器层。对方机器必须 `pull` 或 `load` 该镜像，并允许
  编排器经 docker.sock 启动 `--privileged` 的 `emba` 容器。
