# fwgraph 迁移包部署说明

一条命令即可在新机器上恢复平台：导入 **三层 Docker 镜像**（编排器、沙箱、第一层业务数据），播种命名卷，启动 Web，并联网安装 EMBA。

**不写本机绝对路径。** 任务数据在 Docker 命名卷 `fwgraph-data` 里；兄弟沙箱容器的挂载源由编排器启动时自动探测。

## 新机器要求

- Linux x86_64，磁盘建议 **剩余 ≥ 80GB**（数据镜像约数 GB；EMBA 现场再拉约 36GB）
- 能装 Docker
- 能访问外网（拉 EMBA）。纯离线只做导入启动时加 `SKIP_TOOLS=1`
- 可选：Node.js ≥ 22（工作台挖掘引擎）；自己的 IDA 目录（Hex-Rays）

## 一键安装

把本 zip 拷到新机器并解压后（会得到子目录 `fwgraph-migrate-*`）：

```bash
unzip fwgraph-deploy.zip -d fwgraph-deploy
cd fwgraph-deploy
bash install.sh
# 或指定 compose 目录（里面只有 yml / .env / ida-drop，没有源码树）：
# bash install.sh /home/你/fwgraph
```

脚本会依次：

1. 拷一份薄栈（`docker-compose.yml`、`.env`、`ida-drop/`）
2. `docker load`：
   - `fwgraph-orchestrator:local` 编排器
   - `fwgraph-sandbox:local` 沙箱
   - `fwgraph-data:local` **第一层业务数据**（任务、会话、报告、账号）
3. `docker compose --profile migrate run --rm seed` 灌进命名卷 `fwgraph-data`
4. `docker compose up -d orchestrator`，端口 **8000**
5. 联网：`docker pull` EMBA 官方镜像、安装 qemu-user

打开浏览器：`https://<新机器>:8000`（自签证书，选继续访问）。

查状态：

```bash
docker compose -f ~/fwgraph/docker-compose.yml ps
docker images | grep fwgraph
```

## 常用开关

| 命令 | 作用 |
|---|---|
| `SKIP_TOOLS=1 bash install.sh` | 只导入镜像并启动，不拉 EMBA |
| `INSTALL_DSH=1 bash install.sh` | 提示工作台引擎依赖（需 Node 22） |
| `bash install.sh tools` | 以后补装 EMBA / qemu |
| `bash install.sh status` | 查看镜像与容器状态 |

当前用户若还不在 `docker` 组，把用户加入后重新登录，或用有 docker 权限的账号执行脚本。

## 本包包含 / 不包含

**已打进 zip（均为镜像或薄栈）**

- `images/fwgraph-runtime.tar.gz`：编排器 + 沙箱
- `images/fwgraph-data.tar.gz`：第一层任务数据 / 会话 / finding / `.env`
- `stack/docker-compose.yml`（命名卷 + 相对路径 `./ida-drop`）
- `install.sh`

**需现场联网安装（`install.sh` 默认会做）**

- EMBA 镜像 `embeddedanalyzer/emba:2.0.3a`（约 36GB）
- qemu-user / qemu-user-binfmt

AFL++ 已在沙箱镜像内，不必再在宿主编译。

**需你自行放置**

- IDA Pro：整目录拷到安装目录下的 `ida-drop/` 后重启编排器
- 无 IDA 时仍可用镜像内 `rootfs_elf` 做 ELF 反编译（无 Hex-Rays 许可）

## 路径约定

| 用途 | 位置 |
|---|---|
| compose 薄栈 | `~/fwgraph/`（或你传入的目录） |
| 任务数据 | Docker 卷 `fwgraph-data` → 容器内 `/data` |
| 会话 / finding | 同一卷 `/data/vulnagent/` |
| IDA 投放 | `~/fwgraph/ida-drop/`（相对挂载，不是绝对路径） |

不要设置 `SANDBOX_HOST_PREFIX`。编排器会 `docker inspect` 自己的 `/data` 挂载，得到宿主 Source 后再起兄弟容器。

查看卷里的数据：

```bash
docker run --rm -v fwgraph-data:/data busybox ls /data
```

## 故障排查

- 端口被占：改 compose 的 `8000:8000` 映射。
- 解包失败：确认已 `docker pull embeddedanalyzer/emba:2.0.3a`，且允许 `--privileged`。
- 数据是空的：确认 `fwgraph-data:local` 已 load，并重新 `docker compose --profile migrate run --rm seed`。
- 工作台不能开挖掘会话：装 Node 22 后按仓库 `vulnagent/dsh/setup.sh` 补引擎。
- 登录：沿用包内 `.env` / 卷里的 `users.json`；首登若仍是默认口令会要求改密。
