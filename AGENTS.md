# 仓库协作约定

## 文档同步（强制）

每次完成修改后，必须同步更新对应进度文档（根目录）：

- `进度-项目.md` — 模块状态、验证记录、已知限制、运行环境
- `进度-前端.md` — webui 页面/主题/交互变更
- `进度-后端.md` — pipeline/API/vulnagent/dsh 变更

同时更新文档头部的「最后更新」日期。改了哪层就同步哪层；跨层改动三篇都过一遍。

## 部署与重启

- 本仓库事实源在 VM `~/firmware-graph`（Ubuntu 26.04, 192.168.141.135）。
- 修改 Python 代码后重启编排服务：`kill $(cat fwgraph/data/orchestrator.pid) && bash fwgraph/scripts/run_orchestrator.sh`。
- 修改前端后在 `fwgraph/webui` 执行 `npx vite build`。
- 容器化部署（`deploy/docker/`）：`docker compose -f deploy/docker/docker-compose.yml up -d --build` 启动/重建，`docker compose -f deploy/docker/docker-compose.yml down` 停止；数据（含 TLS 证书）在 `deploy/docker/data/`，详见 `deploy/docker/README.md`。
- 测试基线：`fwgraph/.venv/bin/python -m pytest orchestrator/tests -q`（466 项：465 通过 + 1 跳过），改动后必须保持该基线。
