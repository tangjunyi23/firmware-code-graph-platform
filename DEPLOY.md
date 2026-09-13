# fwgraph 部署包说明（2026-09-08 打包）

本归档是完整的源码 + 预构建前端 + 账号/报告数据的部署包，在新机器上解压后即可按下面步骤拉起。

## 1. 包内有什么

| 内容 | 说明 |
|---|---|
| `fwgraph/` | 平台全部源码（orchestrator + pipeline + scripts + libc-sigs） |
| `fwgraph/webui/dist/` | **已预构建**的前端产物， orchestrator 直接静态托管，可不装 Node |
| `fwgraph/webui/src/` | 前端源码（如需改 UI 再构建：`npm install && npm run build`） |
| `fwgraph/.env` | 当前环境的真实配置（**含 LLM API Key 等敏感信息**，外发前自行删改） |
| `fwgraph/data/users.json` 等 | 账号、系统设置、配额、审计流水 |
| `fwgraph/data/reports/`、`vulnlib/` | 已生成的报告与漏洞库数据 |
| `vulnagent/`、`deploy/`、`tools/` | 挖掘 Agent、Docker 部署套件、辅助工具 |
| `.git/` | 完整版本历史 |

**未包含**（原机器上约 7.9G，均为任务运行产物或可重建内容）：
`data/{firmware,extracted,idb,pseudocode,cbm,graphext,decrypt,routes,attack,traces,surfaces,inputs,qemu_exec,fuzz}`（历史固件与分析产物）、`data/sessions.json`（旧登录令牌，新机器重新登录即可）、`data/tls/`（自签证书，首启自动重新生成）、`.venv`、`webui/node_modules`。

## 2. 环境要求

- Linux（Ubuntu 22.04+/26.04 验证过），Python ≥ 3.12（开发机 3.14）、Node ≥ 20（仅重建前端时需要）
- **完整分析能力**还需要项目外部依赖（详见根目录 `README.md` 第 1 节表格）：IDA Pro 9.1、EMBA（docker 镜像 `embeddedanalyzer/emba:2.0.3a`）、codebase-memory-mcp、qemu-user；只有 orchestrator + Web 界面也能起来，但上传分析会失败在对应阶段
- 外部工具不在本包内（许可/体积原因），需按 README 自行安装

## 3. 裸机部署（最快路径）

```bash
tar -xzf fwgraph-deploy-*.tar.gz && cd firmware-code-graph-platform/fwgraph

# 3.1 检查 .env：IDA_DIR / EMBA_* / LLM_API_KEY 等路径改成新机器的实际值
vim .env

# 3.2 Python 环境（也可以直接跑 setup.sh，它会连同数据目录一起建好）
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 3.3 启动（HTTPS 自签，首启自动生成 data/tls/）
scripts/run_orchestrator.sh
# 或前台调试：
# .venv/bin/python -m uvicorn orchestrator.app.main:app --host 0.0.0.0 --port 8000
```

浏览器打开 `https://<新机器IP>:8000/`（HTTP 则 `ORCH_SSL=0`）。用 `data/users.json` 里的既有账号登录；默认深色主题。`scripts/run_orchestrator.sh` 默认 `FWGRAPH_ROOT` 是旧路径，用环境变量指到新位置：`FWGRAPH_ROOT=$PWD scripts/run_orchestrator.sh`。

## 4. Docker 部署（可选）

`deploy/docker/` 内含 docker-compose 编排（orchestrator / CBM / IDA 投放 / 沙箱），用法见 `deploy/docker/README.md`。

## 5. 打包时间点的代码状态

- 2026-09-08：失败诊断与阶段重试、图谱检索结构化渲染、报告三要素、全站 PageHeader 统一、仪表盘 KPI 重构、侧栏迷你模式（详见 git log）
- 前端 dist 与该源码状态同步构建，无需重新 build 即可运行
