# firmware-code-graph-platform (fwgraph)

> Firmware attack-surface discovery with runtime-coverage evidence:
> EMBA extraction → headless IDA decompilation → CBM code graph →
> source/sink scoring → qemu-user differential coverage → an upstream
> vulnerability-mining agent.

以**运行时覆盖率为核心证据**的固件攻击面发现与排序平台。对解包后的固件
二进制，把静态分析（IDA 反编译、调用图、source/sink 规则）与动态证据
（qemu-user 翻译块覆盖率）结合，输出可验证的攻击面结论，并供上游漏洞
挖掘 AI（vulnagent）只读消费。

平台只产出**忠实、可审计的证据**（observed / verified 分级），不下漏洞
结论；AI 只用于标注与可读性增强，不修改任何原始反编译产物。

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## 核心特性

- **固件解包（M1）**：EMBA extract-only profile（Docker），产出每个 ELF 的
  架构/位数/端序/MD5 清单；原生纯 Python **checksec**（NX/canary/PIE/
  RELRO/FORTIFY），对被 sstrip 掉节表的固件 ELF 依然可用
- **定向反编译（M2）**：按 binary_md5 精准触发 IDA Pro 无头导出
  （`idat -A -S`），IDB 复用、按 md5 归并；导出 Hex-Rays 伪 C + 函数级
  汇编 + symbols.json（攻击面标签 + 规则命名）；可选 M2b 命名恢复
  （FLIRT 签名 / Lumina，默认关）
- **AILIFT AI 语义标注（M3）**：三层漏斗 + 仅攻击链过滤，LLM 输出
  `domain/libc_equiv/confidence/reason` 标签——不改名、不回写 IDB
- **CBM 代码图谱（M4）**：伪 C 树净化后交给 codebase-memory-mcp 建索引，
  元数据（AI 标签、checksec、trace 标记）回注 SQLite；libc_equiv 沿
  SIMILAR_TO 边传播
- **外部输入识别（M6a）**：rootfs 多根扫描（systemd/init.d/inetd/配置/二进制），识别全部公网可达外部输入（协议/端口/输入类型/处理链库/分发链），产出 identification.json；回环、localhost、加密包均显式记账，双验收门自检
- **逐输入攻击面（M6b）**：每个 IN-xxx 导出一个 AS-xxx.json 到 information/：路由链（listen→accept→parse→normalize→dispatch→handler）、分发器/parser/normalizer、终点 handler、载体绑定（URL/header/body→变量，含地址证据）、授权链独立成 AS-AUTH 文件
- **攻击面分析（M6）**：source/sink 规则 → BFS 路径 → 启发式评分
  （`source权重 + sink权重 − 边数×0.22 − 消毒×0.45`）；保守静态路由恢复
  （(字符串, handler) 指针对扫描）
- **qemu-user 差分覆盖率（M7）**：单 ELF `chroot + qemu -d exec` 跑
  baseline/trigger 两遍，trigger-only 函数即请求处理路径；与静态路径
  交叉验证，输出 `observed`（函数被某次 trace 观测）与 `verified`
  （整条链被同一次运行覆盖）——**不做整机/整固件仿真**
- **AI 伪代码增强（ai_enrich）**：伪 C + 函数级汇编送 LLM 恢复调用点
  参数与语义命名，产物为独立 overlay（`source:"ai"`），原始 IDA 导出
  逐字节不动
- **vulnagent（M8）**：上游漏洞挖掘 agent（Managed Agents 抽象，Node ≥20
  零依赖），20 个工具只读消费平台 API（含受控 trace 触发、identification/surfaces 攻击面产物），结构化
  findings（schema 校验 + 去重关联）+ 中文标准报告
- **Web 前端（M5）**：Vue 3 SPA——任务/函数/攻击面（路径详情抽屉 +
  调用链时间线 + 源码三视图）/漏洞挖掘（SSE 事件流卡片）/图谱
  （手写 Canvas 2D）
- **多形态支持**：mips/arm/x86/ppc/riscv ELF 全链路；PX4 容器与 raw
  ARM Cortex-M 裸机镜像（链接脚本验证的板级地址表）

## 系统架构

```
固件.bin
  │  POST /firmware
  ▼
[EMBA 解包 extract-only] ──► manifest.json（ELF 清单 + checksec）
  │  POST /jobs/{id}/decompile {"binary_md5s":[...]}
  ▼
[IDA 无头反编译 idat] ──► symbols.json + functions/*.c + functions/*.asm
  │  POST /jobs/{id}/ailift            ▼
  ▼                              [M2b FLIRT/Lumina 命名恢复]
[AILIFT AI 标注]（仅攻击链函数）
  │  POST /jobs/{id}/graph
  ▼
[CBM 图谱索引] ──► 攻击面分析(source/sink→路径→评分) ──► 路由分析
  │
  ├─ POST /jobs/{id}/trace（qemu-user baseline/trigger 差分覆盖率）
  │        └─► 差分函数 ──► 交叉验证（observed/verified）
  └─ POST /jobs/{id}/aienrich（AI 伪代码增强 overlay）

[vulnagent 上游漏洞挖掘 AI]（只读 API + 受控 trace ──► findings + report.md）
        ▲
[Vue 3 SPA] 任务 / 函数 / 攻击面 / 漏洞挖掘 / 图谱
```

## 部署要求

| 依赖 | 版本/说明 | 用途 |
|---|---|---|
| Linux | 开发环境 Ubuntu 26.04 | 运行平台 |
| Python | ≥ 3.12（`fwgraph/.venv`） | orchestrator + pipeline |
| IDA Pro | 9.1（`idat` 无头） | 反编译（商业软件，自备） |
| EMBA | latest + Docker | 固件解包（extract-only） |
| codebase-memory-mcp | ≥ 0.9 | 代码图谱索引与查询 |
| qemu-user | static（如 10.2.1） | 单 ELF 覆盖率采集 |
| Node.js | ≥ 20 | vulnagent 运行 + webui 构建 |
| LLM | OpenAI 兼容或 Anthropic Messages 网关 | AILIFT/ai_enrich/vulnagent（可选但推荐） |

## 快速开始

```bash
# 1. 环境与依赖
cd fwgraph && ./setup.sh                 # 建 venv、装依赖（详见脚本）
cp .env.example .env                     # 配置 ORCH_TOKEN / IDA_DIR / EMBA_* / LLM_*

# 1a. EMBA 独立克隆（不随本仓库分发，约 3.8G，含 Docker 镜像拉取）
git clone https://github.com/e-m-b-a/emba ~/emba
# 按 EMBA 官方文档安装（installer.sh -d 默认模式），然后把 .env 里的
# EMBA_DIR 指向该克隆路径（示例值是开发机的绝对路径，必须改成实际路径）

# 2. 启动编排服务（API + 前端托管，:8000）
./scripts/run_orchestrator.sh            # 或 systemctl --user start fwgraph.service

# 3. 构建前端
cd webui && npm ci && npx vite build

# 4. 分析一个固件（$T = ORCH_TOKEN，$H = http://<host>:8000）
curl -X POST -H "Authorization: Bearer $T" -F "file=@firmware.bin" $H/firmware
curl -X POST -H "Authorization: Bearer $T" -H "Content-Type: application/json" \
  -d '{"binary_md5s":["<md5>"]}' $H/jobs/<job_id>/decompile
curl -X POST -H "Authorization: Bearer $T" $H/jobs/<job_id>/ailift
curl -X POST -H "Authorization: Bearer $T" $H/jobs/<job_id>/graph   # 含攻击面+路由
curl -X POST -H "Authorization: Bearer $T" -H "Content-Type: application/json" \
  -d '{"binary_md5":"<md5>","argv":["-c","/path/to.conf"],"port":8098,
       "request_path":"/index.html"}' $H/jobs/<job_id>/trace

# 5. 漏洞挖掘（vulnagent）
cd vulnagent && cp .env.example .env     # FWGRAPH_BASE_URL/TOKEN/JOB_ID、LLM_*
node src/cli.js run "对 verified 路径做漏洞挖掘" --max-turns 40
# 或打开 SPA「漏洞挖掘」页签启动并实时查看事件流
```

## API 概览

统一鉴权 `Authorization: Bearer <ORCH_TOKEN>`；错误语义：400 参数 /
404 未知资源 / 409 状态冲突 / 502 上游故障。

| 端点 | 说明 |
|---|---|
| `POST /firmware` | 上传固件，后台 EMBA 解包 |
| `POST /jobs/{id}/decompile` | 定向/全量反编译 |
| `POST·GET /jobs/{id}/ailift` | AILIFT 标注与统计 |
| `POST·GET /jobs/{id}/graph` | 图谱构建 / 摘要 / layout |
| `POST·GET /jobs/{id}/attack` | 攻击面重算 / 摘要 |
| `POST·GET /jobs/{id}/routes` | 路由扫描 / 摘要 |
| `POST·GET /jobs/{id}/inputs`、`GET /jobs/{id}/identification` | M6a 外部输入识别（identification.json，公网可达、零遗漏） |
| `POST·GET /jobs/{id}/surfaces`、`GET /jobs/{id}/surfaces/{sid}` | M6b 逐输入攻击面导出（information/AS-*.json + AS-AUTH-*.json） |
| `POST /jobs/{id}/trace`、`GET /jobs/{id}/traces[/{tid}]` | 差分覆盖率 |
| `GET /jobs/{id}/functions[/{md5}/{addr}/source]` | 函数清单与源码（`?ai=1` overlay、`?asm=1` 汇编） |
| `POST /jobs/{id}/aienrich`、`GET .../aienrich/{md5}` | AI 伪代码增强 |
| `POST /graph/query` | 统一查询：search/cypher/trace/snippet/dangerous/trace_flow/attack_surface/routes |
| `POST·GET /vulnagent/sessions[...]`、`GET /vulnagent/findings[/{fid}]` | 挖掘 session 与 findings |

CLI 亦可直跑 pipeline：`python -m pipeline.trace.tracer` /
`pipeline.ailift.runner` / `pipeline.decompile.ai_enrich` /
`pipeline.attack.runner` / `tools.ida-no-mcp.rootfs_elf.cli`。

## 项目结构

```
fwgraph/                  Python 根包
  orchestrator/app/       FastAPI 编排（main/decompiler/extractor/webui/vulnagent_api）
  orchestrator/tests/     pytest（250 项基线）
  pipeline/               extract / decompile / ailift / graph / attack / routes / trace
  config/                 attack_surface.yaml、naming_spec.yaml
  libc-sigs/              uClibc FLIRT 签名制作
  scripts/                运维与探测脚本
  webui/                  Vue 3 SPA（src → vite build → dist）
vulnagent/                上游漏洞挖掘 agent（Managed Agents：agent.json /
                          environment.json / sessions / events.sse / findings）
tools/ida-no-mcp/         rootfs 批量 ELF 分析工具（vendor）
HANDOFF.md                交接记录（2026-08-03）
项目介绍.md               项目介绍与演进（v1.5）
开发计划.md               历史开发计划
fwgraph/docs/             专题笔记（如 m2b-notes.md）
```

## 设计原则

1. **不做整机/整固件仿真**；只允许单 ELF qemu-user 覆盖率
2. **AI 只标注不改证据**：不改 IDA 名、不回写 IDB、不覆盖原始反编译产物
3. **结论分级**：observed / verified 分开输出；socket accept、连接成功、
   空差分、传输错误都不是漏洞
4. **保守负结果**：不命中就如实输出 0（本案例静态路由恢复即为 0 条），
   不为扩路径放宽规则

## 验证状态（2026-08-05）

- 测试基线：250 项，249 通过 / 1 已知测试间污染项（单独运行通过，待修）
- 案例固件：小米 R3 `miwifi_r3_all_55ac7_2.11.20.bin`（mips32le，274 ELF）
  - 定向反编译 sysapihttpd：1847 函数、1490 成功（80.7%），零加固
  - 攻击面：42 source / 188 sink / 50 路径，3 条 verified
  - CVE-2019-18371（sysapihttpd alias 目录穿越）用 M7 设施动态复现成功
  - vulnagent 产出 CWE-121 栈溢出 finding（已附勘误与待确认问题）

## 文档

- 部署运维手册：[fwgraph/README.md](fwgraph/README.md)
- 交接记录：[HANDOFF.md](HANDOFF.md)
- 项目介绍与演进：[项目介绍.md](项目介绍.md)
- 历史开发计划：[开发计划.md](开发计划.md)
- vulnagent 说明：[vulnagent/README.md](vulnagent/README.md)
- ida-no-mcp 说明：[tools/ida-no-mcp/rootfs_elf/README.md](tools/ida-no-mcp/rootfs_elf/README.md)
- M2b 命名恢复专题：[fwgraph/docs/m2b-notes.md](fwgraph/docs/m2b-notes.md)

## 许可

[Apache License 2.0](LICENSE)
