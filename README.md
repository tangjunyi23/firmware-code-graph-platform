# firmware-code-graph-platform (fwgraph)

> EMBA 解包 → IDA 无头反编译 → CBM 图谱 → qemu-user 差分覆盖 →
> 工作台 DeepSeek Harness 挖掘 agent。

固件攻击面发现平台：静态（反编译、调用图、source/sink）和动态（单 ELF
qemu-user 覆盖差分、整二进制 AFL、PoC 执行）接到同一条证据链。上游挖掘
AI 在工作台里调平台工具，产出带调用链和 PoC 的 finding。**不做整机仿真。**

当前前端入口是 **工作台**（选已完成的前置任务 → 开挖掘会话）。编排提示、
能力验收文案不对用户展示。动态工具结果带 `hunt_next`，给 agent 自己用，
不是给用户看的验收表。

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## 当前状态（2026-08-23）

- 工作台 dsh-web：Thinking 一行、工具卡、审批允许/拒绝、全部同意/需要审批、
  当前窗口开挖、输入框停止生成（只 cancel）、侧栏停止对话（`/stop`）。
- `max_turns` 按 `session.prompt` 计数；到顶暂停询问「继续挖掘 / 结束本轮」。
  暂停后再发消息走 `POST /resume`，看门狗不能把 `done` 会话偷着重开。
- 动态：`fw_request_trace` 支持 `via=stdin` / `input_path=/tmp/<file>` /
  `payload` / `payload_hex` / `payloads_hex`；`fw_qemu_exec` 单次跑 PoC。
  没喂输入就 SIGSEGV 标 `crash_kind=startup`（环境，禁止放弃该 ELF）。
- Archer C7 v2 无人值守挖掘已跑过：job `3a1f3c822c22`，主会话
  `s-mt4rda4n-55d3`，18 条 finding 与会话事件在仓库里。解包/图谱数据仍只在
  分析机 `fwgraph/data/`。
- 已知限制：网络口 trace 仍大量空差分（缺处理函数覆盖）；MIPS 函数级 AFL
  handshake 常失败，整二进制 AFL 能跑；全系统 QEMU 不做。

更细的变更记在 [进度-项目.md](进度-项目.md)。

## 核心特性

- **固件解包（M1）**：EMBA extract-only profile（Docker），产出每个 ELF 的
  架构/位数/端序/MD5 清单；原生纯 Python **checksec**（NX/canary/PIE/
  RELRO/FORTIFY），对被 sstrip 掉节表的固件 ELF 依然可用
- **定向反编译（M2）**：按 binary_md5 精准触发 IDA Pro 无头导出
  （`idat -A -S`），IDB 复用、按 md5 归并；导出 Hex-Rays 伪 C + 函数级
  汇编 + symbols.json（攻击面标签 + 规则命名）；可选 M2b 命名恢复
  （FLIRT 签名 / Lumina，默认关）
- **CBM 代码图谱（M4）**：伪 C 树净化后交给 codebase-memory-mcp 建索引，
  元数据（checksec、trace 标记）回注 SQLite；libc_equiv 沿
  SIMILAR_TO 边传播
- **图谱扩展（M4b）**：每个函数生成 **CFG**（基本块+边，含跳表
  indirect_jump 建模）与 **AST**（tree-sitter 解析伪 C），`/graph/query`
  新增 `cfg`/`ast` op，支持 `max_nodes/max_depth` 截断
- **外部输入识别（M6a）**：rootfs 多根扫描（systemd/init.d/inetd/配置/二进制），识别全部公网可达外部输入（协议/端口/输入类型/处理链库/分发链），证据四级分级（observed/config/kb_default/candidate），产出 identification.json；回环、localhost、加密包均显式记账，双验收门自检
- **逐输入攻击面（M6b）**：每个 IN-xxx 导出一个 AS-xxx.json 到 information/：路由链（listen→accept→parse→normalize→dispatch→handler）、分发器/parser/normalizer、终点 handler、载体绑定（URL/header/body→变量，含地址证据，真/占位分离）、授权链独立成 AS-AUTH 文件
- **攻击面分析（M6）**：source/sink 规则 → BFS 路径 → 启发式评分
  （`source权重 + sink权重 − 边数×0.22 − 消毒×0.45`）；保守静态路由恢复
  （(字符串, handler) 指针对扫描 + GoAhead 表适配）
- **qemu-user 差分覆盖率（M7）**：单 ELF 在 docker 沙箱里 `chroot + qemu -d exec`
  跑 baseline/trigger。网络口用 port + payload；解析器/CLI 用 `via=stdin` 或
  `input_path=/tmp/<file>`。空差分不是漏洞，agent 应改 stdin 再跑。
  **不做整机仿真。**
- **PoC 执行（qemu_exec）**：单次跑固件 ELF，看 crash/timeout/error。
  启动即崩（没喂 payload）是环境；喂了 payload 才崩才当动态证据。
- **函数级 fuzz / frida hook**：x86 用 frida；ARM/MIPS 优先整二进制 AFL++
  qemu（函数级 persistent handshake 在 MIPS 上经常失败）
- **工控协议模糊测试（M-ICS）**：黑盒网络协议 fuzz——协议模板库
  （Modbus TCP / S7 / OPC UA / DNP3 / MQTT / HTTP）+ 确定性字段级变异
  （boundary/bitflip/fill/overflow/random，种子可复现）+ 纯软件监视器
  （TCP 探活/ICMP/协议探测）+ 故障确认与复播复现统计；授权确认闸门 +
  公网目标默认禁止；报告注册进报告中心（DOCX/PDF 导出）
- **vulnagent（M8）**：工作台默认 **dsh-web**（DeepSeek Harness profile
  `fwgraph`）。工具走平台 API；`fw_get_trace` / `fw_list_traces` /
  `fw_qemu_exec` 返回压缩结果 + `hunt_next`（读差分函数或改 via=stdin）。
  `record_finding` 必须同时有 `call_chain`（`→`）和 `poc`。轮次上限、
  会话预算（trace 192 / fuzz 12 / exec 8）、日配额由编排器与插件共同卡住。
- **Web 前端**：工作台（对话在左、选前置任务后发送即开挖）+ 仪表盘 /
  前置任务 / 函数 / 攻击面 / 输入面 / 图谱 / 协议挖掘 / 报告 / 用户 /
  日志 / 设置。隐藏 `【编排】` 与能力验收类注入气泡。
- **产品化与安全**：账号密码登录（防爆破锁定 + 弱口令黑名单 + 首登强制
  改密）、会话 token（fws-）+ 主 token 双轨、owner 数据隔离（他人 404）、
  全量审计日志、按 job×日配额（trace/fuzz/frida/protofuzz）、
  TLS 自签默认开（`ORCH_SSL=0` 退回明文）
- **多形态支持**：mips/arm/x86/ppc/riscv ELF 全链路；PX4 容器与 raw
  ARM Cortex-M 裸机镜像（链接脚本验证的板级地址表）

## 系统架构

```
固件.bin
  │  POST /firmware（支持 auto=1 全自动链）
  ▼
[EMBA 解包 extract-only] ──► manifest.json（ELF 清单 + checksec）
  │  POST /jobs/{id}/decompile {"binary_md5s":[...]}
  ▼
[IDA 无头反编译 idat] ──► symbols.json + functions/*.c + functions/*.asm
  │                              [M2b FLIRT/Lumina 命名恢复]
  │  POST /jobs/{id}/graph
  ▼
[CBM 图谱索引] ──► [M4b CFG/AST] ──► 攻击面分析 ──► 路由分析
  │                                    │                │
  │                                    ▼                ▼
  │                          [M6a 外部输入识别] ──► [M6b 逐输入攻击面导出]
  │                          identification.json      information/AS-*.json
  │
  ├─ POST /jobs/{id}/trace（via=net|stdin，input_path，payload/payloads_hex）
  ├─ POST /jobs/{id}/qemu-exec（单次 PoC，crash_kind=startup|payload）
  ├─ POST /jobs/{id}/fuzz（ARM/MIPS：整二进制 AFL++ qemu）
  ├─ POST /jobs/{id}/frida（x86）
  └─ POST /protofuzz

[工作台 dsh-web]  session.prompt 计轮次 → 工具 hunt_next → findings + report.md
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
| AFL++ | 按架构构建 afl-qemu-trace | ARM/MIPS 函数级 fuzz（可选） |
| frida | ≥ 17（pip） | x86 hook 动态分析（可选） |
| Node.js | ≥ 20（dsh 需 22 + pnpm） | vulnagent 运行 + webui 构建 |
| LibreOffice | writer（soffice） | 报告 PDF 导出（可选） |
| LLM | OpenAI 兼容或 Anthropic Messages 网关 | vulnagent（可选但推荐） |

## 快速开始

```bash
# 1. 环境与依赖
cd fwgraph && ./setup.sh                 # 建 venv、装依赖（详见脚本）
cp .env.example .env                     # 配置 ORCH_TOKEN / IDA_DIR / EMBA_* / LLM_*

# 1a. EMBA 独立克隆（不随本仓库分发，约 3.8G，含 Docker 镜像拉取）
git clone https://github.com/e-m-b-a/emba ~/emba
# 按 EMBA 官方文档安装（installer.sh -d 默认模式），然后把 .env 里的
# EMBA_DIR 指向该克隆路径（示例值是开发机的绝对路径，必须改成实际路径）

# 2. 启动编排服务（API + 前端托管，默认 HTTPS :8000，ORCH_SSL=0 退回明文）
./scripts/run_orchestrator.sh            # 或 systemctl --user start fwgraph.service

# 3. 构建前端
cd webui && npm ci && npx vite build

# 4. 浏览器打开 https://<host>:8000 —— admin/admin123 首登强制改密
#    前置任务页上传固件跑完全自动链；工作台选该任务后发送即开始挖掘

# 5. 挖掘引擎（工作台 dsh-web，Node 22 + pnpm）
bash vulnagent/dsh/setup.sh              # clone/build DeepSeek Harness + fwgraph profile
cd vulnagent && cp .env.example .env     # FWGRAPH_BASE_URL / TOKEN / LLM_*

# 6. 命令行上传固件（$T = fws- 会话 token 或主 token）
curl -k -X POST -H "Authorization: Bearer $T" -F "file=@firmware.bin" $H/firmware?auto=1
```

## Docker 部署（可选）

除宿主机直跑外，也可用 Docker Compose 部署（编排器 + webui + vulnagent
单容器；沙箱镜像由编排器经 docker.sock 按需起兄弟容器）：

```bash
# 构建（--profile build 含沙箱镜像；IDA/cbmbin 可选构建上下文见手册）
docker compose -f deploy/docker/docker-compose.yml --profile build build
# 启动（SANDBOX_HOST_PREFIX 须等于 deploy/docker/data 的宿主绝对路径）
SANDBOX_HOST_PREFIX=$PWD/deploy/docker/data \
  docker compose -f deploy/docker/docker-compose.yml up -d
# 停止
docker compose -f deploy/docker/docker-compose.yml down
```

数据（含 TLS 证书）持久化在 `deploy/docker/data/`；完整手册（.env、
可选组件、已知限制）见 [deploy/docker/README.md](deploy/docker/README.md)。

## 仓库里有什么

GitHub 只收源码和一份 Archer C7 挖掘记录，**clone 下来不能当分析机直接接着挖**。

| 在仓库里 | 不在仓库里（分析机本地） |
|---|---|
| 平台源码、工作台、dsh 插件/skill、测试 | `.env`、TLS 私钥、账号口令 |
| `vulnagent/sessions/`（4 个会话：state、events.sse、报告） | `fwgraph/data/`：解包 rootfs、固件、IDA/IDB、伪代码、CBM 图谱、trace |
| `vulnagent/findings/`（18 条 finding + `index.jsonl`） | EMBA、IDA Pro、qemu-user、沙箱镜像、LLM key |

参考会话：`s-mt4rda4n-55d3`（主挖掘，job `3a1f3c822c22`）、`s-mt5k23tt-aaed`（stdin 验收）。finding 可直接读 JSON；要复现动态验证必须在本机重新解包建图，或继续用已有分析机上的 `fwgraph/data/`。

## API 概览

统一鉴权 `Authorization: Bearer <token>`（`POST /auth/login` 换取 fws-
会话 token；主 token 仅 Bearer header，不接受 URL 传参）；错误语义：
400 参数 / 401 未认证 / 403 越权 / 404 未知资源（含他人数据）/
409 状态冲突 / 429 配额 / 502 上游故障。

| 端点 | 说明 |
|---|---|
| `POST /firmware` | 上传固件，后台 EMBA 解包（`?auto=1` 全自动链） |
| `POST /jobs/{id}/auto` | 终态任务补跑全自动链 |
| `POST /jobs/{id}/decompile` | 定向/全量反编译 |
| `POST·GET /jobs/{id}/graph` | 图谱构建 / 摘要 / layout |
| `POST·GET /jobs/{id}/graphext` | M4b CFG/AST 生成与统计 |
| `POST·GET /jobs/{id}/attack` | 攻击面重算 / 摘要 |
| `POST·GET /jobs/{id}/routes` | 路由扫描 / 摘要 |
| `POST·GET /jobs/{id}/inputs`、`GET /jobs/{id}/identification` | M6a 外部输入识别（identification.json，公网可达、零遗漏） |
| `POST·GET /jobs/{id}/surfaces`、`GET /jobs/{id}/surfaces/{sid}` | M6b 逐输入攻击面导出（information/AS-*.json + AS-AUTH-*.json） |
| `POST /jobs/{id}/trace`、`GET /jobs/{id}/traces[/{tid}]` | 差分覆盖率（`via`/`input_path`/`payloads_hex`） |
| `POST·GET /jobs/{id}/qemu-exec[/{run_id}]` | 单次 qemu-user PoC |
| `POST·GET /jobs/{id}/fuzz[/{run_id}]` | AFL++ qemu fuzz（ARM/MIPS，整二进制优先） |
| `POST·GET /jobs/{id}/frida[/{run_id}]` | frida hook（x86，本机/远程） |
| `GET /jobs/{id}/functions[/{md5}/{addr}/source]` | 函数清单与源码（`?asm=1` 汇编） |
| `GET /jobs/{id}/functions/{md5}/{addr}/brief` | 函数分诊卡（约 1KB：攻击面元数据+伪代码头+危险调用行号+callees） |
| `POST /graph/query` | 统一查询：search/cypher/trace/snippet/dangerous/trace_flow/attack_surface（含 brief）/routes/cfg/ast（含截断） |
| `GET /protofuzz/protocols`、`POST /protofuzz`、`GET /protofuzz[/{rid}]`、`POST .../stop`、`POST .../report` | 工控协议模糊测试 |
| `POST·GET /vulnagent/sessions[...]`、`POST .../continue`、`POST .../resume`、`POST .../stop` | 挖掘会话（到顶续跑 / 暂停后拉活 / 结束） |
| `GET·POST·PATCH /vulnagent/findings[/{fid}]` | findings（服务端权威校验，须 call_chain+poc） |
| `POST /auth/login`、`POST /auth/logout`、`GET /auth/me`、`POST /auth/password` | 认证 |
| `GET·POST·PATCH·DELETE /users`、`GET /audit` | 用户管理 / 审计（admin） |
| `GET /dashboard`、`GET /system/info`、`GET·PUT /system/config`、`GET /logs` | 运维面板（部分 admin） |
| `POST·GET /jobs/{id}/report`、`GET /reports[/{rid}[/download]]`、`GET /reports/{rid}/export?fmt=docx|pdf` | 报告中心（综合/挖掘/协议测试三类） |

CLI 亦可直跑 pipeline：`python -m pipeline.trace.tracer` /
`pipeline.attack.runner` / `tools.ida-no-mcp.rootfs_elf.cli`。

## 项目结构

```
fwgraph/                  Python 根包
  orchestrator/app/       FastAPI 编排（main/accounts/admin_api/protofuzz_api/
                          vulnagent_api/report_export/decompiler/extractor/webui）
  orchestrator/tests/     pytest（基线见根目录 AGENTS.md）
  pipeline/               extract / decompile / graph / graphext /
                          attack / routes / inputs / surfaces / trace /
                          fuzz / frida / protofuzz / report
  config/                 attack_surface.yaml、naming_spec.yaml
  libc-sigs/              uClibc FLIRT 签名制作
  scripts/                运维与探测脚本
  webui/                  Vue 3 SPA；挖掘入口 src/workbench/
vulnagent/                挖掘 agent
  sessions/ findings/     Archer C7 会话事件与 18 条 finding（随仓库）
  dsh/                    Harness profile、工具插件、fwgraph-firmware-hunt skill
tools/ida-no-mcp/         rootfs 批量 ELF 分析工具（vendor）
进度-项目.md              当前进度总览（每次改动同步）
进度-前端.md              前端进度
进度-后端.md              后端进度
HANDOFF.md                交接记录（2026-08-03）
项目介绍.md               项目介绍与演进（v1.5）
开发计划.md               历史开发计划
fwgraph/docs/             专题笔记（如 m2b-notes.md）
```

## 设计原则

1. **不做整机/整固件仿真**；动态证据只到单 ELF 覆盖率、函数级 fuzz、
   单点 hook、协议级黑盒 fuzz
2. **不改证据**：不改 IDA 名、不回写 IDB、不覆盖原始反编译产物；
   挖矿 AI 只消费 Hex-Rays 原始伪代码作为可引用证据
3. **结论分级**：observed / verified 分开输出；socket accept、连接成功、
   空差分、传输错误都不是漏洞；findings 置信度服务端锚点封顶
   （static-only ≤ 0.7）
4. **保守负结果**：不命中就如实输出 0，不为扩路径放宽规则；candidate 级
   证据如实标注为噪声
5. **安全默认**：TLS 默认开、他人数据 404、配额按日限、审计全量、
   公网 fuzz 目标默认禁止

## 验证状态（2026-08-23）

- 测试基线：orchestrator **529 项，528 通过 + 1 跳过**（见 `AGENTS.md`）；
  vulnagent 插件 `dsh_plugin.test.js` 23 项通过。改动后保持该基线，优先模块测试。
- Archer C7 v2 `ArcherC7v2_en_us_3_15_4_up(260427).bin`（job `3a1f3c822c22`）
  - 工作台无人值守挖掘：会话 `s-mt4rda4n-55d3`（80 轮，15+ finding，多为 static-only）
  - stdin 验收 `s-mt5k23tt-aaed`：`input_path` `a432876827e2` 非空差分 45；
    `via=stdin` `f55640905b63` → `ok_empty_diff`
  - 会话与 finding 在 `vulnagent/sessions/`、`vulnagent/findings/`；解包/图谱不在 Git
- 更早案例（2026-08-17，仍有效）：小米 R3 mips32le；`US_MX12V2.tar` arm32
  外部输入/攻击面/CFG/AST；CVE-2019-18371 用 M7 复现过

## 文档

- 部署运维手册：[fwgraph/README.md](fwgraph/README.md)
- 当前进度：[进度-项目.md](进度-项目.md) / [进度-前端.md](进度-前端.md) / [进度-后端.md](进度-后端.md)
- 交接记录：[HANDOFF.md](HANDOFF.md)
- 项目介绍与演进：[项目介绍.md](项目介绍.md)
- 历史开发计划：[开发计划.md](开发计划.md)
- vulnagent 说明：[vulnagent/README.md](vulnagent/README.md)
- ida-no-mcp 说明：[tools/ida-no-mcp/rootfs_elf/README.md](tools/ida-no-mcp/rootfs_elf/README.md)
- M2b 命名恢复专题：[fwgraph/docs/m2b-notes.md](fwgraph/docs/m2b-notes.md)

## 许可

[Apache License 2.0](LICENSE)
