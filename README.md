# firmware-code-graph-platform (fwgraph)

> Firmware attack-surface discovery with runtime-coverage evidence:
> EMBA extraction → headless IDA decompilation → CBM code graph →
> source/sink scoring → qemu-user differential coverage → function-level
> fuzz / frida hooking → ICS protocol fuzzing → an upstream
> vulnerability-mining agent.

以**运行时覆盖率为核心证据**的固件攻击面发现与排序平台。对解包后的固件
二进制，把静态分析（IDA 反编译、调用图、source/sink 规则、CFG/AST）与
动态证据（qemu-user 翻译块覆盖率、AFL++ 函数级 fuzz、frida hook、工控
协议模糊测试）结合，输出可验证的攻击面结论，并供上游漏洞挖掘 AI
（vulnagent）消费。

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
- **qemu-user 差分覆盖率（M7）**：单 ELF `chroot + qemu -d exec` 跑
  baseline/trigger 两遍，trigger-only 函数即请求处理路径；与静态路径
  交叉验证，输出 `observed`（函数被某次 trace 观测）与 `verified`
  （整条链被同一次运行覆盖）——**不做整机/整固件仿真**
- **函数级 fuzz / frida hook（动态分析）**：x86 目标用 **frida**（本机附加
  或远程真机/仿真 27042，hook 模块+导出/偏移，命中事件落盘）；ARM/MIPS 等
  用 **AFL++ qemu persistent 函数级 fuzz**（按架构构建的 afl-qemu-trace，
  只跑目标函数，要求函数在正常启动流程可达）
- **工控协议模糊测试（M-ICS）**：黑盒网络协议 fuzz——协议模板库
  （Modbus TCP / S7 / OPC UA / DNP3 / MQTT / HTTP）+ 确定性字段级变异
  （boundary/bitflip/fill/overflow/random，种子可复现）+ 纯软件监视器
  （TCP 探活/ICMP/协议探测）+ 故障确认与复播复现统计；授权确认闸门 +
  公网目标默认禁止；报告注册进报告中心（DOCX/PDF 导出）
- **vulnagent（M8）**：上游漏洞挖掘 agent（Managed Agents 抽象，Node ≥20
  零依赖；可选 DeepSeek Harness 引擎），工具消费平台 API（含受控
  trace/fuzz/frida 触发、identification/surfaces 攻击面产物）；**纯静态 /
  动静结合双模式**（静态模式收回全部动态工具）；六阶段记忆驱动 hunt
  （锁定→深挖→验证→对抗→报告）；结构化 findings（服务端权威校验 +
  置信度锚点 + 状态生命周期）+ 中文标准报告
- **上下文预算**：函数 brief 分诊卡（约 1KB：攻击面元数据+伪代码头+
  危险调用行号+callees）brief-first 分级检索；`attack_surface brief=true`
  掉链节点；builtin 会话历史自动压缩（旧工具结果换首尾摘录占位，
  幂等可重查）；dsh 引擎自带 compaction
- **Web 前端（M5）**：Vue 3 SPA，浅蓝专业亮色主题——仪表盘 / 任务中心
  （专业+简易双模式：简易模式上传即全自动出报告）/ 函数 /
  攻击面（路径抽屉 + 调用链时间线 + 伪代码/汇编双视图）/
  输入面（路由链时间线 + 授权链）/ 图谱（手写 Canvas 2D）/ 漏洞挖掘
  （流式思考链 + 工具卡状态机）/ 协议挖掘（真机连接 + 工控固件联动
  双入口）/ 报告中心（Markdown 预览 + DOCX/PDF 导出）/ 用户管理 /
  日志审计 / 系统设置
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
  ├─ POST /jobs/{id}/trace（qemu-user baseline/trigger 差分覆盖率）
  │        └─► 差分函数 ──► 交叉验证（observed/verified）
  ├─ POST /jobs/{id}/fuzz（ARM/MIPS：AFL++ qemu 函数级 fuzz）
  ├─ POST /jobs/{id}/frida（x86：frida hook，本机/远程）
  └─ POST /protofuzz（工控协议模糊测试：真机/仿真目标）

[vulnagent 上游漏洞挖掘 AI]（API + 受控动态工具 ──► findings + report.md）
        ▲                        纯静态模式收回动态工具；六阶段 hunt 可选
[Vue 3 SPA] 仪表盘 / 任务 / 分析视图 / 漏洞挖掘 / 协议挖掘 / 报告 / 系统管理
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
#    简易模式：上传固件即全自动完成分析并生成报告
#    专业模式：任务中心可逐阶段触发

# 5. 命令行分析一个固件（$T = 登录获取的 fws- 会话 token 或主 token）
curl -k -X POST -H "Authorization: Bearer $T" -F "file=@firmware.bin" $H/firmware?auto=1

# 6. 漏洞挖掘（vulnagent）
cd vulnagent && cp .env.example .env     # FWGRAPH_BASE_URL/TOKEN/JOB_ID、LLM_*
node src/cli.js run "对 verified 路径做漏洞挖掘" --max-turns 40
node src/cli.js hunt "预认证漏洞" --rounds 3 --mode dynamic   # 六阶段打法
# 或打开 SPA「漏洞挖掘」页签启动并实时查看事件流（纯静态/动静结合可选）
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
| `POST /jobs/{id}/trace`、`GET /jobs/{id}/traces[/{tid}]` | 差分覆盖率 |
| `POST·GET /jobs/{id}/fuzz[/{run_id}]` | AFL++ 函数级 fuzz（ARM/MIPS） |
| `POST·GET /jobs/{id}/frida[/{run_id}]` | frida hook（x86，本机/远程） |
| `GET /jobs/{id}/functions[/{md5}/{addr}/source]` | 函数清单与源码（`?asm=1` 汇编） |
| `GET /jobs/{id}/functions/{md5}/{addr}/brief` | 函数分诊卡（约 1KB：攻击面元数据+伪代码头+危险调用行号+callees） |
| `POST /graph/query` | 统一查询：search/cypher/trace/snippet/dangerous/trace_flow/attack_surface（含 brief）/routes/cfg/ast（含截断） |
| `GET /protofuzz/protocols`、`POST /protofuzz`、`GET /protofuzz[/{rid}]`、`POST .../stop`、`POST .../report` | 工控协议模糊测试 |
| `POST·GET /vulnagent/sessions[...]`、`GET·POST·PATCH /vulnagent/findings[/{fid}]` | 挖掘 session 与 findings（服务端权威校验） |
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
  orchestrator/tests/     pytest（438 项基线：437 通过 + 1 跳过）
  pipeline/               extract / decompile / graph / graphext /
                          attack / routes / inputs / surfaces / trace /
                          fuzz / frida / protofuzz / report
  config/                 attack_surface.yaml、naming_spec.yaml
  libc-sigs/              uClibc FLIRT 签名制作
  scripts/                运维与探测脚本
  webui/                  Vue 3 SPA（src → vite build → dist）
vulnagent/                上游漏洞挖掘 agent（agent.json / sessions / findings）
  playbooks/vuln-hunt/    六阶段打法与参考库
  dsh/                    DeepSeek Harness 引擎整合（插件 + profile + setup.sh）
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

## 验证状态（2026-08-17）

- 测试基线：orchestrator **438 项，437 通过** + 1 跳过；vulnagent **29 项**（node:test 零依赖）
- 案例固件一：小米 R3 `miwifi_r3_all_55ac7_2.11.20.bin`（mips32le，274 ELF）
  - 定向反编译 sysapihttpd：1847 函数、1490 成功（80.7%），零加固
  - 攻击面：42 source / 188 sink / 50 路径，3 条 verified
  - CVE-2019-18371（sysapihttpd alias 目录穿越）用 M7 设施动态复现成功
  - vulnagent 产出 CWE-121 栈溢出 finding（已附勘误与待确认问题）
- 案例固件二：`US_MX12V2.tar`（arm32，169 二进制）
  - 外部输入 39 条（证据四级分级）、攻击面 39 个、授权链 24 条、
    GoAhead 真实路由恢复 8 条
  - CFG 67045 个（假 ret 率 0.38%）、AST 55474 个（ERROR 率 0.09%）
  - 协议 fuzz 冒烟：假 Modbus 设备 25 用例全响应、故障注入正确分级

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
