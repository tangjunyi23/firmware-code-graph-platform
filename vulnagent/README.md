# vulnagent — 上游漏洞挖掘 Agent

基于 **Managed Agents** 抽象实现的固件漏洞挖掘智能体。它是 fwgraph 固件代码图谱平台的**上游消费者**：下游平台负责攻击面识别与函数检索/反编译，本 agent 专心做漏洞挖掘与确认。

## Managed Agents 抽象映射

| 抽象 | 本项目实现 | 说明 |
|---|---|---|
| **Agent**（配置清单） | `agent.json` | model + system prompt + tools + skills，创建一次，所有 session 复用 |
| **Environment**（运行环境） | `environment.json` + `.env` | Node≥20 运行时（内置 fetch，零 npm 依赖）、出站白名单（fwgraph:8000、LLM 网关:3456）、`sessions/`、`findings/` 可写挂载 |
| **Session**（会话实例） | `sessions/<id>/` | Agent + Environment 的一次具体执行。有状态：`state.json` + `messages.json` 每步落盘，可 `resume` 断点续跑，支持长时间运行 |
| **Events**（事件流） | `sessions/<id>/events.sse` | text/event-stream 格式，事件类型对齐 Console Debug 面板：`thinking` / `tool_call` / `tool_result` / `model_usage` / `text` / `session_idle` / `session_end` |

## 架构

```
agent.json (Agent 清单: model + system_prompt + tools + skills)
environment.json (Environment: 网络白名单 + 挂载) + .env (凭据)
       │
       ▼
src/cli.js ──► Session（src/session.js：agent loop，逐步持久化）
       │            │
       │            ├─ LLM（src/llm.js：Anthropic Messages，原生 tool_use，重试+记账）
       │            ├─ Events（src/events.js：SSE 事件流 → events.sse + 终端渲染）
       │            └─ Tools（src/tools.js）：
       │                 fw_*           → fwgraph 平台 API（/graph/query 各 op、
       │                                    函数源码含 asm 通道、manifest、traces；
       │                                    fw_request_trace 为受控写，每 session 限量）
       │                 record_finding → POST /vulnagent/findings（服务端
       │                                  权威校验+落盘，id 由服务端生成；
       │                                  findings/ 仅保留本地缓存副本）
       │                 finish         → 结束 session，生成 report.md
       ▼
fwgraph 平台 (https://192.168.141.135:8000)  ← 攻击面识别 / 函数检索 / 反编译 / 覆盖率 / fuzz
```

## 用法

```bash
cd vulnagent

# 查看 Agent / Environment 清单
node src/cli.js info

# 启动一次挖掘 session（事件流实时打印，同时写 events.sse）
node src/cli.js run "对默认固件任务做漏洞挖掘：先看 verified 攻击路径，逐条取伪代码深挖，确认真实漏洞并记录 findings" --max-turns 40

# 断点续跑（state/messages 每步落盘，中断后可直接恢复）
node src/cli.js resume <session_id>

# 查看历史 session / 回放事件流
node src/cli.js list
node src/cli.js events <session_id>

# 记忆驱动六阶段挖掘（整合 xiaomin_codex vuln-hunt-memory-driven skill：
# Phase1 攻击面锁定 → Phase2 分面深挖 → Phase3 验证（dropped 结论 PATCH
# retracted 落库）→ Phase4 对抗 challenge（末行精确判定 PASS/LOOP）
# → Phase5 产出 FINAL.md（PASS/LOOP 终局都产出；LOOP 显著标注且本轮
# findings 打「未经对抗验证通过」服务端 note）；记忆库按 verdict 回馈
# confidence ±0.05（clamp [0.1,0.95]），注入前按固件 tag 过滤
node src/cli.js hunt "预认证漏洞" --rounds 3 --max-turns 40 --mode dynamic

# DeepSeek Harness 引擎（可选；先执行一次 dsh/setup.sh 完成安装）
node src/cli.js run "对 verified 路径做漏洞挖掘" --engine dsh
```

产物：

- **服务端** `/vulnagent/findings`（F-xxx，status=draft/verified/disputed/retracted）— 权威存储；`findings/F-*.json` + `findings/index.jsonl` 仅是本地缓存副本
- `sessions/<id>/report.md` — 该 session 的 Markdown 漏洞报告
- `sessions/<id>/events.sse` — 完整执行链路（Debug 面板等价物）
- `sessions/hunt-*/` — 六阶段打法产物（attack-surface.md、phase2_round*.md、vuln_hunt_output.md、challenge_verdict_round*.md、context_snapshot.json、**FINAL.md**）

## 上下文预算

- **brief-first 分级检索**：批量筛查函数先 `brief`（约 1KB），疑点再拉全文；`attack_surface brief=true`、`cfg/ast max_nodes/max_depth` 同理——图谱预计算把 6.7 万函数收敛成可翻页的摘要，而不是全文吞吐
- **会话历史压缩**（builtin 引擎）：`session.js` 每轮调 LLM 前把超 `VULNAGENT_COMPACT_THRESHOLD`（默认 1200 字符）的旧 tool_result 换成首尾摘录占位（最近 6 条与任务不动，幂等，压缩动作进事件流）；dsh 引擎自带 compaction-basic + tool-result-pruner
- 实测（MX12 案例）：裸函数清单 28.7MB vs `attack_surface` top20 全量 12KB / brief 7.1KB

测试（零依赖、离线 mock fetch）：

```bash
npm test                       # node --test tests/（record_finding 契约/模式硬拒/playbook 判定/记忆写回/dsh 插件）
node dsh/verify_tools.mjs      # 实boot fwgraph profile 打印注册工具清单并断言 S1 锁定
```

## 六阶段打法（playbooks/vuln-hunt）

整合自 xiaomin_codex skill，已固化为 `src/playbook.js` 驱动器：

- **Phase 1 攻击面锁定**：先 `fw_get_identification` 拉全量外部输入（IN-xxx），再 `fw_list_surfaces` 取每个输入的 AS 文档（路由链/分发器/parser/normalizer/终点 handler/载体绑定/授权链引用），产出 P0/P1 优先级清单 —— 输入全覆盖，不遗漏
- **Phase 2 深挖**：按漏洞类型加载 `playbooks/vuln-hunt/references/strategies/<type>.md` 打法 + `memory/insights.jsonl` 标签匹配记忆（meta_rule / failure_pattern 始终加载）
- **Phase 3 验证**：独立 session 逐条复核 findings 证据（地址存在、载体可控、路径可达）
- **Phase 4 对抗 challenge**：独立 session（不带前文偏见）抽查质疑，末行输出 `overall_verdict: PASS/LOOP`；LOOP 自动进入下一轮（上限 --rounds）
- **Phase 5 出报告**：沿用 session report.md 标准格式

## 固件模拟 agent（dsh/，fwgraph-emul profile）

与漏洞挖掘平行的独立智能体（同一 dsh 引擎、不同组合），把真实固件服务进程
在模拟环境里拉起来，供挖掘 agent 动态确证：

- `dsh/plugin-emul/` — `@fwgraph/dsh-fwgraph-emul-tools`：fw_emul_build /
  boot / console / probe / patch / read / reset / stop / publish（编排器
  /emul/* 薄转发）；插件内封死约束——子代理并发 ≤3、每会话 ≤12 次、
  bash/write/edit 写盘前查会话工作区配额
- `dsh/cordis.patch-emul.yml` — fwgraph-emul(-web) profile：模拟工程师
  persona；放开 web 行（联网查 qemu/nvram 知识）；子代理 spawn provider
  （maxDepth=1）；pwsh/ralph/workflow/ptc-runtime 仍禁
- `dsh/skills/fwgraph-firmware-emul/` — 模拟方法论（真实性红线：环境只由
  真实固件进程构成，禁止自建页面冒充设备；就绪由编排器 publish 复探裁决）
- 编排侧 `fwgraph/orchestrator/app/emulagent_api.py`：/emulagent/sessions*
  （会话）+ /emul/envs*（环境生命周期，docker 常驻容器 + qemu-user 进程簇，
  rootfs tar 管道拷贝保留硬链接）+ /emul/requests（挖掘→模拟请求总线）
- 挖掘 agent（fwgraph profile）新增三个消费工具：fw_emul_request（结论
  成型后发起模拟，携带嫌疑清单/目标 binary/端口）、fw_emul_env（轮询环境
  与请求状态）、fw_emul_send（对 ready 环境发真实 TCP/UDP/HTTP 报文）
- 环境磁盘纪律：单会话 EMUL_SESSION_GB（默认 20）/全局 EMUL_GLOBAL_GB
  （默认 60）配额；环境独立于会话存活（idle-reap 不杀环境）

## DeepSeek Harness 引擎（dsh/）

[dsh](https://github.com/deepseek-ai/deepseek-harness) 作为可选 Agent 运行时二开整合：

- `dsh/plugin/` — 零依赖 cordis 插件 `@fwgraph/dsh-fwgraph-tools`，把平台只读工具（identification / surfaces / function source / attack_surface / search / call_trace / routes / traces / 受控 trace / record_finding / fw_browse_firmware）注册进 dsh 工具体系；另注册全局 tool guard 按名拦截 shell/文件写/web/子代理类工具
- `dsh/cordis.patch.yml` — `fwgraph` profile 补丁层：dsh-base + dsh-headless 组合之上插入工具插件与漏洞挖掘 persona；**整行禁用 dsh-base 的通用工具**（tool-bash / tool-fs / tool-fs-search / tool-str-replace-editor / tool-web / subagent 系列 / ralph / workflow / code-runtime），固件文件只读核对由监禁在 `data/extracted/<job_id>/` 的 `fw_browse_firmware` 承担
- `dsh/setup.sh` — 一键安装（克隆 dsh → pnpm install/build → 建 profile → 组合自检）
- LLM 走 dsh 的 llm-deepseek 适配器：`DEEPSEEK_BASE_URL` 指到任意 OpenAI 兼容网关（如 opencode go），`DEEPSEEK_API_KEY` 供 key

## 挖掘方法论（写进 system prompt）

0. `fw_get_identification` 取外部输入清单（IN-xxx，公网可达、零遗漏）→ `fw_list_surfaces` / `fw_get_surface` 按面推进
1. `fw_attack_surface` 取评分路径（verified 优先；大范围扫描用 `brief=true` 只取分诊字段）+ `fw_get_manifest` 看 checksec 加固画像
2. 逐条路径筛查：**先 `fw_get_function_source brief=true`**（约 1KB 分诊卡：攻击面元数据 + 伪代码头 + 危险调用行号 + callees），命中疑点再拉全文（Hex-Rays 原始伪代码是唯一可引用证据），沿 source→sink 追攻击者可控数据流（栈溢出/命令注入/格式化字符串/路径穿越/整数溢出）
3. `fw_routes` 定位触发路由、`fw_trace_flow` 拿运行时证据、`fw_call_trace` 沿调用链确认入口与 sink；`fw_get_cfg/fw_get_ast`（可加 `max_nodes/max_depth` 截断）做精确控制流/数据流推理
4. `fw_dangerous_callsites` / `fw_cypher` 扩大同类模式审查
5. 每个确认的漏洞 `record_finding`（证据必须具体到函数地址、伪代码行、路径评分、trace_id）

## 证据纪律（继承下游平台原则）

- 不把 socket accept / 连接成功 / 空差分 / 传输错误当漏洞
- 可达性分级如实填写：**verified**（整条链被同一次覆盖运行观测）> **observed** > **static-only**
- AI 只做分析与标注，对所有下游产物只读，不回写、不修改证据

## 配置（`.env`，不入库）

```ini
FWGRAPH_BASE_URL=https://127.0.0.1:8000   # 平台默认 HTTPS 自签
FWGRAPH_TOKEN=<ORCH_TOKEN 或 fws- 会话 token>
FWGRAPH_JOB_ID=<默认固件任务>
LLM_BASE_URL=https://opencode.ai/zen/go/v1
LLM_API_STYLE=anthropic
LLM_MODEL=deepseek-v4-flash
LLM_API_KEY=<key>
LLM_THINKING=0        # 推理模型 reasoning 会先烧输出额度
NODE_EXTRA_CA_CERTS=../fwgraph/data/tls/cert.pem   # Node fetch 信任自签证书
# FWGRAPH_EXTRACTED_ROOT=<固件解包根>   # 默认 ../fwgraph/data/extracted；fw_browse_firmware（dsh）监禁于 <root>/<job_id>/
# VULNAGENT_COMPACT_THRESHOLD=1200 / VULNAGENT_COMPACT_KEEP_RECENT=6  # 历史压缩可调
```

切换分析目标：改 `FWGRAPH_JOB_ID`，或在工具参数里显式传 `job_id`。
