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
fwgraph 平台 (192.168.108.129:8000)  ← 攻击面识别 / 函数检索 / 反编译 / 覆盖率
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

## DeepSeek Harness 引擎（dsh/）

[dsh](https://github.com/deepseek-ai/deepseek-harness) 作为可选 Agent 运行时二开整合：

- `dsh/plugin/` — 零依赖 cordis 插件 `@fwgraph/dsh-fwgraph-tools`，把平台只读工具（identification / surfaces / function source / attack_surface / search / call_trace / routes / traces / 受控 trace / record_finding / fw_browse_firmware）注册进 dsh 工具体系；另注册全局 tool guard 按名拦截 shell/文件写/web/子代理类工具
- `dsh/cordis.patch.yml` — `fwgraph` profile 补丁层：dsh-base + dsh-headless 组合之上插入工具插件与漏洞挖掘 persona；**整行禁用 dsh-base 的通用工具**（tool-bash / tool-fs / tool-fs-search / tool-str-replace-editor / tool-web / subagent 系列 / ralph / workflow / code-runtime），固件文件只读核对由监禁在 `data/extracted/<job_id>/` 的 `fw_browse_firmware` 承担
- `dsh/setup.sh` — 一键安装（克隆 dsh → pnpm install/build → 建 profile → 组合自检）
- LLM 走 dsh 的 llm-deepseek 适配器：`DEEPSEEK_BASE_URL` 指到任意 OpenAI 兼容网关（如 opencode go），`DEEPSEEK_API_KEY` 供 key

## 挖掘方法论（写进 system prompt）

0. `fw_get_identification` 取外部输入清单（IN-xxx，公网可达、零遗漏）→ `fw_list_surfaces` / `fw_get_surface` 按面推进
1. `fw_attack_surface` 取评分路径（verified 优先）+ `fw_get_manifest` 看 checksec 加固画像
2. 逐条路径用 `fw_get_function_source` 取 AI 增强伪代码，沿 source→sink 追攻击者可控数据流（栈溢出/命令注入/格式化字符串/路径穿越/整数溢出）
3. `fw_routes` 定位触发路由、`fw_trace_flow` 拿运行时证据、`fw_call_trace` 沿调用链确认入口与 sink
4. `fw_dangerous_callsites` / `fw_cypher` 扩大同类模式审查
5. 每个确认的漏洞 `record_finding`（证据必须具体到函数地址、伪代码行、路径评分、trace_id）

## 证据纪律（继承下游平台原则）

- 不把 socket accept / 连接成功 / 空差分 / 传输错误当漏洞
- 可达性分级如实填写：**verified**（整条链被同一次覆盖运行观测）> **observed** > **static-only**
- AI 只做分析与标注，对所有下游产物只读，不回写、不修改证据

## 配置（`.env`，不入库）

```ini
FWGRAPH_BASE_URL=http://192.168.108.129:8000
FWGRAPH_TOKEN=<ORCH_TOKEN>
FWGRAPH_JOB_ID=<默认固件任务>
LLM_BASE_URL=http://127.0.0.1:3456/v1
LLM_API_STYLE=anthropic
LLM_MODEL=deepseek-v4-flash
LLM_API_KEY=<key>
LLM_THINKING=0        # 网关输出上限 4096 tokens，开 thinking 会挤占正文额度
# FWGRAPH_EXTRACTED_ROOT=<固件解包根>   # 默认 ../fwgraph/data/extracted；fw_browse_firmware（dsh）监禁于 <root>/<job_id>/
```

切换分析目标：改 `FWGRAPH_JOB_ID`，或在工具参数里显式传 `job_id`。
