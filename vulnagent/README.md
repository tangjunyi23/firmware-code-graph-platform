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
       │                 record_finding → findings/<id>.json + index.jsonl
       │                                  （schema 校验 + 同函数同类去重关联）
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
```

产物：

- `findings/F-*.json` — 结构化漏洞记录（title/severity/vuln_class/位置/summary/evidence/reachability/confidence/exploit_sketch/remediation）
- `findings/index.jsonl` — 全部 findings 索引
- `sessions/<id>/report.md` — 该 session 的 Markdown 漏洞报告
- `sessions/<id>/events.sse` — 完整执行链路（Debug 面板等价物）

## 挖掘方法论（写进 system prompt）

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
```

切换分析目标：改 `FWGRAPH_JOB_ID`，或在工具参数里显式传 `job_id`。
