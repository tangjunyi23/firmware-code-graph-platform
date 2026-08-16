---
name: vuln-hunt-memory-driven
description: "Use when user asks to find/hunt specific vulnerability types in source code or binary targets. Requires target directory and vulnerability type. Produces FINAL.md with verified findings through a strict six-phase loop: memory bootstrap, attack-surface locking, vulnerability hunting, verification, challenge-agent review, and reporting."
---

# Vulnerability Hunt Skill (Memory-Driven)

Use model reasoning as the primary engine for all phases.

使用固定 Phase 工作流构建漏洞挖掘流程，顺序严格按照如下：

### Loop Flow Diagram (Mandatory Sequence)
```
┌───────────────────────────────────────────────────────────┐
│ Round N (fixed order, no skipping/merging/replacing)       │
├───────────────────────────────────────────────────────────┤
│ 1) Attack Surface Locking    → load: references/phase1_attack_surface.md
│ 2) Vulnerability Hunting     → load: references/phase2_hunting.md
│ 3) Verification              → load: references/phase3_verification.md
│ 4) Challenge Agent           → load: references/phase4_challenge.md
└───────────────────────────────────────────────────────────┘
                      │
                      ▼
            Challenge Verdict: PASS or LOOP
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
       PASS                   LOOP
          │                       │
          ▼                       │
     Reporting                    └─> Start Round N+1
     (load: references/phase5_reporting.md)
```

不再依赖外部计划模板，也不再要求额外的计划/进度中间文件。
分析过程以 `attack-surface.md`、`vuln_hunt_output.md`、`call_graphs.md`、`challenge_verdict.md`、`context_snapshot.json` 为主。

## Agent Spawning Protocol（Task 工具派发 — MANDATORY）

主 codex 会话是**编排器（Orchestrator）**，必须用 Task 工具派发子代理，不得由自身内联执行 Phase 1/2/3/4。

### 模型指定（MANDATORY）

派发每个 Task worker 时，**必须**在工具调用参数中指定：
```
model: "gpt-5.4"   （或 "gpt-5.3-codex"，禁止使用 gpt-5.1 或更旧版本）
```

### 编排器职责分工

| Phase | 执行者 | 模型 | 说明 |
|-------|--------|------|------|
| Phase 0/0.5 | 编排器本身 | — | 记忆加载 + snapshot 恢复 |
| Phase 1 | **Task Worker × 1** | gpt-5.4 | 攻击面枚举（独立上下文，避免文件读取污染后续分析） |
| Phase 2 | **Task Worker × N（并行）** | gpt-5.4 | 每个 P0 surface 派发一个 worker |
| Phase 3 | **Task Worker × M（并行）** | gpt-5.4 | 每个候选漏洞派发一个 worker |
| Phase 4 | **Task Worker × 1（独立）** | gpt-5.4 | Challenge agent，严禁内联执行 |
| 合并/汇总 | 编排器本身 | — | 等待所有 worker 完成后聚合 |

### 长耗时等待策略（MANDATORY）

编排器必须对长任务保持耐心等待，禁止因短超时误判 worker 失败：

1. `wait_agent` 默认超时建议 **10-30 分钟**（按任务体量选择），避免 30s 级别高频轮询。
2. 单次 `wait_agent` 超时**不等于失败**；若超时，编排器应继续等待或先处理其他并行任务，不得立刻关闭 worker。
3. 仅当出现明确异常（worker 报错、任务方向错误、用户要求中止）时，才允许 `close_agent`。
4. Phase 1/2/3/4 的 worker 都可能因大目录或反编译分析显著耗时，编排器必须优先保证完整性而非追求短时返回。

### 子代理进度日志规范（MANDATORY）

所有 worker 必须输出各自日志文件，便于编排器观察进度：

- Phase 1: `phase1_worker.log`
- Phase 2: `phase2_surface_<surface_id>.log`
- Phase 3: `phase3_verify_<candidate_id>.log`
- Phase 4: `phase4_challenge.log`

日志要求：

1. 采用追加写入（append），每条日志包含时间戳和当前步骤。
2. 至少记录：开始、关键里程碑、完成/失败原因。
3. 若任务超过 2 分钟，至少每 60-120 秒写入一次进度心跳。
4. 编排器在等待期间可读取这些日志判断是否仍在推进。

### Task 消息通用格式

派发每个 worker 时，消息开头必须包含：

```
你是其中一个并行分析 worker。你不孤单，代码库里可能有其他 agent 在并行工作，不要回退他人的改动。你的职责仅限于[具体任务]。只写你独立负责的输出文件，避免冲突。完成后以 JSON 格式汇报你写入的文件名和主要发现摘要。
```

并在消息中追加日志要求：

```
请同时写入你的进度日志文件（见日志规范），至少包含开始、里程碑、完成三类记录；若任务较长，定期追加心跳日志。
```

详细 Task 消息模板见 `references/agent_templates.md`。

### Phase 1 Worker 派发规则（MANDATORY）

```
输入：漏洞类型 + 目标目录 + 当前 round（若 Round 2+ 还有 snapshot 摘要）
做法：派发单个 Task worker，独立执行完整 Phase 1 攻击面分析
模板：Phase 1 Attack Surface Agent Template（见 agent_templates.md）
输出：worker 写入 attack-surface.md（含覆盖率摘要），更新 context_snapshot.json（attack_surface 字段）
日志：worker 必须写 `phase1_worker.log`
等待：必须等 Phase 1 worker 完成后再派发 Phase 2 worker；等待时优先用长超时并结合日志观察进度
```

### Phase 2 Worker 派发规则（P0 ≥ 1 时 MANDATORY）

```
输入：attack-surface.md 中的 P0 surface 列表
做法：每个 P0 surface 独立派发一个 Task worker（并行启动）
模板：Parallel Surface Analysis Template（见 agent_templates.md）
输出：每个 worker 写入 phase2_surface_<surface_id>.json
日志：每个 worker 写入 phase2_surface_<surface_id>.log
合并：所有 worker 完成后，编排器读取所有 phase2_surface_*.json 执行 §2.4 排序
```

### Phase 4 Challenge Worker 派发规则（MANDATORY）

```
严禁编排器内联执行 Phase 4 — 内联执行会继承 Phase 1-3 的分析偏见，破坏对抗性独立性
做法：派发单个 Task worker，使用 Adversarial Challenge Agent Template
输入：attack-surface.md + vuln_hunt_output.md（禁止传入 Phase 2 中间推理过程）
输出：worker 写入 challenge_verdict.md（最后一行必须为 overall_verdict: PASS/LOOP）
日志：worker 必须写 `phase4_challenge.log`
```

## Reference File Loading Protocol

每个 Phase 开始时，读取对应的 reference 文件：

| Phase | Reference File | 何时加载 |
|-------|---------------|---------|
| Phase 0 | `references/phase0_memory.md` | 每轮开始 |
| Phase 1 | `references/phase1_attack_surface.md` | 每轮 |
| Phase 1B | `references/phase1_binary_analysis.md` | Phase 1 中检测到二进制目标或 `decompile/` 目录时 |
| Phase 1C | `references/phase1_auth_analysis.md` | Phase 1 中漏洞类型为预认证类（预认证漏洞/认证前漏洞/preauth/pre-auth/认证前RCE/认证绕过）时**无条件加载**，不限目标类型（Web/二进制/固件均适用） |
| Phase 2 | `references/phase2_hunting.md` + `references/strategies/<type>.md` | 每轮 |
| Phase 3 | `references/phase3_verification.md` | 每轮 |
| Phase 4 | `references/phase4_challenge.md` | 每轮 |
| Phase 5 | `references/phase5_reporting.md` | 仅 PASS 后 |
| Schema | `references/snapshot_schema.md` | Phase 4 生成 snapshot 时 |
| Agents | `references/agent_templates.md` | Phase 3/4 派发子代理时 |
| Rev-Symbol | `references/rev-symbol.md` | Phase 1B 反编译后符号恢复 |
| Rev-Struct | `references/rev-struct.md` | Phase 1B 反编译后结构体重建 |

### 默认扫描策略（重要）

**当用户未明确指定漏洞类型时，一律使用 `预认证漏洞`（广谱模式）。** 无论目标类型（Web 源码、固件二进制、IoT 设备、桌面应用等），默认目标始终是：在预认证攻击面内搜索一切可利用的漏洞类型，尽可能串联成 Pre-auth RCE 攻击链。仅当用户明确指定特定漏洞类型（如"只看 SQL 注入"）时，才缩窄到对应的单一策略文件。

### 漏洞类型策略文件映射

Phase 2 开始时，根据用户指定的漏洞类型加载对应的策略文件（未指定时默认加载 `preauth_rce.md` 广谱模式）：

| 漏洞类型 | 策略文件 |
|----------|---------|
| SQL注入 | `references/strategies/sqli.md` |
| 缓冲区溢出 | `references/strategies/bof.md` |
| 整数溢出/整型溢出 | `references/strategies/intov.md` |
| 认证绕过 | `references/strategies/authbypass.md` |
| 命令注入 | `references/strategies/cmdi.md` |
| 格式化字符串 | `references/strategies/fmtstr.md` |
| 认证前RCE | `references/strategies/preauth_rce.md` |
| **预认证漏洞/认证前漏洞/preauth/pre-auth** | `references/strategies/preauth_rce.md` （广谱模式，覆盖所有预认证可利用漏洞，含 SQLi/信息泄露/文件读取/认证绕过/RCE 等） |
| 路径穿越 | `references/strategies/pathtrv.md` |
| 文件读取/任意文件读取 | `references/strategies/fileread.md` |
| 文件写入/任意文件写入 | `references/strategies/filewrite.md` |
| 文件上传 | `references/strategies/upload.md` |
| 反序列化 | `references/strategies/deser.md` |
| 内存溢出 | `references/strategies/memov.md` |
| LDAP注入/NoSQL注入/SSTI/EL注入/通用注入 | `references/strategies/injection.md` |
| 拒绝服务/DoS | `references/strategies/dos.md` |
| 会话管理 | `references/strategies/session.md` |
| 密码学/TLS/证书验证 | `references/strategies/crypto.md` |
| 业务逻辑滥用/邮件滥用 | `references/strategies/abuse.md` |

## 记忆标签映射表

根据用户指定的漏洞类型，确定主标签和附加标签。匹配规则：ID 中包含主标签或附加标签的 `vuln_pattern` / `episode` 条目均被选中。

| 漏洞类型 | 主标签 | 附加标签 |
|----------|--------|---------|
| SQL注入 | SQLI | — |
| 缓冲区溢出 | BOF | INTOV, MEMOV |
| 整数溢出 | INTOV | BOF, MEMOV |
| 认证绕过 | AUTHBYPASS | SQLI |
| 命令注入 | CMDI | — |
| 格式化字符串 | FMTSTR | BOF, MEMOV |
| 认证前RCE | PREAUTH, RCE, AUTHBYPASS | BOF, FMTSTR, CMDI, MEMOV, INTOV, PATHTRV, FILEWRITE, FILEREAD, ARCH, SQLI, DESER, INJECT |
| 预认证漏洞/认证前漏洞/preauth | PREAUTH, RCE, AUTHBYPASS | BOF, FMTSTR, CMDI, MEMOV, INTOV, PATHTRV, FILEWRITE, FILEREAD, ARCH, SQLI, DESER, INJECT |
| 路径穿越 | PATHTRV | FILEREAD, FILEWRITE |
| 文件读取 | FILEREAD | PATHTRV |
| 文件写入 | FILEWRITE | PATHTRV, UPLOAD |
| 文件上传 | UPLOAD | PATHTRV, FILEWRITE |
| 反序列化 | DESER | — |
| 内存溢出 | MEMOV | BOF, INTOV |
| LDAP注入/通用注入 | LDAPI | SQLI, NOSQLI, SSTI, INJECT |
| NoSQL注入 | NOSQLI | LDAPI, INJECT |
| SSTI | SSTI | INJECT |
| EL注入 | INJECT | SSTI, NOSQLI |
| 拒绝服务/DoS | DOS | INTOV, DIVZERO, ABUSE |
| 会话管理 | SESSION | AUTHBYPASS |
| 密码学/TLS | CRYPTO | TLS, BOF, INTOV |
| 业务逻辑滥用 | ABUSE | DOS |
| 2FA/MFA | SESSION, 2FA | AUTHBYPASS |

**始终加载**：所有 `meta_rule` 和 `failure_pattern` 类型条目。

## 记忆类型说明

| 类型 | 加载规则 | 用户可自定义 | 说明 |
|------|---------|------------|------|
| `vulnerability_pattern` | 按标签匹配加载 | ✅ | 漏洞类型的 source→sink 检查模板 |
| `meta_rule` | 始终加载 | ✅ | 全局策略规则（如效果型 vs 类型型目标区分） |
| `failure_pattern` | 始终加载 | ✅ | 过去分析失败的教训和反模式 |
| `episode` / `episode_memory` | 按标签匹配加载 | ✅ | 具体漏洞案例的经验总结 |
| `strategy_extension` | Phase 2 加载策略时自动追加 | ✅ | 对现有策略文件的补充 Sources/Sinks/Key Check |
| `tech_stack_hint` | Phase 1 依赖分析时匹配加载 | ✅ | 特定技术栈/框架的审计提示（如 "Rust 项目注意 unsafe 块"） |

### 自定义记忆接口

用户可通过直接编辑 `~/.codex/memory/insights.jsonl` 文件添加自定义记忆条目。每条记忆必须包含以下字段：

```json
{
  "id": "MEM-<TYPE>-<UNIQUE_ID>",
  "type": "<上表中的类型>",
  "content": "记忆内容（自然语言描述）",
  "source": "user-defined",
  "timestamp": "YYYY-MM-DD",
  "confidence": 0.5
}
```

**ID 命名约定**：
- `MEM-PATTERN-<TAG>-<序号>` — 漏洞模式
- `MEM-META-<名称>` — 元规则
- `MEM-FAILURE-<名称>` — 失败反模式
- `MEM-EP-<TAG>-<日期>-<描述>` — 历史经验
- `MEM-STRATEGY-<TAG>-<描述>` — 策略扩展
- `MEM-TECH-<STACK>-<描述>` — 技术栈提示

**标签匹配规则**：记忆 ID 中包含的标签关键词（如 BOF、SQLI、AUTHBYPASS）用于与漏洞类型标签映射表匹配。自定义记忆应确保 ID 中包含正确的标签以被正确加载。

## Loop Rules

1. Each round executes phases in fixed order: Attack Surface → Hunting → Verification → Challenge Agent.
2. Challenge Agent is **mandatory every round** and must be dispatched as independent sub-agent.
3. If verdict is `LOOP`, start Round N+1 and update next actions in `context_snapshot.json`.
4. If verdict is `PASS`, proceed to Reporting (Phase 5).
5. LOOP 后不得以任何理由终止审计流程。
6. 每轮 Phase 4 结束时必须生成 `context_snapshot.json`（参见 `references/snapshot_schema.md`）。

## Conflict Handling Rule

When retrieved memory conflicts:
1. Resolve by: latest explicit user instruction > higher enforcement priority > recency.
2. Record skipped IDs in `unapplied_memory_explanation`.
3. Continue with resolved `must_apply` set.

## Interruption Rule

When user changes constraints mid-task:
1. Persist only if the update is explicit attack-surface direction, vulnerability pattern, or validation strategy.
2. Refresh active snapshot.
3. Continue from current phase with updated `must_apply` rules.
