# Agent Dispatch Templates(ZCode Agent 工具版)

派发方式:Agent 工具,`subagent_type: general-purpose`(纯只读侦察可用 `Explore`)。
子代理**看不到本会话上下文**,以下模板中的 `<>` 占位符必须由编排器全部填实后再派发。
派发上限与合并规则见 SKILL.md「子代理派发协议」:并发 ≤ 4,每轮总额 ≤ 12(Phase 1=1、Phase 2≤6、Phase 3≤4、Phase 4=1 预留)。

## Worker Header(所有子代理 prompt 必须以此开头)

```text
你是其中一个并行分析 worker。你不孤单,代码库里可能有其他 agent 在并行工作,不要回退他人的改动。你的职责仅限于[具体任务描述]。只写你独立负责的输出文件,避免冲突。你必须同时写入自己的进度日志文件(append 模式,带时间戳),至少记录开始、里程碑、完成;长任务需定期心跳。完成后在你的最终回复中以 JSON 格式汇报:{ "files_written": [...], "logs_written": [...], "summary": "..." }
```

---

## Phase 1: Attack Surface Agent Template

```text
你是攻击面分析 worker。你的职责仅限于执行 Phase 1 攻击面枚举,只写你独立负责的输出文件,不要修改其他文件。你必须写入 `phase1_worker.log` 记录进度。完成后在最终回复中以 JSON 汇报:{ "files_written": [...], "logs_written": ["phase1_worker.log"], "summary": "..." }

## 任务参数:
- Vulnerability type: <用户指定漏洞类型>
- Target directory: <目标目录路径>
- Current round: <轮次号>
- Snapshot summary (Round 2+ 时填写): <上一轮 context_snapshot.json 摘要,首轮留空>

## 分析要求(按序执行):

### §1.1 依赖 & 框架分析
读取 package.json / requirements.txt / go.mod / pom.xml / Makefile 等,识别关键框架和依赖。

### §1.2 入口点枚举
枚举所有网络入口:HTTP 路由、RPC handler、消息队列 consumer、WebSocket handler 等。
对每个入口记录:路由路径、处理函数、认证要求(是否预认证可达)。

### §1.3 权限架构分析
识别认证中间件/函数,构建权限架构表:
| 入口/命令ID | 处理函数 | 权限策略 | 是否预认证 | 可达危险操作 |

### §1.4 P0 攻击面识别
基于漏洞类型 + 预认证可达性,筛选 P0(高优先级)攻击面。
每个 P0 攻击面记录:Surface ID、Entry layer、Security decision layer、Sink layer。

### §1.5 调用图构建(可选)
若存在复杂调用关系,生成 call_graphs.md 辅助后续分析。

## 输出文件:
1. `attack-surface.md`(必须):包含完整攻击面列表、权限架构表、P0 surface 列表和覆盖率摘要
2. `call_graphs.md`(可选):调用图
3. 更新 `context_snapshot.json` 的 `attack_surface` 字段(若文件已存在则合并更新)
4. `phase1_worker.log`(必须):记录开始、里程碑、完成状态(append + 时间戳)

## attack-surface.md 输出结构:
```markdown
# Attack Surface Analysis - Round <N>

## 依赖 & 框架
- <框架名>: <版本> — <安全相关注意事项>

## 权限架构表
| 入口/命令ID | 处理函数 | 权限策略 | 是否预认证 | 可达危险操作 |
|------------|---------|---------|----------|------------|

## P0 攻击面列表
### Surface-01: <名称>
- Entry layer: <入口>
- Security decision layer: <认证检查函数>
- Sink layer: <危险操作>
- 预认证可达: YES/NO — <理由>

## 覆盖率摘要
- 总入口数: N
- 已分析: N
- P0 surface 数: N
- 覆盖率: N%
```

完成后汇报:{ "files_written": ["attack-surface.md"], "logs_written": ["phase1_worker.log"], "summary": "P0 surfaces: <数量>, 覆盖率: <百分比>" }
```

---

## Phase 2: Single Surface Analysis Template

```text
你是其中一个并行漏洞分析 worker。你不孤单,代码库里可能有其他 worker 在并行分析其他攻击面,不要回退他人的改动。你的职责仅限于分析你被分配的 P0 攻击面,只写你独立负责的输出文件。你必须写入 `phase2_surface_<surface_id>.log` 记录进度。

## 你的分配攻击面:
- Surface ID: <攻击面编号>
- Target function(s): <目标函数列表>
- Target file(s): <目标文件列表>
- Entry layer: <数据入口描述>
- Security decision layer: <安全决策函数(如有)>
- Sink layer: <危险操作函数>

## Context:
- Vulnerability type: <用户指定漏洞类型>
- Permission architecture (relevant entries): <该攻击面相关的权限策略>
- must_apply memory: <适用的记忆规则>
- Target directory: <目标目录路径>

## Analysis requirements:
1. **漏洞原语识别**:先识别该攻击面中是否存在漏洞原语
2. **全路径枚举**:列出所有从 entry 到 sink 的可能路径
3. **等深度分析**:对每条路径执行完整推理
4. **跨攻击面线索**:如果分析中发现涉及其他攻击面的调用链,记录但不深入

## 输出文件:
- phase2_surface_<surface_id>.json
- phase2_surface_<surface_id>.log(必须,append + 时间戳)
只写这两个文件,不要修改其他文件。

输出格式:
{
  "surface_id": "<攻击面编号>",
  "primitives_found": ["<识别到的漏洞原语>"],
  "paths_analyzed": [
    {
      "path": "source → ... → sink",
      "primitive": "<该路径利用的漏洞原语>",
      "guards": "<中间防护及可绕过性>",
      "candidate_vuln": "<候选漏洞描述(如有)>",
      "confidence": 0.0
    }
  ],
  "cross_surface_refs": ["<涉及其他攻击面的线索>"],
  "coverage": "complete|partial — <未覆盖部分说明>"
}

完成后汇报:{ "files_written": ["phase2_surface_<surface_id>.json"], "logs_written": ["phase2_surface_<surface_id>.log"], "summary": "<主要发现一句话摘要>" }
```

---

## Phase 2: Multi-Surface Batch Template(派发额度不足时的合并模板)

当 P0 surface 数超过 Phase 2 剩余额度时,编排器按优先级(预认证可达 > 高危 sink > 其他)
及同文件/同模块就近原则,把 2–3 个 surface 打包给一个 worker,用本模板:

```text
你是其中一个并行漏洞分析 worker。你被分配了一组(2–3 个)相邻攻击面,不要回退他人的改动。你的职责仅限于分析下列被分配的 P0 攻击面,只写你独立负责的输出文件。你必须写入 `phase2_batch_<batch_id>.log` 记录进度。

## 你的分配攻击面组(Batch ID: <batch_id>):
### Surface A: <Surface ID + 目标函数/文件 + entry/security/sink 三层>
### Surface B: <同上>
### Surface C: <可选>

## Context:
- Vulnerability type: <用户指定漏洞类型>
- Permission architecture (relevant entries): <相关权限策略>
- must_apply memory: <适用的记忆规则>
- Target directory: <目标目录路径>

## Analysis requirements:
1. 对组内**每个** surface 独立执行:漏洞原语识别 → 全路径枚举 → 等深度分析
2. 同一 worker 内先做组内 surface,再记录跨组线索(记录不深入)
3. **禁止**因批量而降低单个 surface 的分析深度

## 输出文件(每个 surface 一份):
- phase2_surface_<surface_id>.json × N(格式与单 surface 模板完全一致)
- phase2_batch_<batch_id>.log(必须,append + 时间戳,按 surface 分节记录)

完成后汇报:{ "files_written": ["phase2_surface_<id1>.json", "phase2_surface_<id2>.json"], "logs_written": ["phase2_batch_<batch_id>.log"], "summary": "<每个 surface 一句话结论>" }
```

---

## Phase 4: Adversarial Challenge Agent Template

```text
你是独立对抗性审查 worker(Challenge Agent)。你不孤单,编排器在等你的结论。
你必须独立工作:你没有参与此前任何 Phase 的分析过程,只能读取提供给你的材料和目标代码文件。
你的职责:对以下候选漏洞发现做对抗性验证,写入 challenge_verdict.md,并写入 `phase4_challenge.log` 记录进度。

## 输入材料(只读这些,不要读 Phase 2 的中间产物):
- attack-surface.md:攻击面列表(读取目标目录下的该文件)
- vuln_hunt_output.md:候选漏洞报告(读取目标目录下的该文件)
- call_graphs.md:调用图(读取目标目录下的该文件,若存在)

## 目标目录:<目标目录路径>
(你可以用 Read/Grep/Glob 读取目标代码,但禁止读取 phase2_surface_*.json 等中间产物)

## Core checks(见 phase4_challenge.md 完整列表):

1. 反向可达性验证
2. 权限策略交叉验证
3. 漏洞原语独立验证
4. 认证管线独立验证(Pre-auth 类)
5. 替代假设检验
6. 攻击面覆盖率审计
7. 组合链完整性审计(Pre-auth RCE 类)

## 输出文件:
- challenge_verdict.md(追加写入,不要覆盖)
- phase4_challenge.log(必须,append + 时间戳)

输出结构:
{
  "reverse_reachability": "PASS|FAILED — <detail>",
  "permission_verification": "CONFIRMED|MISMATCH — <detail>",
  "primitive_verification": "CONFIRMED|NOT_FOUND|DIFFERENT_PRIMITIVE — <detail>",
  "auth_pipeline_verification": "PASS|FAILED|NOT_APPLICABLE — <detail>",
  "combo_chain_audit": "COMPLETE|INCOMPLETE|NOT_APPLICABLE — <detail>",
  "exploitability": "CONFIRMED|EXPLOITABILITY_CONDITIONAL|SOURCE_UNCONTROLLABLE — <detail>",
  "loop_reason": "<if LOOP>",
  "overall_verdict": "PASS|LOOP"
}

最后一行必须是:
overall_verdict: PASS
或
overall_verdict: LOOP

完成后汇报:{ "files_written": ["challenge_verdict.md"], "logs_written": ["phase4_challenge.log"], "summary": "overall_verdict: PASS|LOOP — <一句话理由>" }
```

---

## Phase 3: Verification Sub-agent Template

```text
你是其中一个并行验证 worker。你不孤单,代码库里可能有其他 worker 在并行验证其他候选,不要回退他人的改动。你的职责仅限于验证你被分配的候选漏洞,只写你独立负责的输出文件。你必须写入 `phase3_verify_<candidate_id>.log` 记录进度。完成后在最终回复中以 JSON 汇报。

You are assigned candidate verification for a <漏洞类型> vulnerability.

candidate:
- id: <candidate_id>
- title: <title>
- vuln_type: <用户指定的漏洞类型>
- evidence_hint: <evidence>
- vuln_function: <候选漏洞函数名>

Verification requirements:
1. Confirm the source→sink path is valid and reachable.
2. Confirm the vulnerability type matches: <漏洞类型>.
3. Provide code line references as evidence.
4. Assess bypass feasibility for any intermediate guards.
5. Identify the exact vulnerable function name.
6. Check ALL call paths reaching the sink — each path must be evaluated independently.
7. Do NOT downgrade a candidate solely because "context is insufficient".

Output JSON:
{
  "candidate_id": "...",
  "vuln_type": "...",
  "vuln_function": "...",
  "verification_steps": ["..."],
  "evidence": ["... (with code line references)"],
  "source_sink_path": "source → ... → sink",
  "guards_analysis": "...",
  "poc": "...",
  "impact": "low|medium|high|critical",
  "confidence": 0.0,
  "logs_written": ["phase3_verify_<candidate_id>.log"]
}
```

---

## Phase 3: Multi-Candidate Batch Template(派发额度不足时的合并模板)

候选数超过 Phase 3 剩余额度时,按 confidence 降序 + 同文件/同模块就近分组,一个 worker 验证一组:

```text
你是其中一个并行验证 worker。你被分配了一组(2–4 个)候选漏洞,不要回退他人的改动。
只写你独立负责的输出文件,写入 `phase3_batch_<batch_id>.log` 记录进度(按候选分节)。

## 你的分配候选组(Batch ID: <batch_id>):
- candidate 1: id/title/vuln_type/evidence_hint/vuln_function
- candidate 2: <同上>
- candidate 3: <可选>

Verification requirements(对组内每个候选独立执行,格式与单候选模板一致):
1–7 同单候选模板;**禁止**因批量而跳过任何候选的完整验证链。

输出文件:每候选一个 `phase3_verify_<candidate_id>.json` + 共享 `phase3_batch_<batch_id>.log`。
完成后汇报:{ "files_written": [...], "logs_written": ["phase3_batch_<batch_id>.log"], "summary": "<每候选一句话结论>" }
```

---

## Memory-Enhanced Template (Optional, for large memory stores >=20 entries)

When the memory ledger contains 20+ entries, use this extended template:

```text
You are assigned candidate verification with memory compliance.

memory_snapshot_id: <snapshot_id>
must_apply:
- <MEM-ID-1>: <rule>
- <MEM-ID-2>: <rule>
contextual_memory:
- <MEM-ID-3>: <episode/evidence hint>

candidate:
- id: <candidate_id>
- title: <title>
- vuln_type: <用户指定的漏洞类型>
- evidence_hint: <evidence>

If memory conflicts, resolve by:
1) latest explicit user instruction
2) higher enforcement priority
3) recency

Output JSON:
{
  "memory_snapshot_id": "...",
  "candidate_id": "...",
  "vuln_type": "...",
  "vuln_function": "...",
  "retrieved_memory_ids": ["..."],
  "applied_memory_ids": ["..."],
  "unapplied_memory_explanation": [{"id":"...","reason":"..."}],
  "verification_steps": ["..."],
  "evidence": ["..."],
  "source_sink_path": "...",
  "poc": "...",
  "impact": "low|medium|high|critical",
  "confidence": 0.0
}
```

---

## Supervisor Merge Checklist(编排器合并检查)

- Verify that `vuln_type` matches user-specified vulnerability type.
- Verify that `vuln_function` is a specific function name (not "multiple functions" or file-level).
- Reject report if evidence lacks code line references.
- When using memory-enhanced template: reject if `memory_snapshot_id` mismatch or must-apply memory missing without reason.
- Merge only evidence-backed findings into verified report.
- **Coverage check**: Verify that all P0 attack surfaces have corresponding verification results
  (批量 worker 的输出也要逐 surface 核对,防止合并模板下漏验某个 surface)。
- **Multi-path check**: For each sink, verify that ALL call paths have been analyzed.
- **Budget check**: 每次派发/回收后更新 `context_snapshot.json` 的 `subagent_budget`。
