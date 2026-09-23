# Phase Prompts (LLM-First)

## Phase 1 Prompt

```text
目标：锁定当前目录高危攻击面，按用户指定漏洞类型进行多层分析。
输入：用户要求 + 漏洞类型 + memory_snapshot_id + must_apply + contextual_memory。
执行：
0) 加载 references/phase1_attack_surface.md 获取完整攻击面分析规则。
1) 加载对应漏洞类型的策略文件（references/strategies/<type>.md）获取 Sources/Sinks 关键词。
2) 枚举所有文件（rg --files / file / strings）。
3) 按 phase1_attack_surface.md 中的分级表，将文件分为 P0/P1/P2 三级。
4) 对 P0 文件完整阅读，执行三层攻击面分析：
   a) 数据入口层：标记所有外部数据进入的入口点
   b) 安全决策层：标记所有做安全决策的函数，以及安全决策之前的路由/分发函数
   c) 危险操作层：标记所有 sink 函数
   P1 文件做函数签名扫描。
5) 跨文件调用链追踪：当函数调用跨文件时，记录参数传递关系。
6) 若发现二进制，使用 IDA decompile MCP 输出 C 再分析。
输出：按风险排序的攻击面列表，保存到 attack-surface.md。
```

## Phase 2 Prompt

```text
目标：针对 <漏洞类型> 挖掘候选漏洞，精确定位到漏洞根因函数。
约束：
- 严格遵循 must_apply 记忆规则中匹配的漏洞模式。
- 必须先加载 references/phase2_hunting.md 获取完整分析规则。
- 必须加载 references/strategies/<type>.md 获取该类型的 Sources/Sinks/Key Check/Common Patterns。
执行：
0) 加载漏洞类型策略文件。
1) **全路径枚举**：对每个 P0 攻击面，先列出所有可能的 source→sink 路径。
2) **等深度分析**：对每条路径执行完整推理，不可因路径"看起来不重要"而跳过。
3) 对每个候选漏洞，精确指出漏洞根因所在的函数名。
4) 产出候选漏洞（证据、触发条件、利用思路、影响、置信度）。
5) **覆盖率自检**：确认每个 P0 攻击面至少有一条 source→sink 路径被分析。
输出：候选漏洞列表 → vuln_hunt_output.md；函数调用图 → call_graphs.md。
```

## Phase 3 Prompt

```text
目标：验证候选漏洞真实性并输出可复现证据。
约束：
- 加载 references/phase3_verification.md 获取完整验证规则。
- 先低破坏验证，再高风险操作。
- 验证结果必须包含代码行引用。
- 当记忆条目 >= 20 时：返回 memory_snapshot_id、retrieved_memory_ids 和 applied_memory_ids。
- 当记忆条目 < 20 时：上述字段可选。
- 若记忆冲突，按"最新用户指令 > enforcement_priority > recency"处理。
输出字段：
- candidate_id
- verification_steps
- evidence（含代码行引用）
- poc
- impact
- confidence
- memory_snapshot_id（条件可选）
- applied_memory_ids（条件可选）
- unapplied_memory_explanation（如有冲突）
```
