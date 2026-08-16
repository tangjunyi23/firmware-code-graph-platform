# CC Final Report Prompt Template
#
# 占位符说明：
#   {{TARGET_DIR}}    — 目标目录绝对路径
#   {{VULN_TYPE}}     — 漏洞类型
#   {{SCAN_RESULT}}   — PASS 或 LOOP
#   {{TOTAL_ROUNDS}}  — 总轮次
#   {{ATTACK_SURFACE_MD}}   — attack-surface.md 内容（截取）
#   {{VULN_HUNT_OUTPUT_MD}} — vuln_hunt_output.md 内容（截取）
#   {{CALL_GRAPHS_MD}}      — call_graphs.md 内容（截取）
#   {{CHALLENGE_VERDICT_MD}} — challenge_verdict.md 内容（截取）
#   {{FINAL_MD}}            — FINAL.md 内容（截取，若存在）

BEGIN_PROMPT
你是安全研究报告撰写专家。基于 Codex 漏洞扫描框架的多轮分析产物，生成一份完整的最终安全分析报告。

## 基本信息
- 目标目录：{{TARGET_DIR}}
- 漏洞类型：{{VULN_TYPE}}
- 扫描结果：{{SCAN_RESULT}}
- 总轮次：{{TOTAL_ROUNDS}}

## 你的任务

1. **先读取目标目录下的分析产物文件**（attack-surface.md、call_graphs.md、vuln_hunt_output.md、context_snapshot.json、challenge_verdict.md、FINAL.md），全面了解分析历史
2. **按需读取目标代码**补充信息（特别是认证管线、路由表、关键漏洞函数的上下文）
3. **生成 FINAL_REPORT.md**，严格按照下方模板结构

## 报告模板（MANDATORY — 每个章节都必须包含）

```markdown
# 安全分析报告

## 1. 分析概览

| 项目 | 值 |
|------|---|
| 目标 | <目标描述，从代码结构推断产品/服务类型> |
| 漏洞类型 | <用户指定的漏洞类型> |
| 技术栈 | <语言、框架、Web 服务器、数据库等> |
| 总轮次 | <N> |
| 最终判定 | <PASS/LOOP> |
| 扫描日期 | <从 challenge_verdict.md 或文件时间提取> |

### 技术栈详情
<简述目标的技术栈，包括语言版本、关键依赖、架构模式>

## 2. 已分析文件清单

> 从 context_snapshot.json、attack-surface.md、call_graphs.md 中提取分析过的文件。
> 如果信息不足，用 Grep/Glob 搜索目标目录补充。

| 文件路径 | 功能描述 | 分析深度 | 备注 |
|----------|---------|---------|------|
| <相对路径> | <文件的功能/职责> | <浅层阅读/签名分析/深度追踪> | <关键发现或无> |

## 3. 认证流程与控制流架构

### 3.1 请求处理主循环

> 从 accept()/recv() 到 handler 调用的完整链路。
> 从 call_graphs.md 和源代码中提取。

```
<文本格式的架构图>
请求入口 → [模块A] → [模块B] → ... → Handler
```

### 3.2 认证检查管线

> 逐层列出认证检查函数。

| 检查层 | 函数名 | 位置（文件:行号） | 检查逻辑 | 绕过条件 |
|--------|-------|-----------------|---------|---------|
| Layer 1 | <函数名> | <文件:行号> | <检查什么> | <是否可绕过、条件> |

### 3.3 会话/Token 管理

<会话创建、验证、销毁的机制描述>

### 3.4 控制流架构图

```
<文本格式的整体架构图，标注认证边界>
```

## 4. 攻击面与路由表

### 4.1 路由表

> 着重标注 Pre-auth 入口（★ 标记）。

| # | 路由/入口 | 方法 | Handler 函数 | 认证状态 | 分析状态 | 分析深度 |
|---|----------|------|-------------|---------|---------|---------|
| 1 | <路径> | <GET/POST/...> | <函数名(文件:行号)> | ★Pre-auth / Post-auth / CONDITIONAL | ✅已分析 / ❌未分析 | <0-5> |

### 4.2 攻击面统计

| 指标 | 值 |
|------|---|
| 总 P0 入口 | <N> |
| 已分析 P0 | <N> |
| 广度覆盖率 | <N%> |
| 深度覆盖率 | <N%> |
| Pre-auth 入口总数 | <N> |
| Pre-auth 已分析 | <N> |

### 4.3 未分析入口及原因

| 入口 | 未分析原因 |
|------|----------|
| <路径> | <原因> |

## 5. 漏洞发现

### 5.1 确认的漏洞

> 仅 PASS 时有此章节。包含完整 Source→Sink 链、代码证据、PoC 概念。

#### VULN-01: <漏洞名称>

- **类型**: <漏洞类型>
- **置信度**: High
- **Exploitability**: CONFIRMED
- **认证前提**: Pre-auth / Post-auth
- **影响**: <影响描述>

**Source→Sink 链**:
<逐跳列出，每跳贴代码片段>

**PoC 概念**:
```
<利用方案>
```

### 5.2 候选漏洞（CONDITIONAL / 未完全验证）

> 所有活跃候选漏洞。

#### CAND-01: <候选名称>

- **类型**: <漏洞类型>
- **置信度**: Medium / Low
- **Exploitability**: EXPLOITABILITY_CONDITIONAL / SOURCE_UNCONTROLLABLE
- **利用条件**: <具体条件>
- **当前阻断点**: <什么阻止了确认>
- **Source→Sink 摘要**: <简述链路>

### 5.3 排除的漏洞

> 所有被排除的候选，必须给出排除原因和代码证据。

#### EXCLUDED-01: <候选名称>

- **排除原因**: <具体原因>
- **阻断点**: `<函数名>` (`<文件:行号>`)

```
// <文件:行号>
<阻断代码片段>
```

**分析**: <为什么这段代码阻断了利用链>

## 6. 覆盖率与遗留分析

### 6.1 分析覆盖率总结

<整体覆盖情况评估>

### 6.2 遗留问题与建议

| # | 遗留问题 | 建议后续动作 |
|---|---------|------------|
| 1 | <问题描述> | <建议> |
```

## 输入材料（供参考，你也可以直接读取目标目录下的完整文件）

### attack-surface.md
{{ATTACK_SURFACE_MD}}

### vuln_hunt_output.md
{{VULN_HUNT_OUTPUT_MD}}

### call_graphs.md
{{CALL_GRAPHS_MD}}

### challenge_verdict.md
{{CHALLENGE_VERDICT_MD}}

### FINAL.md（Codex 原始报告）
{{FINAL_MD}}

## 输出要求

1. 将报告写入文件：{{TARGET_DIR}}/FINAL_REPORT.md
2. 使用中文撰写
3. 每个章节都必须有实质内容，不允许写"暂无"或"待补充"
4. 如果某些信息在分析产物中缺失，主动用 Read/Grep/Glob 工具从目标代码中提取
5. 路由表和文件清单尽量完整，宁多勿少
END_PROMPT
