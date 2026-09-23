# Phase 0: Memory Bootstrap

1. Load memory from `~/.zcode/memory/vuln-hunt/insights.jsonl`.
2. Build a current `memory_snapshot_id` and `must_apply` set from active memory.
3. **漏洞类型标签匹配**：根据用户指定的漏洞类型，查阅本文件下方的**记忆标签映射表**确定主标签和附加标签，从 `insights.jsonl` 中筛选 ID 包含匹配标签的 `vuln_pattern` 条目。匹配的记忆条目按 `confidence` 字段降序排列注入 `must_apply`，使高置信记忆优先影响分析。无 `confidence` 字段的条目视为 `0.5`。若存在 `context_snapshot.json`（Round 2+），进一步缩窄到 `next_round_directive.memory_ids_to_load` 中列出的 ID。
4. 同时加载所有 `meta_rule` 和 `failure_pattern` 类型记忆（始终加载，不受标签过滤影响），确保整个流程聚焦用户指定的漏洞类型。
4a. **策略扩展记忆加载**：在标签过滤结果中，若存在 `strategy_extension` 类型的记忆条目，将其内容追加到对应策略文件的加载上下文中。`strategy_extension` 记忆的 ID 应包含对应的漏洞类型标签（如 `MEM-STRATEGY-BOF-*`），以便正确匹配。
4b. **技术栈提示加载**：在 Phase 1 依赖分析（§1.1.2）完成后，根据检测到的技术栈关键词（如 Rust/Django/Spring），从 `insights.jsonl` 中加载匹配的 `tech_stack_hint` 类型条目，注入后续 Phase 的 prompt 上下文中。
5. Inject into every phase prompt and sub-agent task:
   - `memory_snapshot_id`
   - `must_apply` (policy memory + matched vuln_pattern)
   - `contextual_memory` (episode memory)

## 记忆标签映射表

按用户指定的漏洞类型确定主标签和附加标签;ID 中包含任一标签的 `vuln_pattern` / `episode` 条目均被选中。

| 漏洞类型 | 主标签 | 附加标签 |
|----------|--------|---------|
| SQL注入 | SQLI | — |
| 缓冲区溢出 | BOF | INTOV, MEMOV |
| 整数溢出 | INTOV | BOF, MEMOV |
| 认证绕过 | AUTHBYPASS | SQLI |
| 命令注入 | CMDI | — |
| 格式化字符串 | FMTSTR | BOF, MEMOV |
| 认证前RCE / 预认证漏洞 / preauth | PREAUTH, RCE, AUTHBYPASS | BOF, FMTSTR, CMDI, MEMOV, INTOV, PATHTRV, FILEWRITE, FILEREAD, ARCH, SQLI, DESER, INJECT |
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

**始终加载**:所有 `meta_rule` 和 `failure_pattern` 类型条目;`deprecated: true` 的条目一律跳过。

## 记忆类型与自定义 ID 约定

| 类型 | 加载规则 | 说明 |
|------|---------|------|
| `vuln_pattern` / `vulnerability_pattern` | 按标签匹配加载 | 漏洞类型的 source→sink 检查模板 |
| `meta_rule` | 始终加载 | 全局策略规则 |
| `failure_pattern` | 始终加载 | 反模式(什么不该做),ID 前缀 `MEM-FAILURE-*` |
| `episode` / `episode_memory` | 按标签匹配加载 | 具体漏洞案例经验 |
| `strategy_extension` | Phase 2 加载策略时自动追加 | 对策略文件的 Sources/Sinks/Key Check 补充 |
| `tech_stack_hint` | Phase 1 依赖分析后匹配加载 | 技术栈/框架审计提示 |

自定义记忆直接编辑 `~/.zcode/memory/vuln-hunt/insights.jsonl`,每行一条:

```json
{
  "id": "MEM-<TYPE>-<UNIQUE_ID>",
  "type": "<上表类型>",
  "content": "记忆内容(自然语言)",
  "source": "user-defined",
  "timestamp": "YYYY-MM-DD",
  "confidence": 0.5
}
```

ID 命名:`MEM-PATTERN-<TAG>-<序号>`(漏洞模式)、`MEM-META-<名称>`、`MEM-FAILURE-<名称>`、
`MEM-EP-<TAG>-<日期>-<描述>`(经验)、`MEM-STRATEGY-<TAG>-<描述>`、`MEM-TECH-<STACK>-<描述>`。
ID 中的标签关键词(BOF/SQLI/AUTHBYPASS 等)用于标签匹配,务必写对。

## Phase 0.5: Context Snapshot Recovery（Round 2+ 专用）

**仅在以下条件同时满足时执行**：当前为 Round 2 或更高轮次，且项目目录下存在 `context_snapshot.json`。Round 1 跳过此步骤。

1. **读取 snapshot**：读取 `context_snapshot.json`，验证 `$schema` 为 `"context_snapshot_v1"`。若 schema 不匹配或 JSON 解析失败，打印警告并**回退到全量 MD 文件读取模式**（即按 Round 1 行为执行 Phase 1）。
2. **恢复攻击面状态**：从 `attack_surface` 字段恢复所有攻击面条目及其 status（analyzed/pending/excluded）。无需重新读取 `attack-surface.md` 的已分析条目。
3. **恢复候选漏洞**：
   - 从 `candidates.active` 恢复所有活跃候选的完整上下文（evidence_lines、guards、open_questions）
   - 从 `candidates.excluded` 恢复已排除候选列表（仅摘要，**禁止对 excluded 候选重新分析**，除非 Challenge Agent 在上一轮明确要求）
   - 从 `candidates.verified` 恢复已验证候选
4. **恢复调用图摘要**：从 `call_graph_summary` 恢复 fully_read/signature_only 统计和 pending_expansion 列表
5. **恢复权限架构**：从 `permission_architecture` 恢复命令清单和 enumeration_complete 状态
6. **选择性文件读取**：仅读取 `next_round_directive.files_to_read` 指定的 MD 文件及其特定节（section）。格式为 `filename:sections:section_name`，表示仅读取该文件中与 section_name 相关的部分。`files_to_skip` 中列出的内容不读取。
7. **记忆精准加载**：
   - 始终加载所有 `meta_rule` 和 `failure_pattern` 类型条目
   - 从 `next_round_directive.memory_ids_to_load` 加载指定的记忆 ID
   - 跳过不在加载列表中的 `vuln_pattern` 和 `episode` 类型条目
   - 将加载的记忆注入 `must_apply` 和 `contextual_memory`
8. **恢复 Loop History**：从 `loop_history.recent_rounds` 了解最近轮次的 focus 和 decision，避免重复已证伪的方向
9. **Phase 2 精准章节注入**：读取 `next_round_directive.phase2_sections_to_execute`，将其作为 `phase2_active_sections` 注入后续 Phase 2 的执行上下文。
   - 若字段存在且非空：Phase 2 开头将读取此列表，只执行列出的章节
   - 若字段缺失或为空数组：Phase 2 按完整流程执行（不限制章节）
   - 此字段**不影响** Phase 1、Phase 3、Phase 4 的执行范围
