# Context Snapshot Schema Reference

`context_snapshot.json` 由 ZCode 主代理（编排器）在每轮 Phase 4 结束时生成，存放在项目目录下。

```json
{
  "$schema": "context_snapshot_v1",
  "version": 1,
  "round": 37,
  "vuln_type": "认证前远程代码执行",
  "target_dir": "/path/to/target",
  "memory_filter": {
    "vuln_type_tags": ["PREAUTH", "RCE", "BOF"],
    "applied_memory_ids": ["MEM-PATTERN-BOF-01"],
    "excluded_memory_ids": ["MEM-PATTERN-SQLI-01"]
  },
  "subagent_budget": {
    "max_per_round": 12,
    "max_concurrent": 4,
    "dispatched": 7,
    "by_phase": {"phase1": 1, "phase2": 4, "phase3": 1, "phase4": 1},
    "remaining": 5
  },
  "attack_surface": {
    "total_p0": 8,
    "analyzed_p0": 6,
    "deep_analyzed_p0": 3,
    "coverage_pct": 75,
    "deep_coverage_pct": 37.5,
    "surfaces": [
      {
        "id": "AS-01",
        "description": "vbond TLS handler pre-auth message parsing",
        "priority": "P0",
        "status": "analyzed",
        "preauth_reachable": "YES",
        "entry_functions": ["sub_42550"],
        "security_decision_functions": ["sub_5D9B0"],
        "sink_functions": ["sub_2E0B0"],
        "analysis_depth": 4,
        "round_first_analyzed": 2,
        "round_last_updated": 15
      }
    ]
  },
  "candidates": {
    "active": [
      {
        "id": "CAND-13",
        "title": "Heap overflow in vbond message handler",
        "vuln_type": "缓冲区溢出",
        "status": "under_investigation",
        "root_cause_function": "sub_49E20",
        "sink_function": "sub_2E0B0",
        "source_sink_path": "sub_42550 -> sub_5D9B0 -> sub_49E20 -> sub_2E0B0",
        "evidence_lines": [
          {
            "file": "vbond_proc.c",
            "function": "sub_49E20",
            "line": 1847,
            "snippet": "memcpy(buf, msg->data, msg->length)",
            "note": "msg->length from untrusted input, no upper bound check"
          }
        ],
        "guards": [
          {
            "function": "sub_5D9B0",
            "type": "length_check",
            "bypassable": true,
            "reason": "checks message type field, not length field"
          }
        ],
        "confidence": 0.72,
        "open_questions": ["sub_2E0B0 内部是否有额外裁剪"],
        "influencing_memory_ids": ["MEM-PATTERN-BOF-01"],
        "round_discovered": 12,
        "round_last_updated": 37
      }
    ],
    "excluded": [
      {
        "id": "CAND-03",
        "root_cause_function": "sub_1A200",
        "exclusion_reason": "requires admin auth (policy=2)",
        "excluded_in_round": 8,
        "influencing_memory_ids": ["MEM-PATTERN-AUTHBYPASS-01"]
      }
    ],
    "verified": []
  },
  "call_graph_summary": {
    "total_functions_analyzed": 142,
    "fully_read": 89,
    "signature_only": 53,
    "pending_expansion": [
      {
        "function": "sub_7C340",
        "parent": "sub_49E20",
        "reason": "data decode logic, must fully read",
        "priority": "high"
      }
    ]
  },
  "permission_architecture": {
    "total_commands": 47,
    "preauth_commands": [
      {
        "cmd_id": 7,
        "handler": "sub_3B100",
        "capability_class": "C"
      }
    ],
    "enumeration_complete": true
  },
  "auth_pipeline": {
    "analysis_complete": true,
    "layers": [
      {
        "id": "Layer_A",
        "function": "http_alias_fillTarget",
        "location": "httpd.c:4494",
        "type": "route_filter",
        "mechanism": "未登录时对 CGI 路由做白名单过滤，不在白名单中返回 NULL",
        "whitelist": ["/cgi/getParm", "/cgi/login", "/cgi/logout", "/cgi/info"],
        "return_null_handling": "主循环 L3297 检查返回值，NULL → 返回 404"
      },
      {
        "id": "Layer_B",
        "function": "http_author_hasAuthor",
        "location": "httpd.c:4130",
        "type": "session_auth",
        "mechanism": "检查 session 权限位",
        "skip_condition": "strstr(url, '/cgi') 时跳过（L3306）"
      }
    ],
    "route_auth_table": [
      {
        "route": "/cgi/login",
        "layer_a": "白名单放行",
        "layer_b": "跳过",
        "final": "pre-auth"
      },
      {
        "route": "/cgi/softup",
        "layer_a": "返回NULL→404",
        "layer_b": "不可达",
        "final": "post-auth"
      }
    ]
  },
  "loop_history": {
    "total_rounds": 37,
    "recent_rounds": [
      {
        "round": 37,
        "focus": "Deep analysis of sub_49E20 heap overflow path",
        "decision": "LOOP",
        "reason": "pending_expansion sub_7C340 not yet fully read"
      }
    ],
    "archived_rounds_file": "loop_history_archive_r1_r30.json"
  },
  "next_round_directive": {
    "priority_targets": [
      "Complete full read of sub_7C340",
      "Analyze AS-07 (pending P0 surface)"
    ],
    "files_to_read": [
      "call_graphs.md:sections:sub_49E20",
      "attack-surface.md:sections:AS-07"
    ],
    "files_to_skip": [
      "attack-surface.md:sections:archived-p2",
      "vuln_hunt_output.md:sections:archived-excluded"
    ],
    "memory_ids_to_load": [
      "MEM-PATTERN-BOF-01",
      "MEM-META-MEMCORRUPT-IS-RCE"
    ],
    "exclude_known_vulns": [
      "OrgHeaders 跨组织认证绕过",
      "put_clear_device_token 未认证端点"
    ],
    "phase2_sections_to_execute": ["2.2.2", "2.8"]
  },
  "file_sizes": {
    "vuln_hunt_output.md": 112000,
    "context_snapshot.json": 51800,
    "call_graphs.md": 45000,
    "attack-surface.md": 38000,
    "challenge_verdict.md": 51600,
    "vuln_hunt_output.md": 28000
  }
}
```

## 字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `$schema` | string | 固定为 `"context_snapshot_v1"` |
| `round` | int | 当前轮次编号 |
| `vuln_type` | string | 用户指定的漏洞类型（中文） |
| `subagent_budget` | object | 子代理派发额度记账(ZCode 版新增)。每轮重置;每次派发/回收后由编排器更新;Phase 4 派发前必须检查 `remaining >= 1`,不足时压缩 Phase 2/3 后续派发 |
| `attack_surface.analyzed_p0` | int | `analysis_depth >= 3` 的入口数（有明确 auth 结论） |
| `attack_surface.deep_analyzed_p0` | int | `analysis_depth >= 4` 的入口数（source→sink 路径完整追踪） |
| `attack_surface.coverage_pct` | float | `analyzed_p0 / total_p0 * 100` |
| `attack_surface.deep_coverage_pct` | float | `deep_analyzed_p0 / total_p0 * 100` |
| `attack_surface.surfaces[].status` | enum | `analyzed`（depth≥3）/ `pending` / `excluded` |
| `attack_surface.surfaces[].preauth_reachable` | enum | `YES` / `NO` / `CONDITIONAL` / `UNKNOWN`（标注 pre-auth 可达性结论） |
| `attack_surface.surfaces[].analysis_depth` | int | 分析深度，定义见下方深度枚举表 |
| `candidates.active[]` | array | 仍在调查的候选，含完整 evidence_lines（最多 5 条/候选）和 influencing_memory_ids |
| `candidates.excluded[]` | array | 已排除候选，仅含排除原因摘要和 influencing_memory_ids |
| `candidates.verified[]` | array | 已验证候选，同 active 结构 + `verification_round` |
| `auth_pipeline.analysis_complete` | bool | 认证管线分析是否完成。Phase 1 §1.4.5.0 完成后设为 true |
| `auth_pipeline.layers[]` | array | 认证检查层列表，每层含函数名、位置、机制、白名单（如有）、返回值处理 |
| `auth_pipeline.route_auth_table[]` | array | 路由认证状态表，每条路由标注各层结果和最终可达性 |
| `call_graph_summary.pending_expansion[]` | array | 需要完整阅读但尚未展开的函数 |
| `loop_history.recent_rounds` | array | 最近 7 轮的 focus/decision/reason |
| `next_round_directive` | object | 下一轮的精准指令 |
| `next_round_directive.exclude_known_vulns` | array | 已知漏洞描述列表，下一轮不得作为主要发现报告 |
| `next_round_directive.phase2_sections_to_execute` | array | Phase 2 精准执行列表。非空时，下一轮 Phase 2 **只执行**列表中编号对应的章节，跳过其余章节。空数组或字段缺失 = 执行完整 Phase 2。可填值：`"2.1.5"` / `"2.1.6"` / `"2.1.7"` / `"2.2"` / `"2.2.1"` / `"2.2.2"` / `"2.3"` / `"2.4"` / `"2.6.5"` / `"2.7"` / `"2.8"` |

## analysis_depth 深度枚举

| depth | 含义 | 计入 analyzed_p0 | 计入 deep_analyzed_p0 |
|-------|------|:---:|:---:|
| 1 | 仅确认路由/入口存在 | ✗ | ✗ |
| 2 | 确认 auth 检查函数名，未追踪调用链 | ✗ | ✗ |
| 3 | 已识别 security_decision_function + 给出明确 pre-auth 可达性结论（YES/NO/CONDITIONAL） | ✅ | ✗ |
| 4 | source→sink 路径完整追踪，含 guard 分析 | ✅ | ✅ |
| 5 | exploit primitive 已验证（进入 CAND 候选） | ✅ | ✅ |

**规则**：
- `status: "analyzed"` 必须满足 `analysis_depth >= 3`，否则保持 `pending`
- `analyzed_p0` = surfaces 中 `analysis_depth >= 3` 的数量
- `deep_analyzed_p0` = surfaces 中 `analysis_depth >= 4` 的数量
- Phase 4 Challenge Agent 在验证 coverage 时，需同时检查 `coverage_pct`（广度）和 `deep_coverage_pct`（深度）

## 约束
- snapshot 文件总大小不超过 **50KB**
- `evidence_lines` 每个候选最多 **5 条**
- `recent_rounds` 保留最近 **7 轮**
- `excluded` 候选不保留 evidence_lines
