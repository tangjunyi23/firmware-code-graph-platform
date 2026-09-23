---
name: vuln-hunt-memory-driven
description: >
  记忆驱动的漏洞挖掘工作流:对目标目录(源码、固件二进制或混合)按六阶段循环挖掘指定类型漏洞
  (记忆引导→攻击面锁定→漏洞挖掘→验证→独立对抗挑战→报告),产出 FINAL.md 验证报告。
  当用户要求挖漏洞、找漏洞、漏洞挖掘、安全审计、hunt vulnerability,或在 CTF/授权渗透中
  分析目标代码寻找 SQL注入/缓冲区溢出/命令注入/认证绕过/预认证RCE/路径穿越等漏洞时使用本 skill。
  需要目标目录和漏洞类型;未指定类型时默认"预认证漏洞"广谱模式。仅用于授权测试与研究。
---

# Vulnerability Hunt Skill (Memory-Driven, ZCode 版)

主代理(当前会话)是**编排器**:负责记忆加载、snapshot 恢复、结果聚合与轮次控制;
Phase 1/2/3/4 的重分析工作必须用 **Agent 工具**派发子代理执行,不得全部内联。

## Loop Flow(固定顺序,不可跳过/合并/替换)

```
┌───────────────────────────────────────────────────────────┐
│ Round N (fixed order, no skipping/merging/replacing)       │
├───────────────────────────────────────────────────────────┤
│ 0) Memory Bootstrap         → load: references/phase0_memory.md
│ 1) Attack Surface Locking    → load: references/phase1_attack_surface.md
│ 2) Vulnerability Hunting     → load: references/phase2_hunting.md
│ 3) Verification              → load: references/phase3_verification.md
│ 4) Challenge Agent(独立)     → load: references/phase4_challenge.md
└───────────────────────────────────────────────────────────┘
                      │
                      ▼
            Challenge Verdict: PASS or LOOP
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
       PASS                   LOOP(更新 snapshot)
          │                       └─> 编排器直接开始 Round N+1
       Reporting
       (load: references/phase5_reporting.md)
```

多轮迭代**由编排器在本会话内自行循环**,无外部脚本。若上下文即将耗尽或用户中断,依靠
`context_snapshot.json` 在下一会话/下一次提示词处恢复(Phase 0.5),恢复后继续当前轮次,不重跑已分析项。

## 子代理派发协议(Agent 工具 — MANDATORY)

用 Agent 工具派发子代理,`subagent_type: general-purpose`(纯只读侦察类工作可用 `Explore`)。
子代理无法看到本会话上下文,**prompt 必须自包含**:任务参数、输出文件路径、日志要求都要写全。
模板见 `references/agent_templates.md`,派发前必须先读它。

### 派发上限(硬性约束 — 违反即为流程错误)

| 上限 | 值 | 含义 |
|------|----|------|
| `MAX_CONCURRENT` | **4** | 单批同时派发的子代理数;一批完成返回后再派下一批 |
| `MAX_PER_ROUND` | **12** | 每轮 Phase 1–4 子代理总数(含失败重派),达到后剩余工作由编排器内联完成 |

每轮额度分配(总和 = 12):

- Phase 1:**1** 个(固定,不可省)
- Phase 2:**≤ 6** 个
- Phase 3:**≤ 4** 个
- Phase 4:**1** 个(预留,永远优先保证;Phase 2/3 不得占用)

### 超限合并规则(不得通过增加子代理数量解决排队)

- **Phase 2 超限**:P0 surface 数 > 可用额度时,按优先级排序(预认证可达 > 高危 sink > 其他),
  把 2–3 个相邻/同模块 surface 打包给**一个** worker,该 worker 输出多个 `phase2_surface_<id>.json`。
- **Phase 3 超限**:候选数 > 可用额度时,按 confidence 降序 + 同文件/同模块就近分组,
  一个 worker 验证一组候选,输出多个验证结果。
- **任何情况下禁止**:为绕过上限拆成更多子代理、或并发超过 4 个。

### 额度记账(MANDATORY)

编排器在 `context_snapshot.json` 顶层维护:

```json
"subagent_budget": {
  "max_per_round": 12,
  "max_concurrent": 4,
  "dispatched": 7,
  "by_phase": {"phase1": 1, "phase2": 4, "phase3": 1, "phase4": 1},
  "remaining": 5
}
```

每次派发后立即更新;Phase 4 派发前检查 `remaining >= 1`,不足则先压缩 Phase 2/3 的后续派发
(改内联或留到下一轮),为 Phase 4 留出额度。

### 长耗时任务处理

ZCode 子代理调用返回即完成,没有轮询接口:派发后耐心等待结果,不要因任务大体量而预判失败。
只有子代理明确报错或方向错误时才重新派发(重派同样消耗额度)。大批量工作优先用"合并规则"
分批,而不是无限加派。

### 子代理进度日志(所有 worker 必须)

- Phase 1: `phase1_worker.log`;Phase 2: `phase2_surface_<surface_id>.log`
- Phase 3: `phase3_verify_<candidate_id>.log`;Phase 4: `phase4_challenge.log`
- 追加写入、带时间戳;记录开始/里程碑/完成;长任务每 60–120 秒心跳。
- 编排器在等待子代理返回的间隙可读取这些日志观察进度。

### Phase 派发规则

```
Phase 1:单 worker 独立执行攻击面分析,写 attack-surface.md + 更新 snapshot;完成后再进 Phase 2
Phase 2:每个(或每组)surface 一个 worker,并行启动(≤4);全部返回后编排器合并排序
Phase 3:每个(或每组)候选一个 worker,并行启动(≤4);全部返回后编排器汇总
Phase 4:单 worker,独立上下文(严禁编排器内联,禁止传入 Phase 2 中间推理);
        输入仅 attack-surface.md + vuln_hunt_output.md(+call_graphs.md),输出 challenge_verdict.md,
        最后一行必须是 overall_verdict: PASS 或 LOOP
```

### Task 消息通用头部(每个子代理 prompt 第一段)

```
你是其中一个并行分析 worker。你不孤单,代码库里可能有其他 agent 在并行工作,不要回退他人的改动。
你的职责仅限于[具体任务]。只写你独立负责的输出文件,避免冲突。你必须同时写入自己的进度日志文件
(append 模式,带时间戳),至少记录开始、里程碑、完成;长任务需定期心跳。完成后以 JSON 格式汇报:
{ "files_written": [...], "logs_written": [...], "summary": "..." }
```

## Reference File Loading Protocol

每个 Phase 开始时读取对应 reference 文件(相对本 skill 目录):

| Phase | Reference | 何时加载 |
|-------|-----------|---------|
| Phase 0 | `references/phase0_memory.md` | 每轮开始 |
| Phase 1 | `references/phase1_attack_surface.md` | 每轮 |
| Phase 1B | `references/phase1_binary_analysis.md` | 检测到二进制目标或 `decompile/` 目录时 |
| Phase 1C | `references/phase1_auth_analysis.md` | 漏洞类型为预认证类时无条件加载 |
| Phase 2 | `references/phase2_hunting.md` + `references/strategies/<type>.md` | 每轮 |
| Phase 3 | `references/phase3_verification.md` | 每轮 |
| Phase 4 | `references/phase4_challenge.md` | 每轮 |
| Phase 5 | `references/phase5_reporting.md` | 仅 PASS 后 |
| Schema | `references/snapshot_schema.md` | Phase 4 生成 snapshot 时 |
| Agents | `references/agent_templates.md` | 派发子代理前 |
| Rev | `references/rev-symbol.md` / `references/rev-struct.md` | Phase 1B 反编译后 |

### 默认扫描策略

用户未指定漏洞类型时,一律使用 `预认证漏洞`(广谱模式):在预认证攻击面内搜索一切可利用漏洞,
尽量串联成 Pre-auth RCE 链。仅当用户明确指定单一类型时才缩窄到对应策略文件。

### 漏洞类型 → 策略文件映射

| 漏洞类型 | 策略文件 |
|----------|---------|
| SQL注入 | `strategies/sqli.md` |
| 缓冲区溢出 | `strategies/bof.md` |
| 整数溢出 | `strategies/intov.md` |
| 认证绕过 | `strategies/authbypass.md` |
| 命令注入 | `strategies/cmdi.md` |
| 格式化字符串 | `strategies/fmtstr.md` |
| 认证前RCE / 预认证漏洞 / preauth | `strategies/preauth_rce.md`(广谱) |
| 路径穿越 / 文件读取 / 文件写入 | `strategies/pathtrv.md` / `fileread.md` / `filewrite.md` |
| 文件上传 / 反序列化 | `strategies/upload.md` / `deser.md` |
| 内存溢出 | `strategies/memov.md` |
| LDAP/NoSQL/SSTI/通用注入 | `strategies/injection.md` |
| 拒绝服务 / 会话管理 / 密码学 / 业务滥用 | `strategies/dos.md` / `session.md` / `crypto.md` / `abuse.md` |

## 长期记忆

- 记忆账本:`~/.zcode/memory/vuln-hunt/insights.jsonl`(JSONL,每行一条)
- 按漏洞类型标签过滤:`python <skill>/scripts/filter_memory.py <memory_file> <tags...> [max_extra]`
- PASS/LOOP 反馈更新置信度:`python <skill>/scripts/update_feedback.py <snapshot> <verdict> <memory_file>`
- 记忆标签映射表、类型说明、自定义 ID 约定:见 `references/phase0_memory.md` 附表(ID 标签 BOF/SQLI/AUTHBYPASS/PREAUTH 等)
- 始终加载:`meta_rule` 和 `failure_pattern` 条目;`deprecated: true` 的条目跳过

## 二进制目标反编译

调用链进入 ELF 二进制时必须反编译,不得用 strings 输出推断 sink 语义(详见 `references/phase1_binary_analysis.md`)。
单二进制导出用 rootfs-elf skill 安装的 worker:

```bash
IDADIR=<IDA安装目录(≥9.1)> python ~/.zcode/tools/rootfs_elf/rootfs_elf/ida_worker.py \
    --elf <binary_path> --out-dir <output_dir> [--skip-memory]
```

整个 rootfs 已批量导出过时(`by_elf/<elf_id>/decompile/` 存在)直接消费,不必重跑。

## Loop Rules

1. 每轮固定顺序:Attack Surface → Hunting → Verification → Challenge。
2. Challenge Agent 每轮**强制**,必须独立子代理,消耗 1 额度。
3. verdict 为 LOOP → 编排器更新 snapshot 后直接开始 Round N+1(LOOP 后不得终止流程,除非达到用户指定轮数上限,默认 5 轮)。
4. verdict 为 PASS → 进入 Phase 5 报告。
5. 每轮 Phase 4 结束必须生成/更新 `context_snapshot.json`(schema 见 `references/snapshot_schema.md`,含 `subagent_budget`)。

## 冲突与中断

- 记忆冲突:最新用户指令 > 更高强制优先级 > 时间就近;未采用的记忆记入 `unapplied_memory_explanation`。
- 用户中途改约束:仅当是明确的攻击面方向/漏洞模式/验证策略时才持久化为记忆;刷新 snapshot;从当前 Phase 继续。

## 监控(可选,长任务推荐)

```bash
python <skill>/scripts/monitor.py <目标目录>              # CLI 实时监控
python <skill>/scripts/dashboard.py <目标目录> [端口]      # Web Dashboard(默认 8080)
```
