# Phase 4: Challenge Agent

1. Use a challenge perspective to stress-test current conclusions.
2. Must explicitly answer all three questions:
   - **是否找到了匹配目标漏洞类型的高置信漏洞？**（Pre-auth RCE 类型下，认证绕过/任意文件读取/任意文件写入均属于匹配范围，参见 `strategies/preauth_rce.md` 认证前高危漏洞类型表）
   - **是否有未分析的 source->sink 路径？**
   - **漏洞分类是否正确？**

## 核心检查（每轮必执行）

3. **根因函数检查**：报告的漏洞函数是否为真正的根因函数？
4. **主次优先级检查**：是否把利用链路更复杂/更隐蔽的那个标为主要发现？
5. **完整性检查**：是否有仅做上界检查但缺少下界检查的情况？
6. **隐藏漏洞检查**：是否存在弱哈希/缓存键碰撞、过滤顺序可绕过、运算符优先级错误等被遗漏？

## 被降级候选重新审视（MANDATORY）

7. 列出所有被降级为 Medium 或排除的候选漏洞，对每个重新评估降级理由是否充分。
   - **如果被降级候选的漏洞模式更经典，verdict 必须为 LOOP**。

7a. **排除候选的子机制拆分检查（MANDATORY）**：
    - 对每个被排除的候选，检查其是否包含多个**独立的**攻击子机制（如多个不同的 preauth header、多条不同的认证路径、多个不同的 deserialization 入口）
    - 若排除证据只覆盖了部分子机制（如 proxy strip 了 2/5 个 preauth headers），**verdict 必须为 LOOP**
    - LOOP 时指示下一轮：**将未被排除证据覆盖的子机制拆分为独立候选重新评估**
    - **检查方法**：
      1. 找到候选的排除理由中引用的防护证据（如 `RequestHeader unset X-Foo`）
      2. 枚举候选包含的所有子机制（如 compositeFilter 中的每个 filter/header）
      3. 逐一比对：每个子机制是否都有对应的防护证据？
      4. 若存在无防护证据的子机制 → verdict=LOOP
    - **失败教训**：Nutanix CVM 案例中，CAND-HEADER-PREAUTH-01 包含 5 个 preauth header filter，但 SSL terminator 只 strip 了其中 2 个（`X-Nutanix-Preauth-User`、`X-NTNX-Authn`）。扫描器整体排除了该候选，遗漏了 `X-Nutanix-GuestVM-Preauth` 认证绕过。

## 攻击面覆盖率审计（MANDATORY）

8. 回顾 attack-surface.md，逐项检查每个 P0 攻击面是否已被充分分析。
   - **覆盖率 < 100% 时 verdict 必须为 LOOP**。

## 攻击面类型完整性检查（MANDATORY）

8a. **注入类型覆盖检查**：检查 attack-surface.md 的"技术栈 Sink 扩展"章节。
   - 若目标依赖包含 LDAP/NoSQL/SSTI/EL/XML 等非标准注入库，但 P0 攻击面列表中没有对应注入类型的攻击面 → **verdict 必须为 LOOP**（Phase 1 依赖分析未生效或被跳过）。
   - 检查项：`ldap`/`ldap3` → P0 中应有 LDAP 查询相关攻击面；`pymongo`/`mongoose` → 应有 NoSQL 查询攻击面；`jinja2`/`Twig` → 应有模板渲染攻击面。
   - **若"技术栈 Sink 扩展"章节缺失**，说明 §1.1.2 未执行，verdict 必须为 LOOP 并在 challenge_verdict.md 中标注"Round N+1 必须执行依赖分析"。

## 测试代码排除检查（MANDATORY）

8b. **主要发现生产代码验证**：检查 FINAL.md 中主要发现引用的代码文件路径。
   - 若主要发现的代码证据（文件路径:行号）位于以下目录中，**verdict 必须为 LOOP**：
     - `test/`, `tests/`, `testing/`, `t/`（测试代码）
     - `examples/`, `example/`, `samples/`, `demo/`（示例代码）
     - `fuzz/`, `fuzzing/`, `fuzzers/`（模糊测试代码）
     - `benchmarks/`, `benchmark/`, `perf/`（性能测试代码）
     - `testdata/`, `fixtures/`（测试数据）
   - LOOP 时指示下一轮：**转向生产代码中的同类漏洞搜索**，测试代码中的发现可在附录中提及但不得作为主要结论。
   - **红队原则**：测试代码中的漏洞在生产部署中通常不可达，不构成红队可利用的攻击面。

## 已知漏洞排除检查（CONDITIONAL — 编排器传入排除列表时执行）

8c. 若编排器在 prompt 中注入了 `## 已知漏洞排除（MANDATORY）` 段落：
   - 检查 FINAL.md 中的主要发现是否与排除列表中的漏洞描述重叠
   - 若重叠，**verdict 必须为 LOOP**，并在 challenge_verdict.md 中指示：**排除该已知漏洞，转向其他攻击面探索**
   - 允许在报告中附带提及已知漏洞作为交叉验证，但不得作为主要发现

## @NoAuth 入口 Source-First 覆盖审计（MANDATORY — 认证前RCE / Web 应用）

8d. **检查每个 @NoAuth 入口是否完成了 §2.2.2 的 source-first 4 层展开**：

   逐项检查 call_graphs.md 中每个 @NoAuth 入口的记录：
   - 是否有 Layer 1-4 的展开记录？
   - 是否枚举了工厂/策略模式的所有具体实现分支（§1.3.5）？
   - 排除结论是否满足三项排除条件（4层无 sink + 所有分支已枚举 + source 不可控）？

   **以下情况 verdict 必须为 LOOP**：
   - 某 @NoAuth 入口的 call_graphs.md 记录仅有"接口层无 sink"结论，无 4 层展开记录
   - 某 @NoAuth 入口触达工厂/策略分发，但未枚举全部具体实现类（仅分析了部分分支）
   - call_graphs.md 中存在形如 `→ IConnector.authenticateUser() → none reaches sink` 的截断记录（在接口层停止，没有进入具体实现）

## 反向攻击面验证（MANDATORY）

9. 从漏洞函数出发反向追踪，验证其是否真正位于免认证/可达路径上。

## 认证管线独立验证（MANDATORY — Pre-auth 类漏洞候选）

9a. **对每个声称 pre-auth 可达的候选漏洞，Challenge Agent 必须独立执行认证管线验证**：

   1. **读取请求分发主循环代码**：从 accept()/recv() 到 handler 调用，逐行阅读
   2. **识别 handler 调用前的所有函数调用**：不仅限于名称含 `auth` 的函数——路由解析/填充函数内部也可能包含认证逻辑
   3. **对每个函数调用检查**：若该函数返回错误值（NULL/0/负数），主循环是否终止请求？
   4. **交叉验证 `call_graphs.md` 中的认证管线图**：
      - 认证管线图是否完整列出了所有检查层？
      - 路由认证状态表中该路由的每一层结果是否正确？
      - 是否存在遗漏的检查层？
   5. **若发现以下任一情况，verdict 必须为 LOOP**：
      - 报告声称 pre-auth 可达，但 `call_graphs.md` 中缺少认证管线图
      - 认证管线图遗漏了某个检查层（主循环中存在函数调用但未被记录）
      - 某一层的返回值处理被遗漏或分析错误（如函数返回 NULL 导致 404 但报告中未提及）
      - 路由认证状态表中该路由的某一层标注为"跳过"但实际上该层会阻断请求

   **失败教训**：Archer C50 案例中，分析仅发现 `strstr(url, "/cgi")` 跳过了 Layer B（`http_author_hasAuthor`），就判定 pre-auth 可达。但 Layer A（`http_alias_fillTarget`）在 Layer B 之前执行，对未登录用户会做白名单过滤——`/cgi/softup` 不在白名单中，函数返回 NULL，主循环随即返回 404。分析完全遗漏了 Layer A 的阻断作用。

## 认证前高危漏洞类型核查（MANDATORY — 认证前RCE）

10a. **CONDITIONAL 入口的认证绕过可行性是否被评估？**
    - 检查所有 `preauth_reachable=CONDITIONAL` 的入口，是否在 `call_graphs.md` 或 `vuln_hunt_output.md` 中有对应的认证绕过可行性分析
    - 检查绕过条件是否明确描述（不能是"可能可以绕过"，必须是"具体参数X=Y时绕过认证函数Z"）
    - **若 CONDITIONAL 入口超过 2 个但无任何认证绕过可行性分析记录，verdict 必须为 LOOP**

10b. **认证绕过候选是否被错误排除？**
    - 检查所有被排除的候选漏洞，若排除理由是"无 exec sink"或"不是直接 RCE"：
      - 该候选是否满足 Auth Bypass / 任意文件读取 / 任意文件写入的 PASS 条件？
      - **若满足任一 Tier 2 sink 定义（见 `strategies/preauth_rce.md`），该排除无效，verdict 必须为 LOOP**

## 组合链完整性审计（MANDATORY — 认证前RCE）

10c. **已发现漏洞原语的组合利用是否被充分评估？**
    - 检查 `vuln_hunt_output.md` 中是否有 `## 组合链评估` 章节
    - 对每个已发现的前台漏洞原语（SQLi、文件读取、SSRF 等），检查是否完成了 §2.8 的四条路径评估（路径 A/B/C/D）
    - **若存在已发现的前台漏洞原语但未做组合链评估，verdict 必须为 LOOP**
    - **若组合链评估中仅尝试了直接 RCE（如 INTO OUTFILE）就放弃，未评估 Auth Bypass 路径（路径 D），verdict 必须为 LOOP**

11. **认证流程分析是否完整？**
    - 检查 `attack-surface.md` 中是否有 `## 认证流程分析` 章节
    - 检查认证后高危功能清单是否完整（至少覆盖：文件上传、模板编辑、插件安装、命令执行、数据库管理）
    - **若认证流程分析缺失且目标为 Web 应用，verdict 必须为 LOOP**

## 目标适配检查（按条件执行）

12. **函数展开深度审计**（仅 binary targets）：检查子调用树是否达到 3 层深度。
13. **子系统覆盖检查**（仅 large binary targets）：所有预认证子系统是否已分析。
14. **内存破坏原语检查**（仅 C/C++ binary targets）：格式化字符串/堆分配写入一致性。
15. **Pre-auth 全覆盖检查**（仅认证绕过类型）：所有预认证入口点是否已分析。

## Challenge Agent 派发规则（MANDATORY）

14. **必须用 Task 工具派发独立 Challenge Worker**，严禁由编排器内联执行本 Phase。
    - 内联执行会继承 Phase 1-3 的分析偏见，破坏对抗性独立性，等效于"自己检查自己的作业"。
    - 派发方法：用 Task 工具发送如下结构的消息（详见 `references/agent_templates.md` 的 Adversarial Challenge Agent Template Task 版）：

    ```
    你是独立对抗性审查 worker（Challenge Agent）。你不孤单，编排器在等待你的结论，但你必须独立工作，不依赖 Phase 2/3 的中间推理过程。
    你的职责：对以下候选漏洞发现做对抗性验证，写入 challenge_verdict.md。

    [输入：attack-surface.md 全文 + vuln_hunt_output.md 全文，禁止附上 Phase 2 的分析思路]

    完成后汇报：写入 challenge_verdict.md，最后一行必须为 overall_verdict: PASS 或 overall_verdict: LOOP
    ```

15. 使用 `references/agent_templates.md` 中的 **Adversarial Challenge Agent Template（Task 版）**。
16. Challenge Worker 仅接收：(a) 候选漏洞报告（vuln_hunt_output.md）；(b) 权限架构表；(c) 攻击面列表（attack-surface.md）。**禁止传入 Phase 2 的中间推理过程。**

## Verdict 规则

17. Output only one verdict: `PASS` or `LOOP`. **MANDATORY FORMAT**: The final line of `challenge_verdict.md` MUST be exactly:
    ```
    overall_verdict: PASS
    ```
    or
    ```
    overall_verdict: LOOP
    ```
    This is the machine-readable field parsed by the orchestrator. Writing only `verdict: LOOP` or burying PASS/LOOP in prose text will cause the orchestrator to misread the result.
18. `PASS` condition: ALL of the following must be true:
    - 存在匹配目标漏洞类型的高置信发现（Pre-auth RCE 类型下，以下任一即满足）：
      - Pre-auth 可达的 exec/system/popen sink，source 可控
      - Pre-auth 可达的认证绕过（Auth Bypass），绕过条件攻击者可控
      - Pre-auth 可达的任意文件读取，能读取敏感文件（密钥/密码/shadow）
      - Pre-auth 可达的任意文件写入，能写入 webshell 或可执行路径
      - 上述任意组合链，端到端可行
    - 所有 P0 攻击面已被充分分析（`coverage_pct` 100% 或所有 pending 入口已给出明确无法分析的原因）
    - 无有意义的遗漏 source->sink 路径
    - 无被不当降级的候选漏洞（特别检查：未因"无 exec sink"而错误排除 Auth Bypass 候选）
    - 反向攻击面验证通过
19. `LOOP` condition: ANY of the following:
    - 置信度不足、存在遗漏路径、漏洞分类错误、被降级候选可能是真正的主要发现、P0 覆盖率 < 100%、反向验证失败
20. If verdict is `LOOP`, MUST update next-round directives in `context_snapshot.json` before continuing.
21. LOOP 后不得以任何理由终止审计流程。

## Context Snapshot 生成（MANDATORY — 每轮结束时）

22. 在 verdict 输出后生成/更新 `context_snapshot.json`。结构参见 `references/snapshot_schema.md`。
23. 每个候选（active/excluded/verified）须包含 `influencing_memory_ids` 字段。
24. **`next_round_directive.phase2_sections_to_execute` 填写规则（MANDATORY — verdict=LOOP 时）**：

    根据本轮 LOOP 原因，精准填写下一轮 Phase 2 需要执行的章节编号列表，**不填写本轮已充分执行且无新发现的章节**：

    | LOOP 原因 | 建议填写的章节 |
    |-----------|-------------|
    | 某 @NoAuth 入口未完成 4 层展开 | `["2.2.2"]` |
    | 发现前台漏洞原语但未做组合链评估 | `["2.8"]` |
    | 路径上防护机制未分析 | `["2.6.5"]` |
    | 新发现 pending P0 攻击面需要完整分析 | `["2.2.1", "2.2.2", "2.7"]` |
    | 工厂/策略模式分支未枚举完 | `["2.2.1", "2.2.2"]` |
    | 主假设被推翻，需要重新建立 | `[]`（空 = 执行完整 Phase 2） |

    **空数组或字段缺失 = 下一轮执行完整 Phase 2**（适用于首轮或需要全面重新审查的情况）。

    verdict=PASS 时此字段无意义，可省略或填 `[]`。

## 记忆反馈循环（由外部编排器自动执行）

| 条件 | 操作 | 幅度 |
|------|------|------|
| verdict=PASS | applied_memory_ids confidence 提升 | +0.05 |
| verdict=LOOP | applied_memory_ids confidence 提升 | +0.02 |
| verdict=LOOP 且候选被排除 | influencing_memory_ids confidence 降低 | -0.03 |
| 时间衰减 | 每 7 天未被访问 | -0.01 |

此机制由编排器自动完成，主代理（编排器）的职责是填写 `influencing_memory_ids`。

## MD 文件滚动压缩规则（Phase 4 结束时、snapshot 生成之前执行）

| 文件 | 阈值 | 压缩操作 |
|------|------|---------|
| `vuln_hunt_output.md` | > 80KB | 归档 current_round - 5 之前的已排除候选 |
| `call_graphs.md` | > 80KB | 归档已排除候选相关的函数树 |
| `challenge_verdict.md` | > 50KB | 归档 current_round - 3 之前的 verdict |
| `attack-surface.md` | > 100KB | 归档 P2 优先级和 excluded 条目 |
