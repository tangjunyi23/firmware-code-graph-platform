# Phase 4: Challenge Agent（固件二进制域改写版）

> **改写说明（2026-08-15）**：原文档来自 Web/Java 源码审计项目，以下检查项对本
> 固件二进制域（fwgraph 平台：IDA 伪代码 + 攻击面图 + qemu-user 覆盖trace）不适用，
> 已删除或改写：
> - **8a 注入类型覆盖检查**（LDAP/NoSQL/SSTI/EL 依赖库→攻击面映射）：固件侧无此
>   依赖生态，改写为「服务/协议输入覆盖 + 危险 sink 穷尽检查」。
> - **8d @NoAuth 入口 source-first 4 层展开**（Java 注解驱动路由 + 工厂/策略模式
>   分支枚举）：固件侧入口是 C 函数指针表/opcode 分发，改写为「预认证入口
>   source→sink 逐跳展开检查」。
> - **10c SQLi 组合链四路径**（INTO OUTFILE / Auth Bypass 路径 D 等）：SQLi 在固件
>   Web 服务中极少见，改写为「固件漏洞原语组合链」通用检查。
> - **11 Web 应用认证流程分析**（模板编辑/插件安装/数据库管理清单）：改写为
>   AS-AUTH 授权链文档与认证后高危功能（固件升级/配置恢复/诊断命令）覆盖检查。
> - **14 派发规则中的 Task 工具**：本 harness 无 Task 工具，由 playbook driver 以
>   全新 Session 实现同等隔离（不携带 Phase 1-3 消息历史）。
> 保留并对齐固件域的对抗框架：三问、根因/主次/完整性/隐藏漏洞检查、降级候选
> 重审、子机制拆分、覆盖率审计、认证管线独立验证、反向验证、verdict 末行契约。

1. Use a challenge perspective to stress-test current conclusions.
2. Must explicitly answer all three questions:
   - **是否找到了匹配目标漏洞类型的高置信漏洞？**（Pre-auth RCE 类型下，认证绕过/任意文件读取/任意文件写入均属于匹配范围，参见 `strategies/preauth_rce.md` 认证前高危漏洞类型表）
   - **是否有未分析的 source->sink 路径？**
   - **漏洞分类是否正确？**

## 核心检查（每轮必执行）

3. **根因函数检查**：报告的漏洞函数是否为真正的根因函数？（伪代码里真正的拷贝/拼接点，而不是外层 wrapper；必要时 fw_get_function_source asm=true 核对）
4. **主次优先级检查**：是否把利用链路更复杂/更隐蔽的那个标为主要发现？
5. **完整性检查**：是否有仅做上界检查但缺少下界检查的情况？（固件常见：`len > sizeof(buf)` 查了上界，`len < 0` 符号性问题/下溢没查）
6. **隐藏漏洞检查**：是否存在弱比较（strncmp 长度可控、前缀匹配当认证）、过滤顺序可绕过、运算符优先级错误、循环计数器 off-by-one 等被遗漏？

## 被降级候选重新审视（MANDATORY）

7. 列出所有被降级为 Medium 或排除的候选漏洞，对每个重新评估降级理由是否充分。
   - **如果被降级候选的漏洞模式更经典，verdict 必须为 LOOP**。

7a. **排除候选的子机制拆分检查（MANDATORY）**：
    - 对每个被排除的候选，检查其是否包含多个**独立的**攻击子机制（如同一服务的多个 preauth header、多条 opcode 分发路径、多个解析器入口、同一 CGI 的多个参数载体）
    - 若排除证据只覆盖了部分子机制（如只验证了 5 个可疑参数中的 2 个不可控），**verdict 必须为 LOOP**
    - LOOP 时指示下一轮：**将未被排除证据覆盖的子机制拆分为独立候选重新评估**
    - **检查方法**：
      1. 找到候选排除理由引用的防护证据（如某 dispatch 表项前置校验）
      2. 用 fw_get_surface 的 carrier_bindings / fw_dangerous_callsites 枚举全部子机制
      3. 逐一比对：每个子机制是否都有对应的防护/不可控证据？
      4. 若存在无证据覆盖的子机制 → verdict=LOOP

## 攻击面覆盖率审计（MANDATORY）

8. 回顾 attack-surface.md，逐项检查每个 P0 攻击面是否已被充分分析。
   - **覆盖率 < 100% 时 verdict 必须为 LOOP**。

## 输入面与 sink 穷尽检查（MANDATORY）

8a. **外部输入覆盖检查**：对照 fw_get_identification 的 IN-xxx 清单：
   - 每个公网输入（HTTP/UPnP/HNAP/TR-069/自定义二进制协议/厂商私有端口）是否都有对应攻击面分析记录？
   - 若某 IN-xxx 完全未出现在 attack-surface.md → **verdict 必须为 LOOP**。
8a'. **危险 sink 穷尽检查**：fw_dangerous_callsites 对 strcpy/strcat/sprintf/vsprintf/system/popen/printf 族的调用点清单，是否都被排查或给出不查理由？
   - 主要发现集中在单一 sink 类型而其余类型零分析 → **verdict 必须为 LOOP**。

## 测试/调试残余可达性检查（MANDATORY）

8b. **主要发现生产可达性验证**：固件解包中常混入测试/调试残余（`test_*` 二进制、factory 测试接口、diags 诊断命令、厂商 SDK demo）。检查主要发现引用的二进制路径与路由：
   - 若证据位于测试/调试组件，且无任何运行时证据（trace/默认配置加载）表明其在出厂配置中启用，**verdict 必须为 LOOP**；
   - LOOP 时指示下一轮：**转向出厂配置可达的同类组件**，测试残余中的发现可在附录提及但不得作为主要结论。
   - **红队原则**：默认不启用的调试接口不构成远程可利用攻击面（除非能证明出厂启用）。

## 已知漏洞排除检查（CONDITIONAL — 编排器传入排除列表时执行）

8c. 若编排器在 prompt 中注入了 `## 已知漏洞排除（MANDATORY）` 段落：
   - 检查 FINAL.md 中的主要发现是否与排除列表中的漏洞描述重叠
   - 若重叠，**verdict 必须为 LOOP**，并在 challenge_verdict.md 中指示：**排除该已知漏洞，转向其他攻击面探索**
   - 允许在报告中附带提及已知漏洞作为交叉验证，但不得作为主要发现

## 预认证入口 source→sink 展开审计（MANDATORY — 认证前RCE 类）

8d. **检查每个判定为预认证可达的入口是否完成 source→sink 逐跳展开**：

   逐项检查 attack-surface.md / vuln_hunt_output.md 中每个预认证入口的记录：
   - 是否有从 listen/accept/recv 到 final_handler 的逐跳链路（fw_get_surface 的 routing_path + fw_call_trace 验证）？
   - opcode/函数指针表分发（固件常见：dispatch table、register callback）是否枚举了全部分支？
   - 排除结论是否满足三项排除条件（链路穷尽 + 所有分支已枚举 + 载体不可控有伪代码证据）？

   **以下情况 verdict 必须为 LOOP**：
   - 某预认证入口仅有"解析层无 sink"结论，无逐跳链路记录
   - 分发表只分析了部分分支就整体排除
   - 链路在中间层截断（如 `→ dispatch_handler() → none reaches sink`，没有进入具体 handler）

## 反向攻击面验证（MANDATORY）

9. 从漏洞函数出发反向追踪（fw_call_trace inbound），验证其是否真正位于免认证/可达路径上。

## 认证管线独立验证（MANDATORY — Pre-auth 类漏洞候选）

9a. **对每个声称 pre-auth 可达的候选漏洞，Challenge Agent 必须独立执行认证管线验证**：

   1. **读取请求分发主循环伪代码**：从 accept()/recv() 到 handler 调用，逐行阅读（fw_get_function_source）
   2. **识别 handler 调用前的所有函数调用**：不仅限于名称含 `auth` 的函数——路由解析/别名填充/URL normalize 函数内部也可能包含认证逻辑
   3. **对每个函数调用检查**：若该函数返回错误值（NULL/0/负数），主循环是否终止请求？
   4. **交叉验证攻击面文档中的授权链引用（AS-AUTH）**：
      - 授权链是否完整列出了所有检查层？
      - 该路由每一层的结果（放行/阻断/跳过）是否正确？
      - 是否存在遗漏的检查层？
   5. **若发现以下任一情况，verdict 必须为 LOOP**：
      - 报告声称 pre-auth 可达，但缺少认证管线分析
      - 认证管线遗漏了某个检查层（主循环中存在函数调用但未被记录）
      - 某一层的返回值处理被遗漏或分析错误（如函数返回 NULL 导致 404 但报告中未提及）
      - 某一层标注为"跳过"但实际上该层会阻断请求

   **失败教训**：Archer C50 案例中，分析仅发现 `strstr(url, "/cgi")` 跳过了 Layer B（`http_author_hasAuthor`），就判定 pre-auth 可达。但 Layer A（`http_alias_fillTarget`）在 Layer B 之前执行，对未登录用户会做白名单过滤——`/cgi/softup` 不在白名单中，函数返回 NULL，主循环随即返回 404。分析完全遗漏了 Layer A 的阻断作用。

## 认证前高危漏洞类型核查（MANDATORY — 认证前RCE）

10a. **CONDITIONAL 入口的认证绕过可行性是否被评估？**
    - 检查所有 `preauth_reachable=CONDITIONAL` 的入口，是否有对应的认证绕过可行性分析
    - 绕过条件必须具体（"参数 X=Y 时校验函数 Z 提前返回 1"），不能是"可能可以绕过"
    - **若 CONDITIONAL 入口超过 2 个但无任何绕过可行性分析记录，verdict 必须为 LOOP**

10b. **认证绕过候选是否被错误排除？**
    - 检查所有被排除的候选漏洞，若排除理由是"无 exec sink"或"不是直接 RCE"：
      - 该候选是否满足 Auth Bypass / 任意文件读取 / 任意文件写入的 PASS 条件？
      - **若满足任一 Tier 2 sink 定义（见 `strategies/preauth_rce.md`），该排除无效，verdict 必须为 LOOP**

## 组合链完整性审计（MANDATORY — 认证前RCE）

10c. **已发现漏洞原语的组合利用是否被充分评估？**（固件域常见组合）
    - 信息泄露（配置/密钥/shadow 读取）+ 内存破坏 → 绕过地址随机化完成 RCE
    - 认证绕过 + 认证后命令注入/固件升级写入 → 预认证 RCE
    - 任意文件写入 + 配置解析重启加载（如写 nvram/uci/cron）→ 持久化执行
    - **若存在已发现的前台漏洞原语但未做组合链评估，verdict 必须为 LOOP**
    - **若组合链评估只尝试了单步直接 RCE 就放弃，未评估上述组合路径，verdict 必须为 LOOP**

## 授权链与认证后功能覆盖检查（MANDATORY — 固件 Web 管理面）

11. **AS-AUTH 授权链分析是否完整？**
    - attack-surface.md 是否覆盖了所有 AS-AUTH 文档引用的授权链？
    - 认证后高危功能清单是否完整（至少覆盖：固件升级、配置备份/恢复、诊断/ping 命令、文件上传、服务开关）？
    - **若目标含 Web 管理面而授权链分析缺失，verdict 必须为 LOOP**

## 目标适配检查（按条件执行）

12. **函数展开深度审计**（仅 binary targets）：检查子调用树是否达到 3 层深度。
13. **子系统覆盖检查**（仅 large binary targets）：所有预认证子系统是否已分析。
14. **内存破坏原语检查**（仅 C/C++ binary targets）：格式化字符串/堆分配写入一致性。
15. **Pre-auth 全覆盖检查**（仅认证绕过类型）：所有预认证入口点是否已分析。

## Challenge 独立性（由 playbook driver 保证）

16. 本 Phase 由 playbook driver 以**全新 Session** 执行（本 harness 无 Task 工具）：
    Challenge 会话的消息历史只含 attack-surface.md 与 vuln_hunt_output.md 的结论
    文本，**严禁携带 Phase 1-3 的会话上下文**——内联续跑会继承分析偏见，
    等效于"自己检查自己的作业"。

## Verdict 规则

17. Output only one verdict: `PASS` or `LOOP`. **MANDATORY FORMAT**: 输出的最后一行必须是（driver 按最后一行精确匹配解析，写在正文里会被误判为 LOOP）：
    ```
    overall_verdict: PASS
    ```
    or
    ```
    overall_verdict: LOOP
    ```
18. `PASS` condition: ALL of the following must be true:
    - 存在匹配目标漏洞类型的高置信发现（Pre-auth RCE 类型下，以下任一即满足）：
      - Pre-auth 可达的 exec/system/popen sink，source 可控
      - Pre-auth 可达的认证绕过（Auth Bypass），绕过条件攻击者可控
      - Pre-auth 可达的任意文件读取，能读取敏感文件（密钥/密码/shadow）
      - Pre-auth 可达的任意文件写入，能写入可执行路径或配置加载路径
      - 上述任意组合链，端到端可行
    - 所有 P0 攻击面已被充分分析（`coverage_pct` 100% 或所有 pending 入口已给出明确无法分析的原因）
    - 无有意义的遗漏 source->sink 路径
    - 无被不当降级的候选漏洞（特别检查：未因"无 exec sink"而错误排除 Auth Bypass 候选）
    - 反向攻击面验证通过
19. `LOOP` condition: ANY of the following:
    - 置信度不足、存在遗漏路径、漏洞分类错误、被降级候选可能是真正的主要发现、P0 覆盖率 < 100%、反向验证失败
20. If verdict is `LOOP`, MUST list the missed points for the next round before the verdict line.
21. LOOP 后不得以任何理由终止审计流程（driver 侧达到 maxRounds 的硬上限除外——
    该终局会在 FINAL.md 显著标注「未经对抗验证通过」，并给本轮 findings 打
    服务端 note）。

## Context Snapshot 生成（MANDATORY — 每轮结束时）

22. driver 在每轮结束时更新 `context_snapshot.json`（rounds/verdict/findings/retracted），结构参见 `references/snapshot_schema.md`。

## 记忆反馈循环（driver 自动执行）

| 条件 | 操作 | 幅度 |
|------|------|------|
| verdict=PASS | 本轮注入的 insight confidence 提升 | +0.05 |
| verdict=LOOP | 本轮注入的 insight confidence 降低 | -0.05 |
| clamp | 置信度始终限制在 [0.1, 0.95] | — |

此机制由 playbook driver 在 hunt 结束时对 memory/insights.jsonl 原子写回完成。

## MD 文件滚动压缩规则（Phase 4 结束时、snapshot 生成之前执行）

| 文件 | 阈值 | 压缩操作 |
|------|------|---------|
| `vuln_hunt_output.md` | > 80KB | 归档 current_round - 5 之前的已排除候选 |
| `call_graphs.md` | > 80KB | 归档已排除候选相关的函数树 |
| `challenge_verdict.md` | > 50KB | 归档 current_round - 3 之前的 verdict |
| `attack-surface.md` | > 100KB | 归档 P2 优先级和 excluded 条目 |
