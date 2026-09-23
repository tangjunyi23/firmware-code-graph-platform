# Phase 3: Verification

1. 对每个候选漏洞进行验证，使用 `references/agent_templates.md` 中的模板。
2. 验证需包含：
   - 验证步骤（verification_steps）
   - 具体证据（evidence）—— 必须引用代码行
   - PoC 概念（poc）
   - 影响评估（impact）
   - 置信度（confidence）
3. **端到端利用链验证（MANDATORY）**：
   - **Source 可控性确认**：重新验证 source 可控性等级，排除硬编码常量和需高权限前提的 source
   - **认证前提确认**：明确该漏洞入口需要的最低权限（未认证/低权限用户/管理员）
   - **落地效果确认**：对文件上传/写入类漏洞，必须验证落地路径在默认部署下是否可访问；对命令注入类，验证执行结果是否可观测
   - **默认配置假设**：除非有明确证据，一律假设目标使用默认配置
   - **认证链完整性校验（MANDATORY — Pre-auth 类漏洞）**：
     - 从网络入口（accept/recv）开始，逐行跟踪到 handler 被调用的位置
     - 列出路径上的**每一个条件分支和函数调用**，对照 `call_graphs.md` 中的认证管线图
     - 对每个认证检查层，确认该路由是否能通过（不仅检查"是否跳过了某层"，还要检查"前置层是否已阻断"）
     - **必须验证的项目**：
       - 路由解析/填充函数的返回值：返回 NULL/错误时主循环是否终止请求？
       - 白名单/黑名单过滤：目标路由是否在白名单中？
       - Session/cookie 检查：未携带 session 时请求是否被拒绝？
     - **禁止行为**：
       - 禁止仅凭"跳过了函数 X"就判定认证绕过——必须确认函数 X 是请求路径上的**唯一**认证检查点
       - 禁止忽略路由解析函数的返回值处理（如返回 NULL → 主循环返回 404 终止请求）
       - 禁止在未读取主循环完整代码的情况下做出 pre-auth 可达性判断
   - **组合链验证（MANDATORY — 当 Phase 2 §2.8 产出了组合链候选时）**：
     - 验证 Auth Bypass 步骤的每个前提条件（密码哈希算法强度、session 存储机制、凭据表结构）
     - 验证 Post-auth RCE 步骤的实际可行性（上传过滤是否可绕过、模板是否支持代码执行、插件签名是否强制）
     - 组合链中的每一步都必须有代码证据支撑，不允许假设性推理
     - **组合链的 exploitability 取各步骤中最弱一环**：Auth Bypass=CONFIRMED + Post-auth RCE=CONFIRMED → 组合链=CONFIRMED；任一步骤=CONDITIONAL → 组合链=CONDITIONAL
     - 组合链类型的候选漏洞，在 `vuln_hunt_output.md` 中须标注 `chain_type: combo` 和完整的多步利用链
4. **排除理由覆盖范围检查（MANDATORY — 当候选包含多个子机制时）**

   当排除理由基于外部防护（proxy header strip、WAF 规则、IP 白名单等），必须验证该防护覆盖候选中的**每一个**子机制：

   - 若候选包含 N 个 preauth header，排除证据必须分别覆盖全部 N 个 header（逐个给出 strip 规则引用）
   - 若候选包含 M 条认证路径，排除证据必须封堵全部 M 条路径
   - **部分覆盖 ≠ 完全排除**：未被覆盖的子机制必须拆分为新的独立候选，标记为 `active`
   - **禁止行为**：禁止因同一 `compositeFilter`/`FilterChain` 中的部分 filter 被防护就排除整个 filter chain——每个 filter 的防护状态必须独立验证

   **失败教训**：Nutanix CVM 案例中，5 个 preauth filter 被归为一个候选排除，但实际只有 2 个 header 被 proxy strip，剩余 3 个未被 strip 的 filter（包括 `vmAuthFilter` 处理 `X-Nutanix-GuestVM-Preauth`）构成有效认证绕过。

5. 当记忆条目较多时，输出需包含 `memory_snapshot_id` 和 `applied_memory_ids`；当记忆条目较少（<20条）时，这些字段为可选。
5. 将验证过程中获得的新洞察（抽象的、不含具体函数名/地址的模式）总结后追加到 `~/.zcode/memory/vuln-hunt/insights.jsonl`。
