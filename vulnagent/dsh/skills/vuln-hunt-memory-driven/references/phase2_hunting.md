# Phase 2: Vulnerability Hunting

## 执行流程概览（每轮开始前必读）

> **Round 2+ 精准模式**：Phase 0.5 恢复 snapshot 后，若 `phase2_active_sections`（来自 `next_round_directive.phase2_sections_to_execute`）非空，**只执行该列表中的章节编号对应的节**，其余章节跳过。Round 1 或列表为空时按完整流程执行。
>
> 精准模式下，§2.1（漏洞类型适配）和 §2.3/§2.4/§2.6（精确定位/排序/输出）**始终执行**，不受列表约束，因为它们是每轮必要的框架步骤。受列表约束的是中间的分析章节（§2.1.5 至 §2.8）。

### 主流程（每轮必执行，顺序不可颠倒）

```
1. §2.1    漏洞类型适配（读策略文件）
2. §2.1.5  漏洞原语识别          [ALWAYS]
3. §2.1.6  Source 可控性验证      [ALWAYS]
4. §2.1.7  认证逻辑弱点优先扫描   [认证前RCE / Web 应用 / HTTP 服务]  ← 必须在 sink 分析前执行
5. §2.2    子函数递归展开          [binary targets only]
6. §2.2.1  Source->Sink 路径分析  [ALWAYS]
7. §2.2.2  @NoAuth source-first 展开  [认证前RCE / Web 应用]
7. §2.3    精确定位
8. §2.4    多漏洞优先级排序
9. §2.6    输出
```

### 插入规则（满足触发条件时执行，不满足则跳过）

```
§2.6.5  防护机制绕过分析   → 触发条件：路径上存在安全防护时
§2.7    替代假设生成       → 触发条件：产出候选漏洞后、进入验证前（ALWAYS）
§2.8    漏洞组合链升级评估  → 触发条件：发现任何前台漏洞原语时
```

### MANDATORY 分级说明

本文件中 MANDATORY 标记分两档：
- **`[ALWAYS]`**：每轮每个目标必执行，无条件
- **`[WHEN: <条件>]`**：仅满足括号内条件时执行，其余情况跳过

标题中注明了 `MANDATORY` 但无条件说明的，视为 `[ALWAYS]`。

---

## 2.0 并行子代理分析 [MANDATORY — P0 ≥ 1 时]

**编排器必须用 Task 工具派发 worker，不得自己内联执行各 P0 surface 分析。**

每个 P0 攻击面独立派发一个 Task worker（并行启动）：

1. **Task 消息格式**：使用 `references/agent_templates.md` 中的 **Parallel Surface Analysis Template（Task 版）**
2. **拆分策略**：每个 worker 负责 1 个 P0 攻击面的完整 source->sink 分析；surface 超过 6 个时可合并为 1-2 个/worker
3. **输出约定**：每个 worker 写入 `phase2_surface_<surface_id>.json`，编排器不写此文件
4. **汇总规则**：
   - 所有 worker 完成后，编排器读取所有 `phase2_surface_*.json`
   - 按 §2.4 排序规则统一排序，合并去重
   - 不同 worker 发现的同一 sink 的不同路径必须交叉比对
5. **覆盖率保证**：汇总后检查每个 P0 surface 是否有对应 worker 结果，无遗漏方可进入 Phase 3

**触发检查**：若 P0 攻击面数 = 0，跳过 §2.0，直接进入 §2.1（漏洞类型适配）后自行执行全局扫描

## 2.1 漏洞类型适配

**必须首先查阅 `references/strategies/` 目录下对应漏洞类型的策略文件**，获取该类型的 Sources、Sinks、Key Check 和 Common Patterns。

策略文件命名约定：`references/strategies/<type>.md`，type 对应漏洞类型英文缩写（bof/sqli/intov/authbypass/cmdi/fmtstr/preauth_rce/pathtrv/fileread/filewrite/upload/deser/memov）。

## 2.1.5 漏洞原语识别（MANDATORY — ALWAYS）

在进入 source->sink 路径分析前，必须先识别代码中是否存在构成漏洞的基本原语（primitive）：

1. **路径穿越原语**：路径拼接是否使用用户可控输入且无 `../` 过滤或 realpath 规范化？
2. **认证旁路原语**：是否存在 `policy=0` / 免认证标记的命令可直接执行敏感操作？安全检查函数是否可被特定参数值短路？
3. **内存安全原语**：是否存在用户可控长度直接用于 memcpy/malloc 且无上界约束？算术表达式是否存在溢出/下溢？类型转换链路中是否存在截断？
4. **注入原语**：用户输入是否直接参与字符串拼接后进入解释器/执行器？过滤/转义是否完整？
5. **格式化字符串原语**：snprintf/sprintf/fprintf/syslog 等函数的格式化参数（fmt）是否来自用户可控输入？关键区分：`snprintf(buf, sz, user_str)` 是漏洞，`snprintf(buf, sz, "%s", user_str)` 不是。

**关键规则**：漏洞原语的存在是候选漏洞成立的前提。如果在某条 source->sink 路径上找到了 sink 但没有识别到对应的漏洞原语，该路径的优先级应降低。

## 2.1.6 Source 可控性验证（MANDATORY — ALWAYS）

在构建 source->sink 路径前，必须对每个 source 验证其实际可控性：

1. **直接可控**：数据直接来自未认证的外部请求参数——高置信 source
2. **间接可控**：数据来自需要认证的接口、配置文件——条件性 source，必须标注前提条件
3. **不可控**：数据为代码中硬编码的常量、服务端内部生成的随机值——排除或标记为需供应链攻击

**关键判定**：对 URL、路径、配置值等 source，必须查看其赋值来源。若为字面量字符串常量，则不可控；若从用户请求中解析，则可控。不得仅因"代码中存在该变量"就假设可控。

## 2.1.7 认证逻辑弱点优先扫描（MANDATORY — WHEN: 认证前RCE / Web 应用 / HTTP 服务）

**此步骤必须在 source->sink 路径分析（§2.2.1）之前执行。** 现代软件中认证前直接 exec/deser sink 极为罕见，大多数可利用漏洞来自认证逻辑本身的弱点。**禁止跳过此步骤直接寻找 exec sink。**

按以下顺序逐项检查，发现任意一项即记录为候选漏洞：

1. **硬编码密钥/凭据扫描**：
   - 搜索认证相关函数中的字符串常量（密钥、密码、token、secret）
   - 检查加密/签名函数的密钥来源：是否从配置读取？若为代码内字面量 → 记录为 CAND
   - 检查默认凭据：初始化代码、配置模板、安装脚本中是否有默认密码

2. **认证短路/绕过扫描**：
   - 认证检查函数的返回值是否在所有调用点都被正确处理？
   - 是否存在 URL pattern / 参数值可使认证函数短路（如 `strstr(url, "/public")` 跳过 auth）？
   - 是否存在多套认证路径（web 端 + API 端 + 管理端），各路径认证强度是否一致？

3. **Token/Session 可预测性扫描**：
   - session / token 的生成算法是否可预测或基于可控输入（MD5(user_input)、时间戳）？
   - JWT/cookie 签名密钥是否硬编码或可推导？

4. **Pre-auth 信息泄露扫描**：
   - 未认证端点的错误响应是否泄露内部路径、版本、凭据、密钥？
   - 调试接口、状态接口、健康检查接口是否在认证前可达且返回敏感信息？

**输出规则**：
- 发现任意一项 → 立即记录为 CAND，标注 `tier: 1`，**不等待 source->sink 分析完成**
- 若以上 4 项均无发现，在 `vuln_hunt_output.md` 中明确记录"§2.1.7 认证逻辑弱点扫描：无发现"，再继续 §2.2
- **每轮必须执行，不得跳过**（认证逻辑弱点是核心扫描目标，Round 2+ 同样执行）

## 2.2 子函数递归展开（MANDATORY — WHEN: binary/反编译目标）

对于反编译/二进制目标，handler 函数内部的子调用必须递归展开分析：

1. **最小展开深度**：从 handler 入口函数起，必须至少展开 3 层子调用。
2. **必须完整阅读的子函数类型**：参数名/调用上下文暗示数据解码/解析的函数、接受用户可控数据作为参数的函数、内部包含 malloc/calloc/realloc/memcpy/循环写入/格式化输出的函数。
3. **禁止推测性跳过**：不得因子函数"看起来只是工具函数"而跳过阅读。在反编译代码中，函数名不携带语义信息。
4. **展开记录**：在 call_graphs.md 中记录每个展开的函数及其关键逻辑摘要。

## 2.2.1 Source->Sink 路径分析（全路径覆盖）

1. 遵循 `must_apply` 记忆规则中匹配的漏洞模式。
2. **全路径枚举（MANDATORY）**：对每个 P0 攻击面，先枚举所有可能的 source->sink 路径，再逐条分析。
3. 对每条路径执行完整推理：识别 source 点 -> 追踪数据流到 sink 点 -> 评估中间防护 -> 判断 exploit 前提条件。
4. **备选路径不可省略**：多条到达同一 sink 的路径必须全部分析。
5. **Sink 内部分析（MANDATORY）**：不要将 sink 函数视为黑盒。如果实现代码可用，必须阅读其内部实现。对于二进制 sink，**"实现代码可用"的唯一合法形式是 IDA 反编译产物（`decompile/*.c`）**，不包括 strings 输出、objdump 反汇编或 hexdump。若 `decompile/` 不存在，必须先执行 §1.1.3 反编译流程，再继续分析。
6. 产出候选漏洞（证据、触发条件、利用思路、影响、置信度）。

## 2.2.2 @NoAuth / CONDITIONAL 入口 Source-First 强制深度追踪（MANDATORY — WHEN: 认证前RCE / Web 应用）

**此规则解决 sink-first 快筛的系统性盲区。** Phase 1 的 sink 关键词 grep 只能发现入口文件层可见的 sink；当 sink 藏在 4-5 层调用之下或工厂/策略模式的具体实现中时，快筛无法命中。

**核心原则**：入口的深度价值由 source-first 递归展开决定，不由入口层 grep 决定。**任何 @NoAuth 或 preauth_reachable=CONDITIONAL 入口不得仅凭 Phase 1 sink 快筛结果排除。**

### 执行条件

以下两类入口**均必须执行**本节分析：
1. **@NoAuth 入口**：Phase 1 判定 `preauth_reachable=YES` 的入口，无论 sink 快筛是否命中
2. **CONDITIONAL 入口**：Phase 1 判定 `preauth_reachable=CONDITIONAL` 的入口（即认证逻辑存在条件性绕过可能）——**这类入口优先级不低于 @NoAuth，因为认证绕过本身即是高危目标**

对于 CONDITIONAL 入口，source-first 展开需要额外执行：
- **认证绕过可行性分析**：识别使该入口绕过认证的具体条件（特定参数值/Header/请求序列）
- 若绕过条件可由攻击者控制 → 记录为 Auth Bypass CAND，`preauth_reachable` 升级为 `YES`

### 执行步骤

1. **从入口函数开始，强制展开至少 4 层子调用**
   - 对每层调用的被调函数，若其接受用户可控数据作为参数，必须读取其实现
   - 记录每一层展开的函数签名和关键逻辑

2. **工厂/注册表分支枚举（参照 §1.3.5）**
   - 遇到 `createConnector(type)` / `switch(type)` / `registry.get(type)` 时，枚举所有具体实现
   - 对每个具体实现类执行独立的 4 层展开

3. **在展开过程中实施双轨检测**

   **轨道 A（Sink-first）**：在每一层展开中，检测以下扩展 sink 列表：
   ```
   命令执行:    Runtime.exec / ProcessBuilder / system / popen
   反序列化:    readObject / ObjectInputStream / pickle.loads / yaml.load
   JNDI/类加载: InitialContext.lookup / InitialDirContext.search / URLClassLoader
   外向网络调用: new URL(*).openConnection / HttpClient / OkHttpClient / InetAddress.getByName
   EL/模板执行: parseExpression / Ognl.getValue / MVEL.eval / Template.process
   文件操作:    FileWriter / Files.write / new File(*).write
   ```

   **轨道 B（Source-first）**：同时追踪用户可控数据的流向：
   - 标记入口处的 source 变量（来自 request body / header / path param）
   - 在每层展开中追踪该变量（或其衍生值）的传递路径
   - 记录数据在每个函数边界的转换方式（解析 / 解码 / 提取字段）

4. **在 call_graphs.md 中记录每个 @NoAuth 入口的展开状态**
   ```
   [@NoAuth POST /xxx] source-first 展开（4层）
   ├── Layer 1: HandlerA.method(login) → 传递 login.getCert()
   ├── Layer 2: ServiceB.process(cert) → 传递 cert 到 CertValidator
   ├── Layer 3: CertValidator.verify(cert, skipExternal=false)
   │   └── [工厂分支枚举] ConnectorImpl1 / ConnectorImpl2 / ConnectorImpl3
   │       └── ConnectorImpl2.verify → getIntermediateCerts(cert)
   └── Layer 4: getIntermediateCerts → new InitialDirContext().search(url)  ⚠ JNDI Sink
   ```

5. **排除条件（必须同时满足）**
   - 完成 4 层展开后确认无任何 sink 命中（包括轨道 A 的扩展 sink 列表）
   - 所有工厂分支已枚举并独立分析
   - Source 数据在展开过程中确认不可控（硬编码 / 服务端生成）
   - 满足以上三项，才可在 call_graphs.md 中标记该入口为 `source-first 展开完成，无 sink`

### 覆盖率要求

- Phase 4 Challenge Agent 将检查：每个 @NoAuth 入口是否有对应的 source-first 展开记录（Layer 1-4）
- 若某 @NoAuth 入口仅有"无 sink 命中"结论而无 4 层展开记录 → verdict 必须为 LOOP

## 2.3 精确定位

**对于每个候选漏洞，必须定位到具体的漏洞根因函数名**。

**根因函数 vs 调用函数区分规则：**
- 漏洞根因函数 = **漏洞逻辑缺陷实际所在的函数**，而非仅仅调用了危险操作的上层函数。
- **判断标准**：修复漏洞时需要修改哪个函数的代码？那个函数就是根因函数。
- **特殊情况——入口函数中的算术/逻辑缺陷**：如果入口函数 A 中对输入数据的算术操作存在溢出，然后将有缺陷的结果传给函数 B 执行分配/拷贝，则 A 是根因函数。
- **特殊情况——sink 函数内部的独立缺陷**：如果通用库函数 B 内部存在独立于调用者的逻辑缺陷，则 B 是根因函数。

## 2.4 多漏洞优先级排序

1. **首选**与用户指定漏洞类型完全匹配的漏洞。
2. 在类型匹配的漏洞中，按**可利用性**排序：**防护绕过型** > **无防护型**；**非显而易见的逻辑缺陷** > **简单缺失校验**。
3. **若同一函数调用链上有多个漏洞点**，优先报告根因函数中的漏洞。
4. 非用户指定类型的漏洞可附带提及，但不能作为主要发现。

### 2.4.1 禁止草率降级候选漏洞

所有候选漏洞都必须进入 Phase 3 验证环节。不得以"上下文不足"、"需要更多信息"等理由在 Phase 2 中直接降级或排除。

### 2.4.2 分配/拷贝类漏洞的特殊排序规则

- **"固定大小缓冲区 + 外部可控长度拷贝"** 是最高优先的缓冲区溢出模式。
- **调用者函数中的长度/大小不一致**比被调用函数本身更可能是根因。

## 2.5 根因定位细化

- **"不足的检查"所在函数 vs "危险操作"所在函数**：沿数据流追踪，**第一个引入安全缺陷的函数**就是根因函数。
- **通用框架/库函数中的根因**：当 sink 是通用功能函数且内部存在设计缺陷时，该函数是根因。

## 2.6 输出
- 候选漏洞列表保存到 `vuln_hunt_output.md`
- 函数调用图保存到 `call_graphs.md`

## 2.6.5 防护机制绕过分析（MANDATORY — WHEN: source->sink 路径上存在安全防护）

**红队思维要求**：发现 source->sink 路径上存在安全防护时，红队分析师不会仅因"存在防护"就放弃——而是会尝试绕过。框架必须模拟这一行为。

当候选漏洞路径上存在防护机制（类型安全、框架过滤、白名单、ACL 等）时，**不得仅因"存在防护"就排除该路径**。必须执行以下分析后才能做出排除决定：

### 防护分析四步法（MANDATORY — 每个被防护阻断的路径）

1. **防护实现审计**：
   - 完整阅读防护函数/类型/中间件的源码实现
   - 检查是否存在边界情况：编码绕过（双重编码、Unicode 标准化、URL 编码）、竞态条件（TOCTOU）、类型转换绕过（implicit cast）、空值/默认值处理
   - 对框架内置防护：检查当前版本是否存在已知绕过（CVE/Issue）

2. **防护覆盖范围检查**：
   - 该防护是否覆盖了**所有**到达该 sink 的入口路径？
   - 是否存在不经过该防护的替代调用链？
   - 是否存在同一 sink 的不同调用者使用了不同的防护（或无防护）？

3. **防护层级一致性**：
   - 防护是在正确的层级执行的吗？（例如：路径穿越防护在 URL 层做但 sink 在文件系统层——中间可能有标准化差异）
   - 检查点（check point）和使用点（use point）之间是否有数据变换？

4. **结论输出**：
   在 `vuln_hunt_output.md` 中对每个被防护阻断的路径记录：
   ```
   ### 防护分析: <路径描述>
   - 防护机制: <名称和位置>
   - 防护实现: <关键代码摘要>
   - 绕过分析: 可绕过 / 不可绕过 / 需进一步验证
   - 绕过方法: <如果可绕过，描述方法>
   - 替代路径: <如果存在，描述替代路径>
   ```

### 禁止行为

- **禁止**仅因"框架类型安全"（如 Rust 的 `PathBuf`、Go 的 `filepath.Clean`、Java 的 `Path.normalize`）就跳过路径分析
- **禁止**仅因"存在输入过滤函数"就假设过滤完整
- **禁止**在 Phase 2 中以"防护存在"为由直接排除路径——排除必须经过上述四步分析后在 Phase 3 验证中执行
- **禁止**仅因接口需要认证就排除漏洞——红队会通过组合链（§2.8）先突破认证再利用后台漏洞

## 2.7 替代假设生成（MANDATORY — ALWAYS，在产出候选后、进入验证前执行）

在产出候选漏洞列表后、进入验证前，必须强制生成至少一个替代假设：

1. **当前主假设陈述**：明确写出当前排名第一的候选漏洞及其利用链
2. **替代假设生成**：考虑是否存在不需要前置步骤的直接路径、更短的利用链、更直接的输入点
3. **对比评估**：如果替代假设的漏洞原语更直接、利用条件更少，应替换主假设

**失败教训参考**：参见 `MEM-FAILURE-TUNNEL-VISION-01`——过早锁定单一攻击路径是最常见的误报根因。

## 2.8 漏洞组合链升级评估（MANDATORY — WHEN: 发现任何前台漏洞原语）

**此步骤解决的核心问题**：模型发现一个前台漏洞（如 SQLi）后，只尝试最直接的 RCE 路径（如 `INTO OUTFILE`），失败后就放弃该漏洞的利用价值，转而去找其他独立的 pre-auth RCE。这导致模型完全忽略了组合链攻击（如 SQLi → Auth Bypass → Post-auth RCE）。

**同时解决**：即使发现的漏洞类型不是 RCE（如认证绕过、任意文件读取），也必须评估其能否升级为 RCE 或构成独立 PASS 级漏洞。

### 触发条件

当 Phase 2 中发现了**任何以下情况之一**，都必须执行此步骤：
- 前台可达的漏洞原语（SQL 注入、任意文件读取/写入、SSRF、反序列化、信息泄露）
- **CONDITIONAL 入口存在可被攻击者控制的绕过条件**（即使尚未到达 exec sink）
- **认证逻辑存在逻辑缺陷**（返回值处理错误、参数短路、算法可预测）

### 评估流程（MANDATORY — 不可跳过任何子步骤）

对每个已发现的前台漏洞原语，**必须穷举**以下组合链路径：

#### 路径 A：漏洞 → 认证绕过 → 认证后 RCE

1. **该漏洞能否突破认证？**（结合 §1.4.5 认证流程分析）
   - SQLi → 读取管理员密码哈希 → 离线破解（MD5/SHA1 无盐 = 秒破，bcrypt = 不可行）
   - SQLi → UPDATE 修改管理员密码 → 直接登录
   - SQLi → 读取 session 表 → 伪造管理员 session
   - SQLi → 读取 `secret_key` / `app_key` → 伪造 signed cookie / JWT
   - 文件读取 → 配置文件中的数据库密码 → 连接数据库 → 修改管理员凭据
   - 文件读取 → 配置文件中的加密密钥 → 伪造认证 token
   - SSRF → 内网管理接口无认证 → 管理员操作

2. **突破认证后，哪些认证后功能可达 RCE？**（结合 §1.4.5 认证后高危功能清单）
   - 文件上传 → 上传 webshell（检查扩展名/MIME 过滤）
   - 模板/主题编辑 → 写入恶意代码（检查是否支持 PHP/SSTI）
   - 插件/扩展安装 → 安装恶意插件（检查签名验证）
   - 计划任务/Cron → 注入命令
   - 数据库管理界面 → SQL 执行（若有 INTO OUTFILE 或堆叠查询）
   - 配置修改 → 修改日志路径/包含路径 → 文件包含 RCE

3. **组合链端到端可行性评估**：
   - 列出完整链路：`pre-auth 原语 → auth bypass 方法 → post-auth RCE 方法`
   - 评估每一步的前置条件和成功概率
   - 标注 exploitability：若组合链在默认配置下可行 → `CONFIRMED`

#### 路径 B：漏洞直接升级

- SQLi → `INTO OUTFILE` / `INTO DUMPFILE` 写 webshell（需 `FILE` 权限 + 已知 web 目录 + `secure_file_priv` 未限制）
- SQLi → 堆叠查询 → `LOAD_FILE` + 存储过程 → 命令执行
- SQLi → UDF 注入（需 plugin 目录写权限）
- 文件读取 → 源码泄露 → 发现新的 RCE 漏洞
- SSRF → 云元数据获取 → 凭据窃取

#### 路径 C：多漏洞组合

- SQLi + 文件包含 → SQL 注入写入日志 → 包含日志文件 RCE
- SQLi + 反序列化 → 注入恶意序列化数据到数据库 → 触发反序列化
- 文件读取 + SSTI → 读取模板引擎密钥/配置 → 注入模板代码

### 输出要求

在 `vuln_hunt_output.md` 中新增 `## 组合链评估` 章节，对每个前台漏洞原语输出：

```
### <漏洞ID> 组合链评估

#### 直接升级路径
- INTO OUTFILE: <可行性及原因>
- UDF: <可行性及原因>
- 堆叠查询: <可行性及原因>

#### Auth Bypass → Post-auth RCE 路径
| Auth Bypass 方法 | 可行性 | Post-auth RCE 方法 | 可行性 | 组合链评估 |
|-----------------|--------|-------------------|--------|-----------|
| 读取密码哈希+破解 | 高(MD5无盐) | 文件上传webshell | 高 | CONFIRMED |
| 修改管理员密码 | 高(UPDATE权限) | 模板编辑写入代码 | 高 | CONFIRMED |
| 伪造Session | 中(需找session表) | 插件安装 | 高 | EXPLOITABILITY_CONDITIONAL |

#### 最优组合链
<推荐的最短/最可行的组合攻击路径>
```

#### 路径 D：认证绕过独立评估（Pre-auth RCE 专用）

当发现 CONDITIONAL 入口或认证逻辑缺陷时，必须独立评估：

1. **认证绕过完整性验证**：
   - 绕过条件是否完全由攻击者控制（不依赖服务端状态）？
   - 绕过后能访问哪些 post-auth 功能？（结合 §1.4.5 认证后高危功能清单）
   - 绕过是否稳定可重复（非条件竞争）？

2. **若认证绕过可行**：
   - 直接记录为 Auth Bypass CAND，exploitability = `CONFIRMED`（**无需等待发现 exec sink**）
   - 同时评估认证绕过 + post-auth RCE 的组合链（参照路径 A）

3. **Auth Bypass 独立价值判断**：
   - 即使 post-auth 功能无 exec sink，Auth Bypass 本身仍可作为 PASS 级发现
   - 评估绕过后可访问的数据敏感性（管理员凭据、私钥、内部 API）

### 关键规则

- **禁止在直接 RCE 路径失败后就放弃一个漏洞原语**。即使 `INTO OUTFILE` 不可行，SQLi 仍然具有通过 Auth Bypass 达成 RCE 的巨大价值。
- **组合链中的 Auth Bypass 步骤算作"利用前台漏洞的延伸"**，不算作额外的认证前提。因此 `SQLi → Auth Bypass → Post-auth RCE` 仍然是 pre-auth RCE。
- **如果组合链可行（任一路径 A/B/C/D 评估为 CONFIRMED），该候选漏洞必须升级为高置信，不得降级**。
- **Auth Bypass（路径 D）可独立 PASS，不依赖其他路径的成功**。

**失败教训参考**：参见 `MEM-FAILURE-COMBO-CHAIN-ABANDONED-01`——发现 SQLi 后仅尝试 INTO OUTFILE 失败就放弃，忽略了 SQLi → Auth Bypass → Post-auth RCE 的组合链。

### call_graphs.md format
```
函数调用图 - 目标程序
已分析函数 N个

[entry_point] (入口)
├── [func_a] (处理层)
│   ├── [func_b] (数据处理)
│   │   └── [VULN_FUNC] ⚠ 漏洞点
│   └── [func_c] (验证)
└── [func_d] (输出)

Source->Sink 路径：
entry_point -> func_a -> func_b -> VULN_FUNC (sink)
```

### call_graphs.md 认证管线记录（MANDATORY — Pre-auth RCE / 认证绕过 / HTTP 服务目标）

当目标涉及 pre-auth 利用时，`call_graphs.md` 中**必须包含认证管线章节**，记录请求从网络入口到 handler 调用经过的所有认证检查层。此记录是 Phase 3 验证和 Phase 4 Challenge Agent 独立审计的基础。

#### 格式规范

```
## 认证管线（Authentication Pipeline）

### 请求处理主循环
位置: <文件名:行号范围>

request
  │
  ▼
[Layer A: <函数名>] (<文件:行号>)
  │ 功能: <简述函数作用>
  │ 认证逻辑: <具体检查机制>
  │   ├─ <条件1> → <结果1>（放行/阻断/跳过）
  │   ├─ <条件2> → <结果2>
  │   └─ <条件3> → <结果3>
  │ 返回值处理: <主循环如何处理该函数的返回值>
  │   └─ 返回 NULL/0 → <主循环行为：返回错误码/继续/终止连接>
  │
  ▼
[Layer B: <函数名>] (<文件:行号>)
  │ 功能: <简述>
  │ 跳过条件: <哪些路由会跳过此层>
  │
  ▼
[Handler 调用] (<文件:行号>)

### 路由认证状态表
| 路由 | Layer A 结果 | Layer B 结果 | 最终可达性 | 证据行号 |
|------|-------------|-------------|-----------|---------|
| /cgi/login | 白名单放行 | 跳过 | Pre-auth ✓ | L4514,L3306 |
| /cgi/softup | 返回NULL→404 | 不可达 | 需认证 ✗ | L4518→L3297 |
| /api/config | N/A | 权限位检查 | 需认证 ✗ | L3314 |
```

#### 关键要求

1. **每个 Layer 必须记录返回值的处理方式**：不仅记录"函数做了什么检查"，还必须记录"检查不通过时主循环如何处理返回值"（是终止请求还是忽略继续）
2. **路由认证状态表必须覆盖所有 P0 候选路由**：每个声称 pre-auth 可达的路由必须在表中有条目，且每一层的结果都有对应的代码行号证据
3. **当某层存在白名单/黑名单时，必须完整列出白名单内容**
4. **Phase 3/4 的验证代理将依赖此表进行独立认证链校验**——如果此表缺失或不完整，Phase 4 verdict 必须为 LOOP
