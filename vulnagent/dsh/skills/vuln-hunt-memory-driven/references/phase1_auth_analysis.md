# Phase 1C: 认证流程深度分析

> 本文件从 `phase1_attack_surface.md` 拆分而来，仅在目标漏洞类型涉及"认证前RCE"/"认证绕过"或目标为 Web 应用时加载。

## 1C.1 请求处理管线分析（MANDATORY — 所有 HTTP 服务目标）

**此步骤必须在认证入口识别之前执行。** HTTP 服务器的认证不一定是单点检查，可能是多层过滤器/函数链。必须先还原完整的请求处理管线，再判断哪些路由是 pre-auth 可达的。

**失败教训**：TP-Link Archer C50 httpd 中，分析仅发现 `strstr(url, "/cgi")` 跳过了 `http_author_hasAuthor` 就断定 pre-auth 可达，遗漏了前置调用 `http_alias_fillTarget` 内部的白名单过滤（未登录时仅放行 4 个白名单路由，其余返回 NULL → 主循环返回 404）。结果将需要认证的 `/cgi/softup` 误判为 pre-auth 可达。

### 步骤

1. **追踪请求完整处理流程**：从 `accept()`/`recv()` → HTTP 解析 → 路由匹配 → 认证检查 → handler 调用，**逐行阅读主循环代码**，识别每一个会阻断请求的检查点（返回错误码、关闭连接、goto 错误处理等）

2. **枚举所有认证检查层**：认证逻辑可能分布在多个函数中，典型的多层结构：
   - **Layer A — 路由解析层**：路由解析/填充函数内部的白名单/黑名单过滤（如 `http_alias_fillTarget` 中对未登录请求的路由过滤）
   - **Layer B — 显式认证层**：独立的 session/cookie/token 验证函数（如 `http_author_hasAuthor`）
   - **Layer C — Handler 内部层**：handler 函数内部的二次权限检查（如 `SessionHelloCall.execute()` 内部的业务认证）
   - **关键**：某一层的检查被跳过不等于认证绕过——必须确认**所有层**均被跳过

   **⚠️ Java/Spring 项目特别警告（N-central 误判教训）**：
   - 搜索 Interceptor/Filter 注册**不能只查 Java 代码**（`addInterceptors()`/`WebMvcConfigurer`），**必须同时检查 XML 配置文件**：
     ```bash
     # 必须执行
     find . -path "*/WEB-INF/*.xml" -o -name "applicationContext*.xml" -o -name "*servlet-context*.xml" | xargs grep -l "interceptor\|Interceptor" 2>/dev/null
     ```
   - `WEB-INF/beans.xml` 中的 `<mvc:interceptors>` 注册的 Interceptor 覆盖路由可能是**部分路由**（非全局），必须确认哪些路由被覆盖、哪些未被覆盖
   - 即使某路由未被 Interceptor 覆盖，其 Controller handler 内部可能有业务层认证（如调用 `validateSession()`、`SessionHelloCall.execute()` 等 delegate 方法）——**必须跟进 delegate 方法内部**确认无认证逻辑后才能标注 pre-auth

3. **对每个路由/handler，逐一确认是否能通过所有检查层**：
   - 逐层追踪：该路由在 Layer A 是否被放行？Layer A 的返回值是否影响后续流程？
   - 函数返回值分析：路由解析函数返回 NULL/0/错误码时，主循环是否终止请求？
   - **禁止行为**：禁止仅凭"跳过了某一层认证函数"就判定 pre-auth 可达，必须确认该函数是请求路径上的**唯一**认证检查点

4. **输出认证管线图**到 `attack-surface.md` 和 `call_graphs.md`：

   ```
   ## 认证管线（Authentication Pipeline）

   request → [Layer A: http_alias_fillTarget]
                │
                ├─ 未登录 + CGI路由 + 不在白名单 → return NULL → 主循环返回 404 ✗
                ├─ 未登录 + CGI路由 + 在白名单(/cgi/login等) → return Alias → 继续
                └─ 已登录 → return Alias → 继续
                        │
                        ▼
             [Layer B: strstr(url, "/cgi") → 跳过 http_author_hasAuthor]
                        │
                        ▼
             [LABEL_96: handler 调用]

   路由认证状态表：
   | 路由 | Layer A | Layer B | 最终可达性 |
   |------|---------|---------|-----------|
   | /cgi/login | 白名单放行 | 跳过 | Pre-auth ✓ |
   | /cgi/softup | 返回NULL→404 | 不可达 | 需认证 ✗ |
   ```

5. **条件执行（Round 2+）**：若 snapshot 中 `auth_pipeline_analysis` 为 `true`，跳过此步骤

6. **Proxy/Gateway Header Stripping 完备性矩阵（MANDATORY — 存在 preauth header 机制时）**

   当后端注册了多个 header-based preauth filter 时，**必须逐一检查**每个 header 是否被外层 proxy/gateway strip。禁止发现部分 header 被 strip 就推广为全部 header 都被 strip。

   a. **枚举后端接受的所有 preauth headers**：从 Spring Security XML（`<security:custom-filter>`）、`CompositeFilter` bean、Filter 注册、中间件配置中提取，逐个记录 header 名称和对应的 filter bean/class
   b. **枚举外层 proxy/gateway 的所有 strip 规则**：搜索 `RequestHeader unset`（Apache）、`proxy_set_header ... ""`（Nginx）、header strip 配置（Envoy/自定义 proxy），记录被 strip 的 header 完整列表
   c. **构建 Header Stripping 矩阵**并写入 `attack-surface.md`：

   ```
   ## Header Stripping 完备性矩阵

   | Preauth Header | Backend Filter/Bean | Proxy Strip 证据 | 外部可伪造？ |
   |---------------|--------------------|--------------------|------------|
   | X-Foo-Preauth | preAuthFilter      | `RequestHeader unset X-Foo-Preauth` ✅ | 否 |
   | X-Bar-Preauth | barAuthFilter      | **未发现 strip 规则** ❌ | **是 → 独立候选** |
   | X-Baz-Token   | certFilter         | **未发现 strip 规则** ❌ | **是 → 独立候选** |
   ```

   d. **任何「外部可伪造=是」的 header 必须作为独立候选提交到 Phase 2**，不得与已 strip 的 header 归为同一候选
   e. **禁止行为**：禁止因"发现了部分 header strip 规则"就假设同一 compositeFilter 中的所有 header 都被 strip——每个 header 必须有独立的 strip 证据

   **失败教训**：Nutanix CVM 案例中，SSL terminator 只 strip 了 `X-Nutanix-Preauth-User` 和 `X-NTNX-Authn`（2/5），但扫描器将全部 5 个 preauth header 归为一个候选（CAND-HEADER-PREAUTH-01）并整体排除。实际上 `X-Nutanix-GuestVM-Preauth` 和 `X-Ntnx-Service-Token` 未被 strip，外部攻击者可直接伪造触发 `vmAuthFilter` 认证绕过。

## 1C.2 认证机制分析

1. **认证入口识别**：
   - 定位登录/认证相关控制器、中间件、过滤器
   - 识别 session/token/cookie 的创建和验证逻辑
   - 记录认证 SQL 查询语句（用于后续评估 SQLi → Auth Bypass 可行性）
2. **凭据存储与验证机制**：
   - 密码哈希算法（MD5/SHA1/bcrypt/argon2）及是否加盐
   - 凭据存储位置（数据库表名、字段名）
   - 验证流程的具体代码路径
3. **认证后高危功能清单**：
   - 枚举管理员面板中所有危险功能及其 sink
   - **必须覆盖的功能类型**：文件上传、模板/主题编辑、插件/扩展安装、数据库管理、命令执行、配置修改、代码编辑器、计划任务/Cron 管理
   - 对每个功能记录：入口路由、所需最低权限、sink 函数、sink 是否可控

## 1C.3 Auth Bypass 路径评估

为 Phase 2 组合链提供输入。**必须主动搜索，不可仅凭印象断言"未发现"：**

- **SQLi → Auth Bypass**：用 `rg -n "query|execute|where" <前台路由文件>` 搜索拼接型 SQL；若发现，评估能否读取/修改凭据表或伪造 session
- **反序列化 → Auth Bypass**：用 `rg -n "unserialize|readObject|pickle\.load|yaml\.load"` 全目录搜索；若前台可达，评估能否伪造 token/session 对象
- **文件读取 → Auth Bypass**：能否读取配置文件中的数据库凭据/API Key/加密密钥？
- **路径穿越 → Auth Bypass**：能否访问认证后端点或读取敏感配置？
- **SSRF → 内网探测/Auth Bypass**：用 `rg -n "curl|file_get_contents|requests\.get|HttpClient"` 搜索前台可达路由；若 URL 参数外部可控，标记 SSRF 候选

## 1C.4 输出格式

在 `attack-surface.md` 中新增 `## 认证流程分析` 章节：

```
## 认证流程分析

### 认证机制
- 认证入口: <文件:行号>
- 密码哈希: <算法>（加盐/未加盐）
- 凭据存储: <数据库表.字段>
- 认证 SQL: <查询语句模板>
- Session 管理: <机制描述>

### 认证后高危功能
| 功能 | 入口路由 | 所需权限 | Sink 函数 | RCE 可行性 |
|------|---------|---------|----------|-----------|
| 文件上传 | /admin/upload | admin | move_uploaded_file() | 高 — 可上传 webshell |
| 模板编辑 | /admin/theme/edit | admin | file_put_contents() | 高 — 可写入 PHP 代码 |
| 插件安装 | /admin/plugin | admin | include()/eval() | 高 — 可执行任意代码 |
| ... | ... | ... | ... | ... |

### Auth Bypass 路径评估
- [ ] SQLi → 读取管理员密码哈希 → 破解/彩虹表 → 登录
- [ ] SQLi → UPDATE 管理员密码 → 登录
- [ ] SQLi → 读取/伪造 Session → 冒充管理员
- [ ] 文件读取 → 配置文件中的 DB 密码/密钥 → 登录
- [ ] 路径穿越 → 认证后端点直接访问
```

## 1C.5 条件执行（Round 2+）

若 snapshot 中 `auth_flow_analysis` 已完成，跳过 §1C.1-§1C.2。但若本轮新发现了前台漏洞原语（如 SQLi），必须重新评估 §1C.3 Auth Bypass 路径。
