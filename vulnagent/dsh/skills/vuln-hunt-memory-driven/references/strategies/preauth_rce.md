# 认证前远程代码执行（Pre-auth RCE） 专项分析策略

此类型覆盖所有在无需有效认证凭据的情况下**造成高危影响**的漏洞。目标不限于直接 RCE——认证绕过、任意文件读取、持久化写入等只要构成独立可利用的高危影响，或能通过组合链达成 RCE，均为有效发现。

## 认证前高危漏洞类型（均为有效目标）

| 类型 | 定义 | 直接 PASS 条件 |
|------|------|----------------|
| **Pre-auth RCE** | 无需认证直接代码执行 | exec/system/popen sink + pre-auth 可达，source 可控 |
| **Pre-auth Auth Bypass** | 完全绕过认证机制 | 可以任意用户/管理员身份访问 post-auth 功能，无需合法凭据 |
| **Pre-auth 任意文件读取** | 无需认证读取任意文件 | 能读取 `/etc/shadow`、私钥、DB 密码、session 密钥等敏感文件 |
| **Pre-auth 任意文件写入** | 无需认证写入任意路径 | 能写 webshell 或覆盖 cron/配置文件触发执行 |
| **Pre-auth SSRF（高危）** | 无需认证发起服务端请求到内网 | 能访问内网无认证管理接口或 169.254.x.x 云元数据 |
| **Pre-auth SQL 注入** | 无需认证触发 SQL 注入 | 盲注/堆叠查询/Union 可达，或可导致信息泄露/认证绕过/RCE；DB 用户为高权限（DBA/SUPERUSER）时直接 PASS |
| **Pre-auth 信息泄露** | 无需认证获取敏感信息 | 能获取凭据/密钥/哈希/私钥/内网结构等，可作为后续攻击链前置步骤；独立构成高危影响时直接 PASS |
| **Pre-auth 反序列化** | 无需认证触发反序列化 | 反序列化 sink + pre-auth 可达 + payload 字节可控 |
| **Pre-auth 组合链 → RCE** | 以上任意类型串联达到 RCE | 完整链路端到端可行，每步前置条件均已验证 |

**核心判断原则**：
- Auth Bypass 本身即是 CONFIRMED 级别漏洞，**不需要额外的 exec sink**
- 任意文件读取若能读取密钥/凭据并进而突破认证 → 升级为组合链 RCE
- 认证逻辑存在可绕过的逻辑缺陷（如特定 URL/参数短路认证检查）→ 属于 Auth Bypass
- **Pre-auth SQLi 独立构成 PASS 级漏洞**，无需进一步升级为 RCE；DB 为 SUPERUSER 时（PostgreSQL `COPY FROM PROGRAM`、MySQL `INTO OUTFILE` 等）直接评估 RCE 可达性
- **Pre-auth 信息泄露是组合链的关键一环**，不得以"只是查询返回数据"为由排除；需评估泄露内容能否用于认证绕过、解密、横向移动
- **分析时不得预设"必须找到 exec sink 才算成功"**——上表中任意一行满足即可 PASS

**Sources（输入源）：**
- 自定义协议消息中的命令字段（命令ID/操作码、参数、payload）
- 未认证 HTTP/HTTPS 端点的请求参数
- 网络服务的初始握手/协商消息
- SNMP community string / UPnP SOAP 请求
- 管理协议的预认证阶段消息

**Sinks（危险操作）：**

**⚠️ 分析优先级原则（MANDATORY）**：现代软件中认证前直接 exec/deser sink 极为罕见。**分析必须优先从认证逻辑弱点入手**，而非优先寻找 exec sink。Tier 1 是第一优先级，Tier 2 次之，Tier 3 最后。

**Tier 1：认证逻辑弱点（第一优先级 — 必须最先分析）**
- **硬编码凭据/密钥**：认证密钥、加密密钥、默认密码硬编码在代码/配置中，攻击者可直接伪造 session/token/cookie
- **认证绕过 sink**：认证检查函数返回值被绕过（如特定参数值使 auth_check 短路/跳过）、session 伪造（可控密钥）、token 伪造（已知算法+可控参数）
- **信息泄露 sink**：pre-auth 端点泄露凭据/密钥/哈希/私钥/内网结构，可作为后续攻击链前置步骤；独立构成高危影响时直接 PASS
- **任意文件读取 sink**：open/fopen/File.read + 用户可控路径且无 realpath 规范化或白名单限制（可读取密钥/凭据文件）
- **SQLi → Auth Bypass**：pre-auth SQL 注入可读取/修改凭据表或伪造 session

**Tier 2：独立高危 sink（无需进一步升级即可 PASS）**
- **任意文件写入 sink**：fopen(path,"w")/File.write + 用户可控路径，能写入任意目录
- **Pre-auth SQLi（独立）**：盲注/堆叠查询/Union 可达，DB 用户为高权限（DBA/SUPERUSER）时直接 PASS

**Tier 3：直接 RCE sink（现代软件中较罕见，最后分析）**
- 系统命令执行（system/exec/popen/execve/Runtime.exec/ProcessBuilder）配合用户可控参数
- 配置修改接口（可通过修改配置实现代码执行）
- 固件/包安装接口

**Tier 4：间接 RCE sink（需组合链）**
- 文件读取 → 密钥/凭据泄露 → Auth Bypass → post-auth RCE（§2.8 路径 A）
- SQLi/NoSQLi → 认证绕过或凭据修改 → post-auth RCE
- SSRF → 内网无认证管理接口 → 命令执行
- **JNDI / 动态类加载 sink（等同 RCE 原语，Java 目标 MANDATORY 检查）**：
  - `new InitialContext().lookup(url)` — url 攻击者可控 → SSRF + 远程类加载 RCE
  - `new InitialDirContext().search(url, null)` — url 攻击者可控（典型：证书 AIA 扩展）
  - `URLClassLoader(new URL[]{url}).loadClass(...)` — 动态类加载
  - 触发场景：X.509 证书解析（AIA/OCSP/CRL）、JNDI 数据源配置、日志框架（log4j-style）
- **外向网络调用 sink（SSRF / OOB 确认）**：
  - `new URL(url).openConnection()` / `HttpClient.send(uri)` / `OkHttpClient.newCall(url)`
  - `InetAddress.getByName(host)` — DNS OOB
  - 这类 sink 在直接 RCE 不可行时用于 OOB 确认漏洞存在
- **内存破坏 sink（等同 RCE 原语）**：
  - 格式化字符串：printf/sprintf fmt 参数来自用户可控输入 → %n 任意写 → RCE
  - 堆溢出：malloc(size_A) 后 memcpy(size_B)，当 B > A → 覆盖函数指针 → RCE
  - 栈溢出：固定大小栈缓冲区 + 用户可控长度 strcpy/memcpy → 覆盖返回地址 → RCE
  - 整数溢出导致小分配大写入 → 堆溢出 → RCE

**Key Check：**
1. **权限架构枚举（MUST DO FIRST）**：必须先枚举命令分发器中所有命令的权限策略，建立完整预认证命令集。
2. **命令能力评估**：区分"连接管理型"命令和"操作型"命令。前者不构成独立漏洞。
3. **路径穿越原语检查**：免认证命令的路径参数处理是否存在路径穿越？
4. **直接 vs 间接利用判定**：优先报告不依赖前置命令的直接利用路径。
5. **协议级路径穿越**：自定义协议中文件操作命令的路径字段是否直接用于文件系统操作？
6. **会话桥接攻击的实际价值评估**：验证创建的会话是否具有完整权限。
6a. **认证绕过专项检查（MANDATORY — Web 应用 / HTTP 服务）**：
   - 认证检查函数的**返回值是否被正确处理**？（返回 NULL/0/false 时主循环是否终止请求？）
   - 是否存在特定 URL pattern / 参数值可使认证函数短路（如 `strstr(url, "/public")` 跳过 auth）？
   - session / token 的生成算法是否可预测或基于可控输入（MD5(user_input)、时间戳）？
   - 是否存在多套认证路径（web 端 + API 端 + 管理端），各路径认证强度是否一致？
   - **若认证逻辑存在任何可绕过路径 → 记录为 Auth Bypass CAND，不需要额外 exec sink**
7. **内存破坏原语检查（C/C++ 二进制 MANDATORY）**：预认证可达路径中的格式化字符串/分配写入不匹配/栈缓冲区溢出。
8. **JNDI/外向调用原语检查（Java 目标 MANDATORY）**：
   - 搜索 `InitialContext.lookup / InitialDirContext.search / new URL(*).openConnection`
   - 检查证书验证路径：`verifyCertificate` / `validateChain` / `getIntermediateCertificates` 中是否有外向网络调用
   - 检查 `skipExternalCommunication` / `skipX509ExternalChecks` 等开关的默认值（Java boolean 默认 false）
9. **工厂/策略分支枚举（Java/多态目标 MANDATORY — 参照 §1.3.5）**：
   - 认证 Connector 工厂（LDAP / LdapCertificate / SAML / OIDC / Kerberos 实现）必须逐类检查
   - 每种 Connector 实现的 `authenticate` / `verify` 方法需独立的 source->sink 追踪
   - **禁止**以接口层（`IConnector.authenticateUser` 无 sink）代替所有具体实现的分析

**Key Check（续）：**
8. **认证流程深度分析（Web 应用 MANDATORY）**：必须分析认证机制（密码哈希算法、凭据存储、session 管理），并枚举认证后高危功能（文件上传、模板编辑、插件安装、命令执行等）。详见 Phase 1 §1.4.5。
9. **组合链升级评估（MANDATORY）**：对每个已发现的前台漏洞原语，必须穷举组合链路径。禁止在直接 RCE 路径（如 INTO OUTFILE）失败后就放弃该原语。详见 Phase 2 §2.8。

**Common Patterns：**
- `set_policy(CMD_FILE_READ, 0)` — 文件读取命令免认证，路径来自协议消息且无 `../` 过滤
- 免认证命令 handler 中 `fopen(user_path, "w")` — 路径拼接后直接写入
- `switch(cmd_id) { case 7: handle_file(msg); }` 且 `set_policy(7, 0)`
- **反模式**：`set_policy(CMD_CONNECT, 0)` 仅创建连接/返回 session ID，本身无攻击能力

**Combo Chain Patterns（组合链模式）：**
- **SQLi → Auth Bypass → Post-auth RCE**：前台 SQLi 读取/修改管理员凭据 → 登录管理面板 → 利用文件上传/模板编辑/插件安装达成 RCE
  - 变体 1：SQLi → 读取 MD5/SHA1 密码哈希 → 彩虹表/hashcat 秒破 → 管理员登录
  - 变体 2：SQLi → UPDATE 管理员密码 → 直接登录
  - 变体 3：SQLi → 读取 session 表/cookie 密钥 → 伪造管理员会话
- **文件读取 → Auth Bypass → Post-auth RCE**：路径穿越读取配置文件（数据库密码、secret_key）→ 连接数据库修改凭据或伪造 token → RCE
- **SQLi → 日志注入 → 文件包含 RCE**：SQL 注入写入恶意代码到数据库 → 日志/缓存文件包含该内容 → LFI 触发代码执行
- **SSRF → 内网服务 → RCE**：前台 SSRF 访问内网无认证管理接口 → 直接执行管理操作
- **反模式**：发现 SQLi 后仅尝试 `INTO OUTFILE` → 失败 → 放弃 SQLi 转而寻找独立 RCE。**这是错误的**——SQLi 的 Auth Bypass 价值远大于直接文件写入
