# 认证绕过 专项分析策略

**Sources：**
- 登录表单（用户名、密码、token、验证码）
- HTTP 认证头（Authorization、Cookie、X-Auth-Token）
- SSO/OAuth 回调参数（code、state、id_token）
- API key / session token 参数
- 请求 URL 路径和查询参数
- 协议消息类型字段（msg_type）和消息体状态位（verify_status 等）

**Sinks：**
- Session 创建/设置函数
- Cookie 设置（Set-Cookie）
- JWT/Token 签发函数
- 认证成功状态返回（return true / authenticated = 1）
- 权限提升操作
- 协议状态机中的 is_authenticated / session_state 标志位赋值

**Key Check：**
1. **用户控制比较长度**：`strncmp(expected, user_input, strlen(user_input))` — 空输入时 strlen 为 0，strncmp 返回 0，直接通过。
2. **隐藏认证码/后门参数**：是否存在硬编码的 authCode/backdoor/master_password？
3. **弱哈希碰撞**：是否使用 CRC32/Adler32/自定义短哈希作为认证缓存键？
4. **SSO/OAuth 仅验证用户名**：回调处理是否只提取用户名而不验证签名/token 有效性？
5. **类型混淆**：JSON 中传 null/数组/数字替代字符串是否导致比较逻辑异常？
6. **默认凭据/空密码**：某些分支是否允许空密码或默认密码通过认证？
7. **路径/大小写绕过**：认证检查是否依赖 URL 路径匹配？大小写或路径标准化差异是否可绕过？
8. **文件/数据不存在时的默认值**：认证信息从文件读取时，若文件不存在，变量保持默认初始值（如 0），攻击者可构造匹配默认值通过比较。
9. **URI子串匹配绕过**：认证白名单是否使用 `strstr`/`contains` 做子串匹配？攻击者可在需认证 URL 后附加白名单子串绕过。
10. **不存在用户名→空密码→空哈希绕过**：对不存在用户名返回失败但不中断流程，密码缓冲区保持为空，后续空值哈希匹配。
11. **SQL查询缓存键碰撞绕过**：认证查询是否使用弱哈希（CRC32）作为缓存键？不同参数可碰撞出相同CRC32。**此类漏洞比简单缺失校验更隐蔽，应优先报告**。
12. **预认证 URL 白名单/分发器函数（MUST CHECK）**：必须检查认证检查之前的 URL 路由/分发逻辑。
13. **SQL查询缓存碰撞的 refreshCache 参数有效性**：必须验证所有调用链是否都传了 refreshCache=true。
14. **协议状态机注入（State Injection）**：自定义协议的消息分发器（dispatcher）是否维护未认证消息白名单？白名单中是否包含可覆写认证状态的消息类型？三步检查：
    - (a) **白名单过宽**：dispatcher 的 allow-list 是否放行了不应在认证前到达的 msg_type？特别注意**服务端→客户端方向**的消息被客户端反向发送到服务端。
    - (b) **远程可控状态位**：handler 是否从网络数据包中读取状态字段（如 verify_status）直接覆写本地 `is_authenticated` 标志？认证决策应由**本地密码学验证**驱动，而非对端声明。
    - (c) **单一标志位门控**：整个权限模型是否依赖单个 `is_authenticated` 布尔值？一旦被置 1 是否解锁所有 post-auth handler（如 SSH 密钥注入、配置修改）？
15. **协议握手步骤跳过**：多步认证握手中是否可以跳过中间步骤？如跳过 CHALLENGE_ACK（身份证明）直接发送 CHALLENGE_ACK_ACK（确认认证成功）。检查每个步骤是否强制依赖前一步骤的完成状态。
16. **Proxy/Gateway Header Stripping 完备性（MUST CHECK）**：当目标架构包含反向代理/网关/SSL terminator 层时，后端接受的每个 preauth header 是否**都**被外层 strip？**必须逐个 header 交叉比对**（构建 Header Stripping 矩阵），不可因"发现了部分 strip 规则"就假设所有 preauth header 都被 strip。部分 strip（如只 unset 2/5 个 preauth headers）意味着未被 strip 的 header 可被外部攻击者直接伪造，触发后端 preauth filter 完成认证绕过。检查点：
    - (a) `compositeFilter`/`FilterChain` 中的每个 filter 对应的 header 是否都有 strip 规则？
    - (b) Cookie-based preauth filter 是否有 cookie strip/清除规则？（cookie 通常不被 `RequestHeader unset` 覆盖）
    - (c) 不同 virtualhost/端口的 strip 规则是否一致？（如 :9440 strip 了但 :9444 未 strip）

**Common Patterns：**
- `strncmp(stored_pass, user_pass, strlen(user_pass))` — 空密码绕过
- `if(params.authCode) { createSession(user) }` — 任意 authCode 值即可
- `cache_key = crc32(sql + values); if cache_key exists return cached_result` — CRC32 碰撞
- `fopen(sp_file, "r")` 失败 → `v4` 保持 0 → `return v4 == id` 当 `id=0` 时通过
- `strstr(uri, preauth_string_list[i])` — 预认证安全检查使用子串匹配
- `crc = crc32(sql + implode(values)); if(cached[crc]) return cached[crc]` — 碰撞返回另一用户结果
- `if (msg_type in allow_list) { pass_gate(); } ... case 10: p_peer->is_authenticated = p_msg->verify_status;` — 协议状态机注入（CVE-2026-20127 模式）
- 握手步骤跳过：跳过 Type 9 (身份证明) → 直接伪造 Type 10 (verify_status=1) → 服务端盲信 → 解锁 Type 14 (SSH key 注入)
- Proxy header strip 不完整：`RequestHeader unset X-Foo-Preauth` + `RequestHeader unset X-Bar-Authn`（仅 2/5），但 `X-Baz-GuestVM-Preauth` 未 strip → 外部伪造 `X-Baz-GuestVM-Preauth: admin` → 后端 `RequestHeaderAuthenticationFilter` 直接信任 → 认证绕过
