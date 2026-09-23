# 会话管理漏洞 专项分析策略

**红队视角**：会话管理漏洞通常可升级为认证绕过或账户接管，在红队场景中价值较高。

**Sources：**
- Session cookie / token
- 登录/认证成功事件
- 密码重置/变更操作
- 权限变更操作（角色提升/降级）
- OAuth/SSO 回调

**Sinks：**
- Session 创建/写入函数
- Cookie 设置函数（Set-Cookie）
- Token 签发/刷新函数
- 认证状态变更函数

**Key Check：**
1. **会话固定（Session Fixation）**：登录成功后是否调用 `session.regenerate()` / `session_regenerate_id()` / `request.getSession(true)` 重新生成 session ID？若未轮换，攻击者可预设 session ID 等用户登录后劫持会话。
2. **会话未失效**：密码变更/权限变更后，是否使旧 session 失效？退出登录时是否在服务端销毁 session（而非仅清除客户端 cookie）？
3. **并发会话限制**：是否限制同一账户的并发活跃 session 数？无限制时一个被盗 session 可长期有效。
4. **Session Token 强度**：session ID 是否使用密码学安全的随机数生成器？长度是否足够（>=128 位）？
5. **Cookie 安全属性**：是否设置了 `HttpOnly`、`Secure`、`SameSite` 属性？
6. **Token 泄露**：session token 是否出现在 URL 参数（Referer 泄露）、日志、错误消息中？
7. **Recovery Code 隔离**：2FA recovery code 是否按用户隔离（查询时包含 user_id 条件）？不隔离时任意用户的 code 可恢复任意账户。

**Common Patterns：**
- 登录函数中 `session["user"] = user_id` 但未调用 `session.regenerate()`
- 密码变更 handler 修改密码但不调用 `invalidate_other_sessions()`
- `Set-Cookie: session=xxx` 缺少 `Secure; HttpOnly; SameSite=Strict`
- Recovery code 查询 `SELECT * FROM recovery_codes WHERE code = ?`（无 `AND user_id = ?`）
- 退出登录仅 `res.clearCookie("session")` 而未调用 `session.destroy()`
