# 任意文件读取 专项分析策略

**Sources：**
- URL 路径参数（`/read?file=xxx`）
- 路由中的动态路径段
- HTTP 请求头（Accept-Language、Referer 等用于选择文件）
- 表单字段中的文件路径

**Sinks：**
- open(path, 'r') / FileInputStream / file_get_contents / readFile
- getRequestDispatcher().forward()
- include / require（PHP）
- sendFile / serveFile 函数
- 自定义流读取器（StreamReader/InputStream 包装）

**Key Check：**
1. **UTF-8 overlong encoding 绕过**：路径校验是否对标准 `../` 拦截但对 overlong 编码放行？
2. **双重解码**：URL 解码发生在安全检查之前还是之后？
3. **路径标准化顺序**：先检查黑名单再做标准化时可能绕过。
4. **协议处理器**：`file:///`、`jar:file:///`、`php://filter` 等协议前缀是否可用？
5. **服务端转发可控路径**：`getRequestDispatcher(user_path).forward(req, resp)` 中 user_path 是否可控？
6. **符号链接跟随**：创建符号链接指向敏感文件后通过合法接口读取。

**Common Patterns：**
- 自定义 UTF-8 解码器将 overlong 编码 normalize 后绕过黑名单
- `req.getRequestDispatcher(userPath).forward(req, resp)` — userPath 可控
- `file = request.args.get('path'); return send_file(file)` — 无路径校验
- URL 路由 `/static/{path}` 未限制 `..` 导致目录穿越
