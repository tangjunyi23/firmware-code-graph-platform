# 格式化字符串 专项分析策略

**Sources：**
- HTTP 请求参数、协议字段中的字符串值
- 配置同步/管理协议中的标识符字段（如 hostname、FQDN、IP 地址字符串）
- 用户可控的 username/hostname/device name 等标识字段
- SNMP community string、RADIUS attribute 值

**Sinks：**
- printf / fprintf / sprintf / snprintf / vprintf / vfprintf / vsprintf / vsnprintf
- syslog / vsyslog
- 自定义日志函数内部调用 v*printf 系列且 fmt 来自参数透传
- 嵌入式设备的 debug/trace 输出函数

**Key Check：**
1. **fmt 参数来源**：snprintf(buf, size, fmt, ...) 中 fmt（第三参数）是否来自用户可控数据？关键区分：`snprintf(buf, sz, user_str)` 漏洞 vs `snprintf(buf, sz, "%s", user_str)` 安全
2. **间接 fmt 透传**：上层函数是否将用户输入作为参数传给封装函数，封装函数再将其作为 fmt 传给 *printf？
3. **条件分支中的格式化**：某些分支可能安全（使用 "%s"），但其他分支直接使用用户字符串作 fmt
4. **日志/调试路径**：错误处理或调试日志中是否将用户输入直接格式化输出？
5. **利用评估**：目标是否开启了 FORTIFY_SOURCE / -fstack-protector？%n 利用难度但不影响漏洞存在性

**Common Patterns：**
- `v3 = get_param(req, "hostname"); snprintf(buf, 127, *(char**)(v3+8))` — 协议字段直接作为 fmt
- `void log_msg(const char *fmt, ...) { va_list ap; va_start(ap,fmt); vfprintf(logfile, fmt, ap); }` 且调用处 `log_msg(user_input)` — 封装函数透传
- `syslog(LOG_ERR, user_controlled_error_message)` — 错误消息作为 fmt
