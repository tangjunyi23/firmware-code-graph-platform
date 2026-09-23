# 拒绝服务 (DoS) 专项分析策略

**红队视角**：DoS 漏洞在红队场景中通常不是最高优先级，但未认证 DoS 可作为业务影响评估的补充发现。当主要 RCE/AuthBypass 路径受阻时，DoS 可作为降级发现报告。

**Sources：**
- API 请求中的数值参数（计数器、间隔、超时、大小）
- 文件上传的大小/数量
- 正则表达式匹配的用户输入
- XML/JSON 请求体的嵌套深度
- 循环/递归的迭代次数参数

**Sinks：**
- 除法/取模运算（除零 panic）
- 内存分配函数的大小参数（OOM）
- 正则引擎的匹配函数（ReDoS）
- XML 解析器（Billion Laughs / XML 炸弹）
- 递归函数调用（栈溢出）
- 文件系统写入（磁盘耗尽）
- 数据库查询（慢查询/锁表）

**Key Check：**
1. **除零**：用户可控数值是否直接作为除数？Rust 中整数除零会 panic（debug 和 release 模式均如此）；C/C++ 中整数除零是 UB；Go 中整数除零 panic。
2. **整数参数无下界**：时间间隔、等待天数等参数是否允许 0 或负值？
3. **正则 DoS（ReDoS）**：用户输入是否直接作为正则模式？正则模式是否包含嵌套量词（如 `(a+)+`）？
4. **资源耗尽**：请求是否可触发大量内存分配/文件创建/数据库写入且无速率限制？
5. **递归深度**：JSON/XML/协议消息的嵌套深度是否受限？
6. **Panic/异常未捕获**：服务端是否捕获了 panic（Rust）/exception（Java/Python）/segfault（C）？未捕获的异常是否导致整个进程退出？

**Common Patterns：**
- `wait_time = params.get("days"); sleep(wait_time * 86400)` — days=0 或负值
- `ratio = total / count` — count 来自用户输入且无零值检查
- `Regex::new(&user_input).is_match(data)` — 用户控制正则模式
- `for _ in 0..user_count { allocate_buffer() }` — 无上界的循环分配
- 嵌套 JSON 解析无深度限制导致栈溢出
