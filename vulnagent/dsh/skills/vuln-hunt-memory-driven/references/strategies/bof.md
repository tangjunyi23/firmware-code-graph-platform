# 缓冲区溢出 专项分析策略

**Sources：**
- 网络数据包的 payload/header 字段
- 文件格式中的长度/大小字段
- 用户输入的字符串
- 协议解析得到的变量

**Sinks：**
- memcpy / memmove / strcpy / strncpy / strcat
- sprintf / snprintf（格式化到固定缓冲区）
- sscanf / scanf（无宽度限制的 %s）
- recv / read + 直接写入固定缓冲区
- 循环中逐字节/逐块写入固定缓冲区

**Key Check：**
1. **运算符优先级**：长度赋值表达式中是否有优先级陷阱？如 `x = strtol(s) > 0` 实际是 `x = (strtol(s) > 0)` 使 x 只能为 0 或 1。
2. **长度计算一致性**：检查代码中长度的"计算处"和"使用处"是否一致，有无中间修改。
3. **边界检查缺失**：dest 缓冲区是否固定大小？src 长度是否来自外部输入？两者之间有无 min/bounds 检查？
4. **sscanf 无宽度**：`sscanf(input, "%s", buf)` 无限制写入 buf。
5. **off-by-one**：循环终止条件 `<=` vs `<`，或 null terminator 未计入。
6. **字符替换/转义膨胀**：函数是否将 1 字节字符替换为多字节序列（如 `\r\n` → `<br>` 为 1→4 倍膨胀）？若边界检查基于原始字符串长度而非膨胀后长度，连续特殊字符可导致栈/堆溢出。

**Common Patterns：**
- `sscanf(header, "%s", fixed_buf)` — fixed_buf 大小固定，header 长度无限
- `len = strtol(hdr) > 0; memcpy(dst, src, len)` — 优先级 bug 使 len 始终为 0/1
- `memcpy(struct_member, packet_data, packet_length)` — packet_length 来自包头且无 sizeof 上界
- 循环 `while(i < ext_len) { buf[i] = data[i]; i++; }` — ext_len 来自外部
- 字符转义函数将 `\r`/`\n` 替换为 `<br>`（4字节），但循环计数器按原始字符数递增
