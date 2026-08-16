# 整数溢出 / 整型溢出 专项分析策略

**Sources：**
- 图像/媒体文件头中的宽度、高度、通道数、深度字段
- 网络协议中的长度/大小/计数字段
- 文件格式中的偏移量/大小字段
- 用户提供的数值参数

**Sinks：**
- 内存分配函数（malloc/calloc/realloc/kmalloc/ExAllocatePool）的大小参数
- 数组索引计算
- memcpy/memmove 的长度参数
- 循环边界/偏移量计算
- 缓冲区偏移后的指针解引用

**Key Check：**
1. **有符号/无符号混用**：int 值是否在与 unsigned 比较后被用作 unsigned？负值能否绕过 `if(val > MAX)` 检查？
2. **乘法溢出**：`width * height * bytes_per_pixel` 是否在分配前检查溢出？
3. **类型截断**：64位值赋给32位变量，或32位赋给16位，高位被丢弃。
4. **减法下溢**：`unsigned_a - unsigned_b` 当 b > a 时回绕为极大值。
5. **加法溢出**：`offset + size` 溢出回绕为小值，绕过边界检查。
6. **比较与使用的类型不一致**：检查时用 int（有符号），使用时隐式转为 size_t（无符号）。
7. **算术表达式括号缺失（运算符优先级）**：`a - B + C` 实际意图是 `a - (B + C)`，因优先级相同左结合变成 `(a - B) + C`。**必须逐行审查每个含减法的表达式是否缺少括号**。
8. **根因定位——检查不足所在函数**：当函数 A 对输入做了不充分的校验导致非法值传入函数 B 触发危险操作时，A 是根因函数。

**Common Patterns：**
- `if(v3 > 2) return err; val = array[v3 - 64]` — v3 可为负值，v3-64 为极大无符号值
- `int len = ntohs(pkt->length); buf = malloc(len * sizeof(item))` — len*sizeof 溢出
- `uint16_t size = (uint32_t)header_size` — 32位截断为16位
- `remaining = total_len - header_len - data_len` — 减法下溢时 remaining 为极大值
- `ethlen -= offset + len - VLAN_ETH_HLEN + vlan_hlen` — 加减号优先级导致语义颠倒
