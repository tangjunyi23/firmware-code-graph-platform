# Phase 1B: 二进制目标分析

> 本文件从 `phase1_attack_surface.md` 拆分而来，仅在目标包含二进制文件或存在 `decompile/` 目录时加载。

## 1B.1 可疑二进制 Sink 触发反编译（MANDATORY）

**此规则解决 strings/objdump 替代反编译造成的 sink 误判问题。** 当调用链追踪到 ELF 二进制内部（无法直接阅读源码）时，**必须触发 IDA 反编译**，不得以 strings 输出推断 sink 语义。

### 触发条件（满足任一即触发）

1. **调用链中存在未反编译的二进制**：source→sink 路径经过 `.so`、无扩展名 ELF、固件 daemon 等，且对应 `decompile/` 目录不存在
2. **sink 语义不确定**：候选漏洞的 sink 函数位于二进制内部，当前只有 strings 级别证据（如"字符串中存在 `system`/`popen`"），未读到实际函数实现
3. **CONDITIONAL 降级原因为 sink 未确认**：候选因"sink 最终执行语义未确认"而停留在 CONDITIONAL，需要反编译解除

### 执行步骤

```bash
bash ~/.codex/skills/ida-decompile/ida-decompile.sh <binary_path> <output_dir>
```

**多个可疑二进制时**：按以下优先级逐个反编译，每个完成后立即分析，不等所有反编译完成再分析：

| 优先级 | 目标 | 触发原因 |
|--------|------|---------|
| P0 | 调用链直接触达的二进制（如 `sdb_helper`、`libXxx.so`） | sink 在其内部，必须确认 |
| P0 | 目标的主 HTTP daemon（`httpd`、`muhttpd`、`webasp` 等） | 网络入口，攻击面入口点 |
| P1 | 被 P0 二进制动态加载的 `.so` | 间接调用链 |
| P2 | 其他守护进程 | 扩展攻击面时按需反编译 |

### 禁止行为

- **禁止**以 `strings binary | grep system` 的输出作为"存在 system() sink"的证明
- **禁止**以"strings 中未发现危险函数"作为"sink 不存在"的排除依据
- **禁止**因候选已标注 CONDITIONAL 而跳过反编译——CONDITIONAL 本身即触发反编译的理由

## 1B.2 二进制目标处理（MANDATORY — 遇到 ELF/PE/Mach-O 等二进制时）

当目标目录包含二进制文件（`.so`、`.elf`、无扩展名 ELF、`.bin`、固件 httpd 等）且**尚未存在** `decompile/` 目录时，必须先执行反编译导出，再进行攻击面分析。**禁止跳过此步骤直接分析二进制 hexdump。**

**混合目标（源码 + 二进制共存）额外规定**：当目标目录同时包含可读源码（Lua/PHP/Python/JS 等）和 ELF 二进制时：
- 源码层的攻击面分析**不免除**对二进制 P0 入口的反编译义务
- 调用链从源码延伸进二进制时（如 Lua 脚本调用 `sdb_helper`、PHP 调用 C CGI），**必须**对被调用二进制执行 §1B.1 反编译流程
- 禁止以"源码层已找到漏洞"为由跳过二进制入口的分析

### 自动反编译流程

使用 IDA headless 脚本（INP.py）自动导出：

```bash
bash ~/.codex/skills/ida-decompile/ida-decompile.sh <binary_path> <output_dir>
```

- `<binary_path>`：目标二进制的绝对路径
- `<output_dir>`：导出目录，**建议设为目标目录本身**（`decompile/` 将在其下创建）

**示例**：
```bash
bash ~/.codex/skills/ida-decompile/ida-decompile.sh \
    /path/to/firmware/bin/httpd \
    /path/to/firmware/bin/
```

导出完成后，目标目录下将生成：

| 文件/目录 | 内容 | Phase 使用方式 |
|----------|------|--------------|
| `decompile/*.c` | 每个函数一个文件，含 `callers`/`callees` 元数据 | P0/P1 直接 Read 分析 |
| `exports.txt` | 导出函数表（地址:函数名） | Phase 1 入口枚举 |
| `imports.txt` | 导入函数表 | Phase 1 依赖/Sink 扩展 |
| `strings.txt` | 字符串表（含地址） | Phase 1 路由/URL 提取 |
| `function_index.txt` | 调用关系索引 | 调用链追踪 |
| `memory/` | hexdump 分片（1MB/文件） | 仅在函数反编译失败时使用 |

### 反编译目录已存在时

若 `decompile/` 已存在（上一轮已导出），**直接使用现有文件，不重复运行导出脚本**。

### 反编译后的攻击面分析流程

1. **入口枚举**：读取 `exports.txt` 确定导出函数集合；读取 `strings.txt` 提取 URL 路径、协议字符串、命令字符串
2. **函数分级**：在 `decompile/` 中对函数文件按 §1.2 策略分级（P0/P1/P2）
3. **调用链追踪**：利用每个 `.c` 文件头部的 `callers`/`callees` 元数据追踪跨函数调用，无需额外工具
4. **大型二进制**（函数数 > 500）：优先读取 `function_index.txt` 建立调用关系图，再按 P0 优先顺序深入分析

## 1B.3 反编译后逆向增强分析（MANDATORY — 存在 decompile/ 时）

当 `decompile/` 目录存在时，在函数分级和调用链追踪之前，**必须执行以下逆向增强分析**以提升反编译代码的可读性和分析精度。加载参考文件 `references/rev-symbol.md` 和 `references/rev-struct.md` 获取详细步骤。

### 步骤 1：符号恢复（rev-symbol）

对 P0 优先级的关键函数（网络入口、认证函数、危险操作处理函数）执行符号恢复：

1. **读取目标函数的 `.c` 文件**，提取 `callers`/`callees` 元数据
2. **分析内部特征**：字符串常量、Magic Number（如 MD5/CRC32/AES S-Box 常量）、代码结构模式
3. **交叉引用分析**：
   - 检查 `imports.txt` 中 callees 是否有已知符号
   - 追踪 callers 链直到找到有符号的函数，推断被调用函数的用途
   - 识别配对函数模式（alloc/free、lock/unlock、open/close）
   - 根据参数模式推断（如 `sub_XXX(2, 1, 0)` → `socket(AF_INET, SOCK_STREAM, 0)`）
4. **输出**：在 `decompile/` 目录下创建 `symbol_map.md`，记录恢复的符号映射：
   ```
   | 地址 | 原名 | 推断符号 | 置信度 | 推理依据 |
   |------|------|---------|--------|---------|
   | 0x401000 | sub_401000 | handle_http_request | High | 调用 recv/send，含 HTTP 解析逻辑 |
   ```

### 步骤 2：结构体重建（rev-struct）

对 P0 函数中频繁出现的结构体指针参数执行结构体重建：

1. **收集内存访问模式**：扫描 `*(a1 + offset)` 风格的偏移访问，记录 offset、size、读写方向
2. **遍历 callers/callees**：从调用者获取分配大小、初始化模式；从被调用者获取更多字段访问
3. **聚合推断**：
   - 合并所有偏移信息，按 offset 排序
   - 推断字段类型（函数指针 → vtable、传给 strlen → string、next/prev → 链表）
   - 计算结构体大小：max(offset) + last_field_size
4. **输出**：在 `decompile/` 目录下创建 `struct_defs.md`，记录重建的结构体：
   ```c
   // 来源: sub_401000 参数 a1
   // 估计大小: 0x48 bytes
   struct http_request {
       /* 0x00 */ int method;        // HTTP method enum
       /* 0x08 */ char *url;         // URL string, passed to strstr
       /* 0x10 */ char *headers;     // header buffer
       /* 0x18 */ int content_len;   // content length
       /* 0x20 */ void *body;        // request body pointer
   };
   ```

### 执行策略

- **按 decompile/ 目录粒度执行**：目标目录下可能存在多个二进制，每个二进制有独立的 `decompile/` 目录（如 `bin/decompile/`、`lib/decompile/`）。逆向增强分析以每个 `decompile/` 目录为单位独立执行
- **Round 1**：对当前轮次所有已反编译的 `decompile/` 目录，执行符号恢复和结构体重建
- **Round 2+**：
  - 若本轮新反编译了二进制（产生了新的 `decompile/` 目录），对新目录执行完整的符号恢复和结构体重建
  - 已有 `symbol_map.md` 和 `struct_defs.md` 的 `decompile/` 目录，仅对本轮新增的 P0 函数追加分析（如调用链延伸到的新函数）
- **跳过条件**：某个 `decompile/` 目录下 `symbol_map.md` 和 `struct_defs.md` 均已存在，且本轮无新 P0 函数触达该目录时，跳过该目录
- **优先级**：符号恢复和结构体重建的优先级低于攻击面枚举，但高于深度 source→sink 追踪——先理解代码结构再追踪数据流
