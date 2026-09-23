# rootfs_elf 产物格式与消费指南

消费 `by_elf/` 与 `indexes/` 下的文件前先读本文。所有格式来自源码
(scanner.py / analyzer.py / ida_worker.py),并标注了已知的失真点。

## 身份与命名

- `elf_id = <净化后的相对路径>__<sha256 前 8 位>`。路径分隔符和其他非法字符都替换为 `_`
  (Windows 上 `bin\tiny.elf` → `bin_tiny.elf`),因此**不同子目录同名文件不会冲突,但仅凭 elf_id
  无法可靠还原原始路径**——以 meta.json 里的 `rel_path` 为准。
- meta.json 记录完整 SHA-256,跨工具引用二进制身份时用它,不要用 8 位短 hash。

## meta.json(每个 ELF 一份)

字段:`status`(pending/running/done/failed)、`path`、`rel_path`、`size`、`sha256`、`arch`、
`bits`、`endian`、`elf_type`、`checksec`、`error`(失败原因)、时间戳。

- checksec 子对象:`raw`(工具原始输出)与 `normalized`(`canary/nx/pie` 为 0/1,`relro` 为
  full/partial/none,另有 `fortified`/`fortifyable` 计数)。checksec 不可用时为 null。
- `arch` 取值:x86 / x86_64 / mips / arm / aarch64 / powerpc / riscv / `unknown(0x..)`。

## 文本产物(by_elf/<elf_id>/)

文件头几行以 `#` 开头,解析时跳过。

| 文件 | 行格式 | 备注 |
|---|---|---|
| strings.txt | `addr \| length \| type \| content` | type ∈ ASCII/UTF-16/UTF-32;换行转义为 `\n` |
| imports.txt | `addr:name` | IDA 导入表视角;name 缺失时为 `ordinal_N` |
| exports.txt | `addr:name` | IDA entry 视角。**同一地址多个别名会丢**(只出一个) |
| data_symbols.txt | `addr \| size \| segment \| type \| name \| value` | **只有字符串值的数据行**;非字符串全局对象(handler 表、函数指针表)被过滤掉——已知失真,勿据此断言"无全局对象" |
| decompile_failed.txt | `addr \| name \| reason` | 真实反编译失败 |
| decompile_skipped.txt | `addr \| name \| reason` | 库函数(FUNC_LIB)等主动跳过,**不是失败** |

## function_index.jsonl

每函数一行:`name`、`address`(0x 十六进制)、`filename`(固定 "source.c")、`entry_line`
(source.c 中定义行号,正则匹配、可能为 0)、`callers`/`callees`(函数级起始地址列表)、
`is_entry_candidate`、`entry_reason`。

已知限制:callers/callees 来自代码 xref,**表达不了导入调用**(导入槽不是函数体);
跨 ELF 调用关系更不在其中。做调用图分析时把 imports.txt 与之对齐。

## decompile/<name>_<ADDR>.c

逐函数 Hex-Rays 输出,文件头注释块含 `func-name` / `func-address` / `callers` / `callees`。
文件名 = 净化函数名 + `_` + 大写十六进制地址,同名函数靠地址区分。

## source.c 与 decompile/ 的关系

source.c 是 `decompile_many` 的整文件导出,decompile/*.c 是逐函数导出——**内容大量重复**。
把两者同时喂给同一个下游分析器(如 Joern)会造成重复定义;喂 Joern 时逐选 decompile/ 或仅 source.c。
database.i64 是 IDA 数据库,可重新打开复查,但占空间大。

## 全局索引(indexes/)

每次运行结束时按 by_elf/ 目录现状全量重建(与本次是否跑 IDA 无关,历史产物也会计入):

- `elf_index.csv`:列 `elf_id,path,rel_path,arch,bits,endian,type,size,status,nx,canary,relro,pie`。
  path/rel_path 带引号但内部逗号未转义,严格 CSV 解析可能错列,建议按 elf_id 回读 meta.json。
- `strings_global.jsonl`:`{elf_id, addr, str}`(str 已按 ` | ` 切分,内容本身含 ` | ` 时会截断)。
- `imports_global.jsonl` / `exports_global.jsonl`:`{elf_id, addr, func}`。
- `entry_candidates.jsonl`:function_index 中 is_entry_candidate 的行,附 elf_id。启发式很宽
  (名字含 init/daemon/handler/http/listen 等即命中),是候选不是结论。
- `label_evidence.jsonl`:`{elf_id, label, reason, source}`,label ∈ unsafe(nx=0 且 canary=0)/
  crypto(OpenSSL 字符串或 SSL_/EVP_ 导入)/ service(bind/listen/accept/socket 导入)。

## errors.jsonl / manifest.jsonl / summary.json

- errors.jsonl:`{elf_id, path, rel_path, reason, timestamp}`。**checksec 缺失时每个 ELF 一条噪音**,
  判断真实成败看 meta.json.status。
- manifest.jsonl:本次入队记录 `{elf_id, status: pending}`;`--force` 时会清空重建。
- summary.json:`{rootfs, out_dir, stats{total_elf,queued,skipped,failed}, timestamp}`。
  注意 stats.failed 统计的是 checksec 错误 + IDA 失败的总和,不等于 IDA 失败数。
