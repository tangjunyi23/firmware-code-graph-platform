---
name: rootfs-elf
description: >
  用 rootfs_elf 工具批量分析固件 rootfs 目录下的所有 ELF(扫描指纹 SHA-256/架构/位数/端序/checksec、
  任务编排 resume/force/retry/timeout、可选 IDA Pro idalib 导出 source.c + 逐函数 decompile/*.c +
  strings/imports/exports/function_index)。
  当用户提到 rootfs_elf / rootfs-elf、扫描或批量反编译 rootfs/固件文件系统、枚举目录树下全部 ELF、
  对大量二进制生成 IDA 产物时使用本 skill——即使用户没有说出工具名。
  Use whenever the user wants to batch-scan, fingerprint, or batch-decompile all ELF binaries
  under a firmware rootfs directory (e.g. extracted squashfs/cramfs trees).
---

# rootfs_elf:RootFS 批量 ELF 分析

离线扫描一个 rootfs 目录,识别所有 ELF(ET_EXEC + ET_DYN,含 PIE 和 .so),计算 SHA-256/架构/位数/端序/checksec,并可用 IDA idalib 无头导出反编译产物。工具源码 tarball 随本 skill 打包在 `assets/rootfs_elf.tar.gz`。

## 一次性安装(每台机器一次)

运行本 skill 目录下的安装脚本(解压工具到 `~/.zcode/tools/rootfs_elf`,自动发现 IDA ≥ 9.1 并激活 idalib):

```bash
python <本skill目录>/scripts/setup_rootfs_elf.py
```

可选参数:`--tarball <路径>` 用外部新版归档替换随包版本;`--target <目录>` 改解压目标;`--ida-dir <目录>` 指定 IDA 安装;`--no-ida` 跳过 IDA 激活;`--force` 重新解压。脚本结束时会打印本机可直接复制的运行命令。

手动安装等价操作:

```bash
# 归档实际是纯 POSIX tar(尽管扩展名是 .tar.gz),必须用 -xf 而不是 -xzf
mkdir -p ~/.zcode/tools/rootfs_elf
tar -xf <本skill目录>/assets/rootfs_elf.tar.gz -C ~/.zcode/tools/rootfs_elf
```

没有 setup.py,**不能用 pip 安装**;入口是包父目录下的 `python -m rootfs_elf`。README 里的 `python cli.py` 是过时写法,会因相对导入直接报错。

## 运行

工作目录必须是解压出的 `rootfs_elf` 包的**父目录**(即 `~/.zcode/tools/rootfs_elf`;Git Bash 下 `~` 可直接用,Windows 原生 shell 写 `%USERPROFILE%\.zcode\tools\rootfs_elf`):

```bash
cd ~/.zcode/tools/rootfs_elf

# 1) 只扫描 + checksec(不需要 IDA):ELF 入队,meta.json 状态停在 pending
python -m rootfs_elf <rootfs目录> -o <输出目录> --progress

# 2) 完整流程:扫描 + IDA 反编译导出(IDADIR 用 setup 脚本打印的安装目录)
IDADIR=<IDA安装目录> \
python -m rootfs_elf <rootfs目录> -o <输出目录> \
  --run-ida --skip-memory --ida-log -j 4 --timeout 900 --retry 1 --progress
```

### IDA 环境

- IDA 导出走 idalib(`<IDA>/idalib/python`),要求 **IDA 9.1+**:工具的
  `idapro.open_database(path, True, "-o...")` 三参数调用 9.0 不支持(TypeError),且 9.0 的
  idalib 曾出现 open_database 原生崩溃(access violation)。多版本共存时选最新的 ≥ 9.1。
- idalib 是 per-user 激活:运行 `<IDA>/idalib/python/py-activate-idalib.py` 把配置指到所选安装
  (setup 脚本已自动做);之后调用时再设 `IDADIR` 环境变量指向同一安装即可。
- 无 IDA 或不传 `--run-ida` 时只做扫描/checksec,完全可用。
- 首次使用一台新机器的 idalib 前,该 IDA 至少要启动过一次接受许可条款。

### 常用参数

| 参数 | 作用 |
|---|---|
| `-o, --out-dir` | 输出目录。**务必显式指定**(默认落在包内 `output/`,与归档里带的陈旧结果混在一起) |
| `--run-ida` | 启用 IDA 导出(默认只扫描) |
| `-j, --workers N` | 并行 IDA 进程数(默认 1;每个 worker 是独立 idalib 进程) |
| `--timeout N` / `--retry N` | 单 ELF 超时秒数(0 不限)/ 失败重试次数 |
| `--skip-memory` | 不导出 memory/ 段十六进制转储(1MB 文本/段,**强烈建议加上**,否则体积爆炸) |
| `--exclude regex` | 按相对路径正则排除(如 `'^usr/share/'`) |
| `--max-bytes N` | 跳过超大文件 |
| `--only-exec` | 只分析 ET_EXEC(默认同时包含 ET_DYN/.so/PIE) |
| `--no-decompile-funcs` | 不导出逐函数 `decompile/*.c`(只保留整文件 source.c) |
| `--no-function-index` | 不导出 function_index.jsonl |
| `--force` / `--only-failed` | 全部重跑 / 只重跑失败的 |
| `--ida-log` | 每 ELF 写 ida.log(排障时开) |

## 断点续跑语义

meta.json 的 status 生命周期:`pending → running → done | failed`。

- 默认 resume 开启:status 为 done/pending 的 ELF 跳过;中断后原命令重跑即续。
- `--only-failed` 只重跑 failed;`--force` 清空 manifest/errors 全部重来。
- 已 done 的 ELF 产物不会被覆盖,除非 `--force`/`--only-failed` 时会先清空该 ELF 目录再跑。

## 输出布局与消费

```text
<out-dir>/
├── summary.json            # 本次运行统计
├── manifest.jsonl          # 入队记录
├── errors.jsonl            # 错误记录(见下方 pitfalls)
├── by_elf/<elf_id>/        # elf_id = 净化后的相对路径 + "__" + sha256前8位
│   ├── meta.json           # 状态、sha256、arch/bits/endian、checksec
│   ├── source.c            # 整个二进制的 Hex-Rays 汇总反编译
│   ├── decompile/<name>_<ADDR>.c   # 逐函数反编译(头注释含 callers/callees)
│   ├── strings.txt / imports.txt / exports.txt / data_symbols.txt
│   ├── function_index.jsonl / decompile_failed.txt / decompile_skipped.txt
│   ├── memory/…(未 --skip-memory 时) / database.i64 / ida.log
└── indexes/                # 全局聚合,每次运行结束重建
    ├── elf_index.csv               # 所有 ELF 一行一个:status、nx/canary/relro/pie
    ├── strings_global.jsonl / imports_global.jsonl / exports_global.jsonl
    ├── entry_candidates.jsonl      # 疑似入口/服务函数(is_entry_candidate)
    └── label_evidence.jsonl        # 规则打标:unsafe / crypto / service 及证据
```

各产物的逐行格式、字段 schema 和已知失真见 [references/output-formats.md](references/output-formats.md)——在消费这些文件做进一步分析前先读它。

查某个二进制的产物:先在 `indexes/elf_index.csv` 或各 meta.json 里按 rel_path 找到 `elf_id`,再进 `by_elf/<elf_id>/`。

## Pitfalls(均有实测依据)

1. `tar -xzf` 报 "not in gzip format" → 归档是纯 POSIX tar,用 `tar -xf`。
2. Git Bash 里 tar/路径用 `/c/...` 或 `~/...` 风格;含盘符冒号的 `C:\...` 会被 tar 当远程主机。
3. `python cli.py` 报 ImportError → 必须 `python -m rootfs_elf` 且 cwd 在包父目录。
4. errors.jsonl 出现大量 `checksec: ...` 条目:机器没装 checksec 时**每个 ELF 都记一条**,但只是噪音——任务照常入队,checksec 字段为 null,索引里显示 unknown。判断成败看 meta.json 的 status。
5. 扫描模式(无 --run-ida)跑完后 status 全是 pending,属预期:IDA 任务从未执行。
6. IDA 模式要求 idalib API ≥ 9.1 且 `IDADIR` 指向该安装;指到 9.0 会在 open_database 处 TypeError 或原生崩溃。
7. 大 rootfs 必加 `--skip-memory` 并考虑 `--max-bytes`、`--exclude`;memory/ 转储和 database.i64 会迅速吃满磁盘。
8. 中文路径 OK,但输出目录建议纯 ASCII,避免下游工具(如某些 CSV 解析器)出问题。
