# rootfs_elf (ida-no-mcp)

离线 RootFS 批量 ELF 分析工具。已整合进 fwgraph 仓库
（`tools/ida-no-mcp/`），相对独立版的改动：

- `checksec` 默认使用 `fwgraph/pipeline/extract/checksec.py` 的原生纯
  Python 实现（可解析被 sstrip 掉节表的固件 ELF），pwntools 的
  `checksec` 二进制仅作为回退
- 去掉了对 `mofuzz` / `ndisec` 私有配置的依赖：IDA 路径只读
  `IDADIR` / `IDA_DIR` 环境变量；输出基目录默认模块下 `output/`，
  可用 `ROOTFS_ELF_OUT` 覆盖

功能：
- RootFS 扫描与 ELF 识别
- 任务编排（resume/force/timeout/retry）
- `checksec` 解析与索引生成
- 可选 IDA 单 ELF 导出（strings/imports/exports/data/decompile）
- 输出目录结构与 `summary.json`

直接运行（在仓库根目录）：

```bash
python -m tools.ida-no-mcp.rootfs_elf.cli /path/to/rootfs --progress
```

说明：
- CLI 默认会分析 `ET_EXEC` 和 `ET_DYN`
- 也就是说现代 PIE 可执行文件和 `.so` 默认都会进入扫描队列

如果要导出 IDA 结果：

```bash
IDA_DIR=/opt/ida-pro-9.1 python -m tools.ida-no-mcp.rootfs_elf.cli \
    /path/to/rootfs --run-ida --workers 4 --progress
```

常用参数：
- `-o, --out-dir` 指定输出目录
- `--include-so` 包含共享库 `ET_DYN`，当前 CLI 默认已开启
- `--exclude` 用正则排除路径
- `--max-bytes` 跳过过大的文件
- `--run-ida` 启用 IDA 导出
- `--skip-memory` 不导出内存段
- `--no-decompile-funcs` 不导出逐函数反编译
- `--no-function-index` 不导出函数索引
