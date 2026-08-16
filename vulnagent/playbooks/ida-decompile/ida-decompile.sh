#!/bin/bash
# ida-decompile.sh — 全自动 IDA headless 反编译脚本
#
# 用法:
#   ./ida-decompile.sh <binary_path> [output_dir]
#
# 示例:
#   ./ida-decompile.sh /path/to/httpd
#   ./ida-decompile.sh /path/to/httpd /path/to/output/
#
# 输出结构:
#   <output_dir>/
#     decompile/        每个函数一个 .c 文件（含 callers/callees 元数据）
#     strings.txt       字符串表（地址+内容）
#     imports.txt       导入表
#     exports.txt       导出表
#     memory/           内存 hexdump（1MB 分片）
#     function_index.txt 函数调用关系索引
#     decompile_failed.txt  反编译失败列表
#     decompile_skipped.txt 跳过函数列表

set -euo pipefail

BINARY="${1:?用法: $0 <binary_path> [output_dir]}"
OUTPUT_DIR="${2:-}"

IDA_BIN="${IDA_PATH:-$HOME/ida-pro-9.1/idat}"
IDA_DIR="$(dirname "$IDA_BIN")"
INP_SCRIPT="$HOME/.idapro/plugins/INP.py"
IDAUSR="${IDAUSR:-$HOME/.idapro}"

# 检查依赖
if [ ! -f "$IDA_BIN" ]; then
    echo "[ERROR] idat not found at: $IDA_BIN"
    exit 1
fi

if [ ! -f "$INP_SCRIPT" ]; then
    echo "[ERROR] INP.py not found at: $INP_SCRIPT"
    echo "[INFO]  Installing from GitHub..."
    mkdir -p "$(dirname "$INP_SCRIPT")"
    curl -s https://raw.githubusercontent.com/P4nda0s/IDA-NO-MCP/main/INP.py -o "$INP_SCRIPT"
fi

if [ ! -f "$BINARY" ]; then
    echo "[ERROR] Binary not found: $BINARY"
    exit 1
fi

# 确定输出目录
if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="$(dirname "$BINARY")/decompile-export"
fi

mkdir -p "$OUTPUT_DIR"

BINARY_ABS="$(realpath "$BINARY")"
OUTPUT_ABS="$(realpath "$OUTPUT_DIR")"

# IDA 数据库目录：必须可写，使用输出目录避免只读系统目录问题
IDB_PATH="$OUTPUT_ABS/$(basename "$BINARY_ABS").i64"

echo "=========================================="
echo " IDA Headless Decompile"
echo " Binary : $BINARY_ABS"
echo " Output : $OUTPUT_ABS"
echo " IDA    : $IDA_BIN"
echo " IDB    : $IDB_PATH"
echo "=========================================="

# 临时覆盖 idapython.cfg 中的 SCRIPT_TIMEOUT，防止大型二进制超时
TEMP_CFG="$OUTPUT_ABS/.idapython_tmp.cfg"
cp "$IDA_DIR/cfg/idapython.cfg" "$TEMP_CFG" 2>/dev/null || true
if [ -f "$TEMP_CFG" ]; then
    sed -i 's/SCRIPT_TIMEOUT = [0-9]*/SCRIPT_TIMEOUT = 0/' "$TEMP_CFG"
fi

# IDA headless 模式:
#   -A  : autonomous（无对话框）
#   -c  : 强制重新分析（不复用旧 idb）
#   -o  : 指定数据库输出路径（避免写入只读目录）
#   -S  : 执行脚本，传入 output_dir 和 skip_analysis=1
# INP.py __main__ 块执行完后自动 idc.qexit(0)

IDAUSR="$IDAUSR" \
IDALOG="$OUTPUT_ABS/ida.log" \
    "$IDA_BIN" -A -c \
    -o"$IDB_PATH" \
    -S"$INP_SCRIPT $OUTPUT_ABS 0" \
    "$BINARY_ABS" 2>&1

rm -f "$TEMP_CFG"

EXIT_CODE=$?

echo ""
echo "=========================================="
if [ $EXIT_CODE -eq 0 ]; then
    echo "[+] 反编译完成"
    echo "    输出目录: $OUTPUT_ABS"
    FUNC_COUNT=$(ls "$OUTPUT_ABS/decompile/"*.c 2>/dev/null | wc -l || echo 0)
    echo "    反编译函数数: $FUNC_COUNT"
else
    echo "[!] IDA 退出码: $EXIT_CODE（非零不一定是失败，idc.qexit 有时返回非零）"
    echo "    检查输出目录: $OUTPUT_ABS"
fi
echo "=========================================="
