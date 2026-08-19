#!/bin/bash
# M2b official rerun: ida_export.py with FLIRT_SIGS=1 on both busybox IDBs.
# Backs up the pristine .i64 files first (the export applies sigs in-place
# and IDA saves the database on qexit).
set -x
export TVHEADLESS=1
export FLIRT_SIGS=1
IDAT="${IDAT:-/home/tankuku/ida-pro-9.1/idat}"
EXPORT="${EXPORT:-/home/tankuku/firmware-graph/fwgraph/pipeline/decompile/ida_export.py}"
S="${SAMPLES:-/home/tankuku/firmware-graph/samples}"
OUT=$S/export_m2b
mkdir -p "$OUT"
[ -f "$S/busybox-mips.i64.m2b-bak" ] || cp "$S/busybox-mips.i64" "$S/busybox-mips.i64.m2b-bak"
[ -f "$S/busybox-armv7l.i64.m2b-bak" ] || cp "$S/busybox-armv7l.i64" "$S/busybox-armv7l.i64.m2b-bak"
"$IDAT" -A "-S$EXPORT $OUT/mips" "$S/busybox-mips.i64" > "$OUT/mips.log" 2>&1
echo MIPS_EXPORT rc=$?
"$IDAT" -A "-S$EXPORT $OUT/arm" "$S/busybox-armv7l.i64" > "$OUT/arm.log" 2>&1
echo ARM_EXPORT rc=$?
