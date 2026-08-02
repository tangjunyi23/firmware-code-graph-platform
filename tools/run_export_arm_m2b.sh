#!/bin/bash
# M2b official rerun, ARM only (mips sig set not final yet).
set -x
export TVHEADLESS=1
export FLIRT_SIGS=1
IDAT=/home/tankuku/ida-pro-9.1/idat
EXPORT=/home/tankuku/firmware-graph/fwgraph/pipeline/decompile/ida_export.py
S=/home/tankuku/firmware-graph/samples
OUT=$S/export_m2b
mkdir -p "$OUT"
[ -f "$S/busybox-armv7l.i64.m2b-bak" ] || cp "$S/busybox-armv7l.i64" "$S/busybox-armv7l.i64.m2b-bak"
"$IDAT" -A "-S$EXPORT $OUT/arm" "$S/busybox-armv7l.i64" > "$OUT/arm.log" 2>&1
echo ARM_EXPORT rc=$?
