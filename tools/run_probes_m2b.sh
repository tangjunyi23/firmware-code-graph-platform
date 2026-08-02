#!/bin/bash
# M2b probes: apply candidate FLIRT sigs to copies of the busybox IDBs.
export TVHEADLESS=1
IDAT=/home/tankuku/ida-pro-9.1/idat
PROBE=/home/tankuku/firmware-graph/fwgraph/libc-sigs/apply_sig_probe.py
"$IDAT" -A "-S$PROBE /tmp/probe_mips_src.json fwgraph_uclibc_mips.sig" /tmp/probe_mips_src.i64 > /tmp/probe_mips_src.log 2>&1
echo MIPS_DONE rc=$?
"$IDAT" -A "-S$PROBE /tmp/probe_arm_tc.json fwgraph_uclibc_arm.sig" /tmp/probe_arm_tc.i64 > /tmp/probe_arm_tc.log 2>&1
echo ARM_DONE rc=$?
