"""Probe 4: lumina UI action with control action + debug flags.

Run (with and without -A):
  TVHEADLESS=1 idat [-A] "-S/path/probe_lumina4.py <out.json>" <binary-or-.i64>
"""

import json
import os
import time
import traceback

import ida_auto
import ida_pro
import idaapi
import idautils
import idc

report = {"steps": [], "error": None}


def step(name, **kw):
    kw["step"] = name
    report["steps"].append(kw)


def named_stats():
    total = named = sub = 0
    for ea in idautils.Functions():
        total += 1
        n = idc.get_func_name(ea) or ""
        if n.startswith("sub_"):
            sub += 1
        elif n:
            named += 1
    return {"total": total, "named": named, "sub_": sub}


def main():
    out = "probe_lumina4_result.json"
    try:
        argv = [str(a) for a in idc.ARGV]
        if len(argv) > 1:
            out = argv[1]
    except Exception:  # noqa: BLE001
        pass
    try:
        import ida_kernwin as kw

        try:
            kw.set_debug_flags(kw.IDA_DEBUG_LUMINA)
            step("set_debug_flags IDA_DEBUG_LUMINA", ok=True)
        except Exception as exc:  # noqa: BLE001
            step("set_debug_flags", error=repr(exc))

        ida_auto.auto_wait()
        step("baseline", **named_stats())

        # control: an action that must always work in a live UI
        t0 = time.time()
        ok = kw.process_ui_action("About", 0)
        step("control About", ok=bool(ok), elapsed=round(time.time() - t0, 2))

        t0 = time.time()
        ok = kw.process_ui_action("LuminaPullAllMds", 0)
        step("LuminaPullAllMds flag0", ok=bool(ok),
             elapsed=round(time.time() - t0, 2))
        ida_auto.auto_wait()
        step("after pull", **named_stats())

        t0 = time.time()
        ok = kw.process_ui_action("LuminaPullAllMds", 1)
        step("LuminaPullAllMds flag1", ok=bool(ok),
             elapsed=round(time.time() - t0, 2))
        ida_auto.auto_wait()
        step("after pull flag1", **named_stats())

    except Exception as exc:  # noqa: BLE001
        report["error"] = "%s: %s\n%s" % (type(exc).__name__, exc,
                                          traceback.format_exc())
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    os.sync()
    ida_pro.qexit(0)


main()
