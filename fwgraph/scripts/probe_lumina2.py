"""Probe 2: registered UI actions + alternative lumina triggers (headless).

Run:
  TVHEADLESS=1 idat -A "-S/path/probe_lumina2.py <out.json>" <binary-or-.i64>
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
    out = "probe_lumina2_result.json"
    try:
        argv = [str(a) for a in idc.ARGV]
        if len(argv) > 1:
            out = argv[1]
    except Exception:  # noqa: BLE001
        pass
    try:
        import ida_kernwin as kw

        step("kernwin action-ish attrs",
             attrs=[a for a in dir(kw) if "action" in a.lower()])

        # enumerate registered actions
        acts = None
        try:
            acts = kw.get_registered_actions()
            step("get_registered_actions", n=len(acts),
                 lumina=[a for a in acts if "lumina" in a.lower()])
        except Exception as exc:  # noqa: BLE001
            step("get_registered_actions", error=repr(exc))

        ida_auto.auto_wait()
        step("baseline", **named_stats())

        # try every lumina action that is actually registered
        for name in (acts or []):
            if "lumina" not in name.lower():
                continue
            try:
                t0 = time.time()
                ok = kw.process_ui_action(name, 0)
                step("process_ui_action " + name, ok=bool(ok),
                     elapsed=round(time.time() - t0, 2))
            except Exception as exc:  # noqa: BLE001
                step("process_ui_action " + name, error=repr(exc))
        ida_auto.auto_wait()
        step("after_actions", **named_stats())

        # check FUNC_LUMINA flags currently set on any function
        import ida_funcs
        n_lum = 0
        for ea in idautils.Functions():
            f = ida_funcs.get_func(ea)
            if f is not None and (f.flags & ida_funcs.FUNC_LUMINA):
                n_lum += 1
        step("funcs_with_FUNC_LUMINA", count=n_lum)

    except Exception as exc:  # noqa: BLE001
        report["error"] = "%s: %s\n%s" % (type(exc).__name__, exc,
                                          traceback.format_exc())
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    os.sync()
    ida_pro.qexit(0)


main()
