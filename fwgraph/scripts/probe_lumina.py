"""Probe: what Lumina surface does IDA 9.1 headless IDAPython expose?

Run:
  TVHEADLESS=1 idat -A "-S/path/probe_lumina.py <out.json>" <binary-or-.i64>

Writes a JSON report to <out.json> (default: probe_lumina_result.json next
to the input file). Never raises; always qexit(0).
"""

import json
import os
import time
import traceback

import ida_auto
import ida_funcs
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
    out = "probe_lumina_result.json"
    try:
        argv = [str(a) for a in idc.ARGV]
        if len(argv) > 1:
            out = argv[1]
    except Exception:  # noqa: BLE001
        pass
    try:
        # 1. is there an ida_lumina module?
        try:
            import ida_lumina  # noqa: F401
            step("import ida_lumina", ok=True,
                 attrs=[a for a in dir(ida_lumina) if not a.startswith("_")])
        except Exception as exc:  # noqa: BLE001
            step("import ida_lumina", ok=False, error=repr(exc))

        # 2. lumina-ish attrs on the usual modules
        import ida_kernwin
        import ida_nalt
        for mod in (idc, idaapi, ida_kernwin, ida_nalt, ida_funcs):
            hits = [a for a in dir(mod) if "lumina" in a.lower()]
            step("dir(%s)" % mod.__name__, lumina_attrs=hits)

        # 3. baseline stats after autoanalysis
        ida_auto.auto_wait()
        step("baseline", **named_stats())

        # 4. try to trigger the kernel Lumina pull via UI action
        try:
            import ida_kernwin as kw
            t0 = time.time()
            ok = kw.process_ui_action("LuminaPullAllMds", 0)
            step("process_ui_action LuminaPullAllMds", ok=bool(ok),
                 elapsed=round(time.time() - t0, 2))
            ida_auto.auto_wait()
            step("after_pull", **named_stats())
        except Exception as exc:  # noqa: BLE001
            step("process_ui_action LuminaPullAllMds", ok=False,
                 error=repr(exc), trace=traceback.format_exc())

        # 5. view-all to learn what the kernel thinks is available
        try:
            import ida_kernwin as kw
            ok = kw.process_ui_action("LuminaViewAllMds", 0)
            step("process_ui_action LuminaViewAllMds", ok=bool(ok))
        except Exception as exc:  # noqa: BLE001
            step("process_ui_action LuminaViewAllMds", ok=False, error=repr(exc))

    except Exception as exc:  # noqa: BLE001
        report["error"] = "%s: %s\n%s" % (type(exc).__name__, exc,
                                          traceback.format_exc())
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    os.sync()
    ida_pro.qexit(0)


main()
