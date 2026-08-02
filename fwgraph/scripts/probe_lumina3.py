"""Probe 3: why do the registered Lumina actions refuse to activate?

Run:
  TVHEADLESS=1 idat -A "-S/path/probe_lumina3.py <out.json>" <binary-or-.i64>
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
    out = "probe_lumina3_result.json"
    try:
        argv = [str(a) for a in idc.ARGV]
        if len(argv) > 1:
            out = argv[1]
    except Exception:  # noqa: BLE001
        pass
    try:
        import ida_kernwin as kw

        step("kernel_version", v=idaapi.get_kernel_version())
        step("kw open-ish attrs", attrs=[a for a in dir(kw)
                                         if a.startswith(("open", "get_current",
                                                          "activate", "find_widget"))])

        for name in ("LuminaPullAllMds", "LuminaViewAllMds", "About"):
            info = {"action": name}
            for fn in ("get_action_state", "is_action_enabled",
                       "get_action_label", "get_action_visibility"):
                try:
                    info[fn] = getattr(kw, fn)(name)
                except Exception as exc:  # noqa: BLE001
                    info[fn] = "ERR " + repr(exc)
            step("action info", **info)

        ida_auto.auto_wait()
        step("baseline", **named_stats())

        # try to give the action a widget context, then activate again
        try:
            w = None
            for opener in ("open_functions_window", "open_disasm_window"):
                if hasattr(kw, opener):
                    try:
                        if opener == "open_disasm_window":
                            w = getattr(kw, opener)(idautils.Functions()[0])
                        else:
                            w = getattr(kw, opener)()
                        step("opened widget", opener=opener, widget=str(w))
                        break
                    except Exception as exc:  # noqa: BLE001
                        step("open widget failed", opener=opener, error=repr(exc))
            if w is not None:
                try:
                    kw.activate_widget(w, True)
                    step("activate_widget", ok=True)
                except Exception as exc:  # noqa: BLE001
                    step("activate_widget", error=repr(exc))
                t0 = time.time()
                ok = kw.process_ui_action("LuminaPullAllMds", 0)
                step("process_ui_action with widget", ok=bool(ok),
                     elapsed=round(time.time() - t0, 2))
                step("after_pull", **named_stats())
        except Exception as exc:  # noqa: BLE001
            step("widget path", error=repr(exc), trace=traceback.format_exc())

    except Exception as exc:  # noqa: BLE001
        report["error"] = "%s: %s\n%s" % (type(exc).__name__, exc,
                                          traceback.format_exc())
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    os.sync()
    ida_pro.qexit(0)


main()
