"""Probe 5: lumina via ida_hexrays.decompile_many(VDRUN_LUMINA), headless.

Run:
  TVHEADLESS=1 idat -A "-S/path/probe_lumina5.py <out.json>" <binary-or-.i64>
"""

import json
import os
import time
import traceback

import ida_auto
import ida_funcs
import ida_hexrays
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
    lumina_named = 0
    for ea in idautils.Functions():
        total += 1
        n = idc.get_func_name(ea) or ""
        f = ida_funcs.get_func(ea)
        if f is not None and (f.flags & ida_funcs.FUNC_LUMINA):
            lumina_named += 1
        if n.startswith("sub_"):
            sub += 1
        elif n:
            named += 1
    return {"total": total, "named": named, "sub_": sub,
            "FUNC_LUMINA": lumina_named}


def main():
    out = "probe_lumina5_result.json"
    try:
        argv = [str(a) for a in idc.ARGV]
        if len(argv) > 1:
            out = argv[1]
    except Exception:  # noqa: BLE001
        pass
    try:
        ida_auto.auto_wait()
        step("baseline", **named_stats())

        if not ida_hexrays.init_hexrays_plugin():
            step("init_hexrays_plugin", ok=False)
        else:
            step("init_hexrays_plugin", ok=True)
            # decompile a slice of functions with VDRUN_LUMINA: if lumina
            # metadata reaches us, those functions should get named.
            eas = []
            it = idautils.Functions()
            for i, ea in enumerate(it):
                if i % 10 == 0:  # ~330 funcs, keeps the probe quick
                    eas.append(ea)
            vec = ida_pro.uint64vec_t()
            for ea in eas:
                vec.append(ea)
            flags = (ida_hexrays.VDRUN_LUMINA | ida_hexrays.VDRUN_SILENT
                     | ida_hexrays.VDRUN_NEWFILE)
            t0 = time.time()
            ok = ida_hexrays.decompile_many(out + ".c", vec, flags)
            step("decompile_many VDRUN_LUMINA", ok=bool(ok), nfuncs=len(eas),
                 elapsed=round(time.time() - t0, 2))
            ida_auto.auto_wait()
            step("after", **named_stats())
            # sample of newly named functions
            sample = []
            for ea in eas:
                n = idc.get_func_name(ea) or ""
                if n and not n.startswith("sub_"):
                    sample.append((hex(ea), n))
            step("named_sample", n=len(sample), names=sample[:30])

    except Exception as exc:  # noqa: BLE001
        report["error"] = "%s: %s\n%s" % (type(exc).__name__, exc,
                                          traceback.format_exc())
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    os.sync()
    ida_pro.qexit(0)


main()
