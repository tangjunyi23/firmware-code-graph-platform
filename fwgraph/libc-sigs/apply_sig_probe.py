"""Probe: apply FLIRT .sig files to the open database, headless.

Run:
  TVHEADLESS=1 idat -A "-S/path/apply_sig_probe.py <out.json> sig1.sig [sig2.sig...]" <binary-or-.i64>

Signature file names are short names (no directory); IDA resolves them in
sig/ and sig/<procname>/ of the install. Reports per-sig plan/apply state
and name stats before/after.
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


def stats():
    total = named = sub = lib = 0
    names = []
    for ea in idautils.Functions():
        total += 1
        n = idc.get_func_name(ea) or ""
        flags = idc.get_func_flags(ea)
        if flags & ida_funcs.FUNC_LIB:
            lib += 1
        if n.startswith("sub_"):
            sub += 1
        elif n:
            named += 1
            if len(names) < 40 and not n.startswith(("sub_", "nullsub",
                                                     ".init", ".fini",
                                                     "_start", "__")):
                names.append(n)
    return {"total": total, "named": named, "sub_": sub, "lib": lib,
            "sample_names": names}


def main():
    out = "apply_sig_probe_result.json"
    sigs = []
    try:
        argv = [str(a) for a in idc.ARGV]
        if len(argv) > 1:
            out = argv[1]
        sigs = argv[2:]
    except Exception:  # noqa: BLE001
        pass
    try:
        ida_auto.auto_wait()
        step("baseline", **stats())
        step("sig_plan_qty_before", qty=ida_funcs.get_idasgn_qty())

        for sig in sigs:
            try:
                t0 = time.time()
                qty = ida_funcs.plan_to_apply_idasgn(sig)
                step("plan_to_apply_idasgn", sig=sig, qty=qty,
                     elapsed=round(time.time() - t0, 2))
            except Exception as exc:  # noqa: BLE001
                step("plan_to_apply_idasgn", sig=sig, error=repr(exc))

        t0 = time.time()
        ida_auto.auto_wait()
        step("auto_wait_after_plan", elapsed=round(time.time() - t0, 2))

        # per-planned-sig states
        states = []
        try:
            qty = ida_funcs.get_idasgn_qty()
            for i in range(qty):
                states.append({"n": i,
                               "state": ida_funcs.calc_idasgn_state(i)})
        except Exception as exc:  # noqa: BLE001
            step("idasgn_states", error=repr(exc))
        step("idasgn_states", states=states,
             legend={"IDASGN_OK": 0, "IDASGN_APPLIED": 2,
                     "IDASGN_CURRENT": 3, "IDASGN_PLANNED": 4})

        step("after", **stats())

    except Exception as exc:  # noqa: BLE001
        report["error"] = "%s: %s\n%s" % (type(exc).__name__, exc,
                                          traceback.format_exc())
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    os.sync()
    ida_pro.qexit(0)


main()
