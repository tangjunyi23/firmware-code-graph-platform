# IDA headless smoke test: count functions, decompile the largest one.
# Run: TVHEADLESS=1 idat -A -S/path/ida_smoke.py <binary>
# Result is written to <binary>.smoke.json (headless stdout is unreliable).
import json
import os

import ida_auto
import idaapi
import idautils
import ida_hexrays
import ida_pro
import idc

result = {"hexrays": False, "functions": 0, "sample": None, "error": None}
try:
    ida_auto.auto_wait()
    funcs = list(idautils.Functions())
    result["functions"] = len(funcs)
    named = sum(1 for ea in funcs if not idc.get_func_name(ea).startswith("sub_"))
    result["named_functions"] = named

    if ida_hexrays.init_hexrays_plugin():
        result["hexrays"] = True
        best_ea, best_len = None, 0
        for ea in funcs:
            f = idaapi.get_func(ea)
            if f and f.size() > best_len:
                best_ea, best_len = ea, f.size()
        if best_ea is not None:
            cfunc = ida_hexrays.decompile(best_ea)
            lines = str(cfunc).splitlines() if cfunc else []
            result["sample"] = {
                "name": idc.get_func_name(best_ea),
                "addr": hex(best_ea),
                "size": best_len,
                "lines": len(lines),
                "head": lines[:5],
            }
except Exception as e:  # noqa: BLE001
    result["error"] = repr(e)

out = idaapi.get_input_file_path() + ".smoke.json"
with open(out, "w") as fh:
    json.dump(result, fh, indent=2)
os.sync()
ida_pro.qexit(0)
