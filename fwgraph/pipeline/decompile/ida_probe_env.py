# Probe: lumina availability + flirt-apply API surface in IDA 9.1.
import json
import ida_auto
import ida_pro
import idaapi

result = {"lumina": None, "sig_api": [], "lumina_api": []}

try:
    ida_auto.auto_wait()
except Exception:
    pass

try:
    import ida_lumina
    result["lumina"] = "module_found"
    result["lumina_api"] = [n for n in dir(ida_lumina) if not n.startswith("_")]
except ImportError as e:
    result["lumina"] = f"no_module: {e}"
except Exception as e:  # noqa: BLE001
    result["lumina"] = f"error: {e!r}"

for modname in ("ida_search", "ida_funcs", "ida_name", "idc", "idaapi", "ida_diskio"):
    try:
        mod = __import__(modname)
        for n in dir(mod):
            low = n.lower()
            if "sig" in low and "design" not in low and "assign" not in low:
                result["sig_api"].append(f"{modname}.{n}")
            if "lumina" in low:
                result["lumina_api"].append(f"{modname}.{n}")
    except Exception:
        pass

out = idaapi.get_input_file_path() + ".probe.json"
with open(out, "w") as fh:
    json.dump(result, fh, indent=2)
ida_pro.qexit(0)
