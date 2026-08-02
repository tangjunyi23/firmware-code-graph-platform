"""IDA headless rename applier (M3). Separate from ida_export.py on purpose.

Run:
  TVHEADLESS=1 idat -A "-S/path/ida_apply_renames.py <renames.json> <md5>" \
      <binary.i64>

renames.json maps md5 -> {addr: new_name}; only the section for <md5> is
applied. Each rename is idc.set_name(ea, sanitized) (IDA-illegal characters
are replaced); afterwards the IDB is saved in place so the second-pass export
sees the new names.

Writes (headless stdout is unreliable -> everything goes to files):
  <renames_dir>/<md5>/apply_renames_done.json
  (i.e. data/pseudocode/<job>/<md5>/apply_renames_done.json, since the
  runner passes data/pseudocode/<job>/renames.json)
"""

import json
import os
import re
import time
import traceback
from datetime import datetime, timezone

import ida_auto
import ida_funcs
import ida_pro
import idaapi
import idc

_IDA_ILLEGAL = re.compile(r"[^A-Za-z0-9_.$?@]")


def _now():
    return datetime.now(timezone.utc).isoformat()


def _resolve_args():
    """(renames_path, md5) from idc.ARGV, skipping the input database path."""
    input_abs = os.path.abspath(idaapi.get_input_file_path())
    args = []
    try:
        argv = [str(a) for a in idc.ARGV]
    except Exception:  # noqa: BLE001
        argv = []
    for arg in argv[1:]:
        if arg.lower().endswith((".i64", ".idb", ".id0", ".id1", ".id2")):
            continue
        if os.path.abspath(arg) == input_abs:
            continue
        args.append(arg)
    if not args:
        raise RuntimeError("usage: ida_apply_renames.py <renames.json> <md5>")
    return args[0], (args[1] if len(args) > 1 else None)


def _sanitize(name):
    """Make a name acceptable to idc.set_name (keep it close to the spec)."""
    cleaned = _IDA_ILLEGAL.sub("_", name.strip())
    if cleaned and cleaned[0].isdigit():
        cleaned = "f_" + cleaned
    return cleaned[:120]


def _set_name(ea, name):
    try:
        return bool(idc.set_name(ea, name, idc.SN_CHECK))
    except Exception:  # noqa: BLE001
        return False


def _save_idb():
    path = idc.get_idb_path()
    for saver in (
            lambda: __import__("ida_loader").save_database(path, 0),
            lambda: idc.save_database(path, 0),
    ):
        try:
            saver()
            return True
        except Exception:  # noqa: BLE001 - try the next API shape
            continue
    return False


def main():
    t0 = time.time()
    done = {"status": "ok", "input": idaapi.get_input_file_path(),
            "renames": 0, "applied": 0, "failed": 0, "saved": False,
            "failures": [], "elapsed_seconds": 0.0, "finished_at": None,
            "error": None}
    done_path = None
    try:
        renames_path, md5 = _resolve_args()
        outdir = os.path.join(os.path.dirname(os.path.abspath(renames_path)),
                              md5 or "")
        os.makedirs(outdir, exist_ok=True)
        done_path = os.path.join(outdir, "apply_renames_done.json")

        with open(renames_path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        section = payload.get(md5, {}) if md5 else {}
        done["renames"] = len(section)

        ida_auto.auto_wait()
        for addr_str, new_name in section.items():
            try:
                ea = int(addr_str, 16)
            except (TypeError, ValueError):
                done["failed"] += 1
                done["failures"].append({"addr": addr_str, "error": "bad addr"})
                continue
            if ida_funcs.get_func(ea) is None:
                done["failed"] += 1
                done["failures"].append({"addr": addr_str,
                                         "error": "not a function"})
                continue
            name = _sanitize(new_name)
            ok = _set_name(ea, name)
            if not ok:  # last-resort disambiguation inside IDA
                ok = _set_name(ea, name + "_a")
            if ok:
                done["applied"] += 1
            else:
                done["failed"] += 1
                done["failures"].append({"addr": addr_str, "name": new_name,
                                         "error": "set_name rejected"})
        done["saved"] = _save_idb()
        if not done["saved"]:
            done["status"] = "error"
            done["error"] = "could not save IDB"
    except Exception as exc:  # noqa: BLE001 - fatal: still report, then exit 1
        done["status"] = "error"
        done["error"] = "{}: {}\n{}".format(type(exc).__name__, exc,
                                            traceback.format_exc())
    done["elapsed_seconds"] = round(time.time() - t0, 2)
    done["finished_at"] = _now()
    if done_path is None:
        done_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "apply_renames_done.json")
    with open(done_path, "w", encoding="utf-8") as fh:
        json.dump(done, fh, indent=1)
    os.sync()
    ida_pro.qexit(0 if done["status"] == "ok" else 1)


main()
