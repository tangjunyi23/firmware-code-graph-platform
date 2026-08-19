"""IDA headless pseudo-C export (M2, extended in M2b).

Run:
  TVHEADLESS=1 idat -A "-S/path/ida_export.py [outdir]" <binary-or-.i64>

The output dir travels inside the -S argument: in IDA 9.1 a plain trailing
token after the input file never reaches idc.ARGV (verified by probe).
When input is an existing .i64, IDA opens the database and skips reloading,
which is much faster than analyzing the ELF again. Default outdir:
<input>.export/.

M2b: optional naming-recovery steps between auto_wait() and the export loop.
Both are env-gated, and any failure is only recorded in export_done.json --
the export itself always proceeds.

  LUMINA_ENABLED=1   pull Lumina metadata via a headless batch decompile
                     (ida_hexrays.decompile_many with VDRUN_LUMINA; the only
                     lumina trigger that works under TVHEADLESS on IDA 9.1 --
                     see docs/m2b-notes.md). With this install's license the
                     server answers "lumina: bad signature", i.e. the pull is
                     rejected; the step then costs one extra batch decompile
                     and names nothing. Default off.
  FLIRT_SIGS         comma list of short .sig names to apply with
                     ida_funcs.plan_to_apply_idasgn(), or "1" to apply every
                     fwgraph_*.sig installed in <ida>/sig/<proc>/. Sigs are
                     produced by libc-sigs/build_sig.sh. Default off.

Writes (headless stdout is unreliable -> everything goes to files):
  <outdir>/functions/<addr>.c   pseudo-C per function; first line is
                                // addr=0x.. name=.. arch=.. size=..
  <outdir>/functions/<addr>.asm disassembly per function (same header);
                                input for the AI enrichment overlay
  <outdir>/symbols_raw.json     {"meta": ..., "functions": [...]}
  <outdir>/export_done.json     run stats; also written (status=error) when
                                the run dies with a fatal exception
"""

import json
import os
import time
import traceback
from datetime import datetime, timezone

import ida_auto
import ida_entry
import ida_funcs
import ida_hexrays
import ida_ida
import ida_pro
import ida_segment
import idaapi
import idautils
import idc

MAX_STRING_LEN = 200
MIN_STRING_LEN = 4


def _now():
    return datetime.now(timezone.utc).isoformat()


def _resolve_outdir():
    """First idc.ARGV entry after the script path that is not the input db."""
    input_path = idaapi.get_input_file_path()
    try:
        argv = [str(a) for a in idc.ARGV]
    except Exception:  # noqa: BLE001
        argv = []
    input_abs = os.path.abspath(input_path)
    for arg in argv[1:]:
        if arg.lower().endswith((".i64", ".idb", ".id0", ".id1", ".id2")):
            continue
        if os.path.abspath(arg) == input_abs:
            continue
        return arg
    return input_path + ".export"


def _raw_entry_arg():
    """Verified raw-image reset entry passed by the orchestrator, if any."""
    try:
        argv = [str(a) for a in idc.ARGV]
    except Exception:  # noqa: BLE001
        return None
    for arg in argv[1:]:
        if arg.startswith("--raw-entry="):
            try:
                return int(arg.split("=", 1)[1], 0)
            except ValueError:
                return None
    return None


def _configure_raw_arm_database():
    """Pin a raw Cortex-M database to 32-bit before auto-analysis starts."""
    rec = {}
    try:
        rec["set_32bit"] = bool(ida_ida.inf_set_32bit(True))
        ida_ida.inf_set_app_bitness(32)
        rec["is_32bit"] = bool(ida_ida.inf_is_32bit_exactly())
        rec["is_64bit"] = bool(ida_ida.inf_is_64bit())
    except Exception as exc:  # noqa: BLE001
        rec["error"] = repr(exc)
    return rec


def _bootstrap_raw_entry(entry, database_config=None):
    """Seed Cortex-M Thumb analysis from a linker-profile-verified reset entry."""
    if entry is None:
        return None
    rec = {"entrypoint": hex(entry), "created": False, "error": None}
    if database_config is not None:
        rec["database_config"] = database_config
    try:
        segments = []
        for start in idautils.Segments():
            end = idc.get_segm_end(start)
            segments.append({
                "start": hex(start),
                "end": hex(end),
                "name": idc.get_segm_name(start),
            })
        rec["segments"] = segments
        rec["mapped"] = bool(idc.is_mapped(entry))
        raw = idc.get_bytes(entry, 8) if rec["mapped"] else None
        rec["entry_bytes"] = raw.hex() if raw else None
        seg = ida_segment.getseg(entry)
        if seg is not None:
            rec["segment_type_before"] = int(seg.type)
            rec["segment_perm_before"] = int(seg.perm)
            seg.type = ida_segment.SEG_CODE
            seg.perm |= ida_segment.SEGPERM_READ | ida_segment.SEGPERM_EXEC
            rec["segment_updated"] = bool(ida_segment.update_segm(seg))
        # Cortex-M vectors store bit 0 as the Thumb marker; the manifest keeps
        # the normalized even address and this register range preserves mode.
        idc.split_sreg_range(entry, "T", 1, idc.SR_user)
        rec["add_entry"] = bool(ida_entry.add_entry(
            entry, entry, "reset_handler", True))
        ida_auto.auto_wait()
        if ida_funcs.get_func(entry) is None:
            rec["create_insn"] = int(idc.create_insn(entry) or 0)
            ida_auto.auto_make_proc(entry)
            ida_auto.auto_wait()
            rec["auto_make_proc_created"] = ida_funcs.get_func(entry) is not None
        if ida_funcs.get_func(entry) is None:
            candidate = ida_funcs.func_t()
            candidate.start_ea = entry
            candidate.end_ea = idc.BADADDR
            rec["find_func_bounds"] = int(ida_funcs.find_func_bounds(
                candidate, ida_funcs.FIND_FUNC_DEFINE))
            rec["candidate_start"] = hex(candidate.start_ea)
            rec["candidate_end"] = hex(candidate.end_ea)
            rec["add_func_ex"] = bool(ida_funcs.add_func_ex(candidate))
            ida_auto.auto_wait()
        rec["created"] = ida_funcs.get_func(entry) is not None
        if not rec["created"]:
            rec["error"] = "IDA did not create the reset handler"
    except Exception as exc:  # noqa: BLE001
        rec["error"] = repr(exc)
    return rec


def _inf_meta():
    """Processor / bits / endianness from the opened database."""
    try:  # IDA 9.x
        import ida_ida

        procname = ida_ida.inf_get_procname()
        is64 = bool(ida_ida.inf_is_64bit())
        try:
            is32 = bool(ida_ida.inf_is_32bit())
        except Exception:  # noqa: BLE001
            is32 = not is64
        is_be = bool(ida_ida.inf_is_be())
    except Exception:  # noqa: BLE001 - IDA <= 8.x fallback
        inf = idaapi.get_inf_structure()
        procname = inf.procname
        is64 = bool(inf.is_64bit())
        is32 = bool(inf.is_32bit())
        is_be = bool(inf.is_be())
    bits = 64 if is64 else (32 if is32 else 16)
    p = (procname or "").lower()
    if p.startswith("mips"):
        arch = "mips"
    elif p.startswith("arm") or p.startswith("aarch"):
        arch = "arm64" if is64 else "arm"
    elif p.startswith("ppc"):
        arch = "ppc64" if is64 else "ppc"
    elif p.startswith("metapc") or "x86" in p or "80386" in p:
        arch = "x64" if is64 else "x86"
    elif p.startswith("riscv") or p.startswith("rv"):
        arch = "riscv"
    else:
        arch = p or "unknown"
    endian = "be" if is_be else "le"
    return {
        "procname": procname,
        "arch": arch,
        "bits": bits,
        "endianness": endian,
        "arch_tag": f"{arch}{bits}{endian}",
    }


def _entry_points():
    """Addresses of all exported symbols / ELF entry points."""
    entries = set()
    try:
        for i in range(ida_entry.get_entry_qty()):
            entries.add(ida_entry.get_entry(ida_entry.get_entry_ordinal(i)))
    except Exception:  # noqa: BLE001
        pass
    return entries


def _read_string(ea):
    """C string content at ea if it looks like real text, else None."""
    try:
        raw = idc.get_strlit_contents(ea, -1, idc.STRTYPE_C)
    except Exception:  # noqa: BLE001
        return None
    if not raw:
        return None
    text = raw.decode("utf-8", errors="replace").strip()
    if len(text) < MIN_STRING_LEN:
        return None
    printable = sum(1 for ch in text if 32 <= ord(ch) < 127)
    if printable < len(text) * 0.9:
        return None
    return text[:MAX_STRING_LEN]


def _function_refs(func):
    """(calls, strings) of a function, collected from instruction xrefs."""
    calls = {}
    strings = []
    seen_str = set()
    for item in idautils.FuncItems(func.start_ea):
        for tgt in idautils.CodeRefsFrom(item, 0):  # 0: ignore ordinary flow
            callee = ida_funcs.get_func(tgt)
            if callee is not None and callee.start_ea != func.start_ea:
                calls[callee.start_ea] = idc.get_func_name(callee.start_ea)
        for tgt in idautils.DataRefsFrom(item):
            if tgt in seen_str:
                continue
            text = _read_string(tgt)
            if text:
                seen_str.add(tgt)
                strings.append(text)
    return calls, strings


def _export_function(ea, funcs_dir, meta, entries, hexrays_ok):
    rec = {
        "addr": hex(ea),
        "name": idc.get_func_name(ea) or "",
        "size": 0,
        "lines": 0,
        "calls": [],
        "strings": [],
        "is_exported": ea in entries,
        "decompile_ok": False,
        "decompile_error": None,
    }
    func = ida_funcs.get_func(ea)
    if func is None:
        rec["decompile_error"] = "not a function"
        return rec
    rec["size"] = func.size()
    calls, strings = _function_refs(func)
    rec["calls"] = sorted(calls.values())
    rec["strings"] = strings
    # disassembly feeds the AI enrichment overlay (call-site argument
    # recovery); exported for every function, including decompile failures
    header = "// addr={} name={} arch={} size={}\n".format(
        hex(ea), rec["name"], meta["arch_tag"], rec["size"])
    with open(os.path.join(funcs_dir, hex(ea) + ".asm"), "w", encoding="utf-8") as fh:
        fh.write(header)
        for item in idautils.FuncItems(func.start_ea):
            fh.write("{:08x}: {}\n".format(
                item, idc.generate_disasm_line(item, 0) or ""))
    if not hexrays_ok:
        rec["decompile_error"] = "hexrays decompiler unavailable"
        return rec
    try:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc is None:
            rec["decompile_error"] = "decompile() returned None"
            return rec
        text = str(cfunc)
        rec["decompile_ok"] = True
        rec["lines"] = len(text.splitlines())
        header = "// addr={} name={} arch={} size={}\n".format(
            hex(ea), rec["name"], meta["arch_tag"], rec["size"])
        with open(os.path.join(funcs_dir, hex(ea) + ".c"), "w", encoding="utf-8") as fh:
            fh.write(header)
            fh.write(text)
            if not text.endswith("\n"):
                fh.write("\n")
    except Exception as exc:  # noqa: BLE001 - one bad function must not stop the run
        rec["decompile_error"] = repr(exc)
    return rec


def _write_json(path, payload):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=1)


def _name_counts():
    """(total, named, sub_, lib) over all functions."""
    total = named = sub = lib = 0
    for ea in idautils.Functions():
        total += 1
        n = idc.get_func_name(ea) or ""
        if n.startswith("sub_"):
            sub += 1
        elif n:
            named += 1
        if idc.get_func_flags(ea) & ida_funcs.FUNC_LIB:
            lib += 1
    return {"total": total, "named": named, "sub_": sub, "lib": lib}


def _lumina_pull(outdir, hexrays_ok):
    """LUMINA_ENABLED=1: pull Lumina metadata headless, never raise.

    On IDA 9.1 under TVHEADLESS the only working trigger is a batch
    decompile with VDRUN_LUMINA (probe-verified: there is no ida_lumina
    module and process_ui_action is dead in autonomous mode). With this
    install's license the server rejects the pull ("lumina: bad
    signature"), so expect named_delta=0 here.
    """
    if os.getenv("LUMINA_ENABLED", "0") != "1":
        return None
    rec = {"enabled": True, "error": None}
    try:
        if not hexrays_ok:
            rec["error"] = "hexrays unavailable, lumina pull skipped"
            return rec
        rec["before"] = _name_counts()
        vec = ida_pro.uint64vec_t()
        for ea in idautils.Functions():
            vec.append(ea)
        flags = (ida_hexrays.VDRUN_LUMINA | ida_hexrays.VDRUN_SILENT
                 | ida_hexrays.VDRUN_NEWFILE)
        rec["decompile_many_ok"] = bool(ida_hexrays.decompile_many(
            os.path.join(outdir, "lumina_decompile.c"), vec, flags))
        ida_auto.auto_wait()
        rec["after"] = _name_counts()
        rec["named_delta"] = rec["after"]["named"] - rec["before"]["named"]
    except Exception as exc:  # noqa: BLE001 - optional step, log only
        rec["error"] = repr(exc)
    return rec


def _sig_dir_name(procname):
    """Map inf procname to the IDA sig/ subdirectory."""
    p = (procname or "").lower()
    if p.startswith("mips"):
        return "mips"
    if p.startswith("arm") or p.startswith("aarch"):
        return "arm"
    if p.startswith("ppc"):
        return "ppc"
    if p.startswith("metapc") or "x86" in p:
        return "pc"
    if p.startswith("sh"):
        return "sh3"
    return p


def _apply_flirt(meta):
    """FLIRT_SIGS: apply FLIRT signature files, never raise.

    FLIRT_SIGS unset/empty/0 -> skip (returns None). "1" -> every
    fwgraph_*.sig in <ida>/sig/<proc>/. Otherwise a comma list of short
    sig names (resolved by IDA in sig/ and sig/<proc>/).
    """
    spec = os.getenv("FLIRT_SIGS", "").strip()
    if not spec or spec == "0":
        return None
    rec = {"enabled": True, "spec": spec, "planned": [], "errors": []}
    try:
        sigs = []
        if spec == "1":
            import glob as _glob
            # sig 根目录：IDA_SIG_DIR 优先，其次 idadir("sig")，再 $IDA_DIR/sig；
            # 都取不到则为 None 并跳过 sig 应用（本步骤保持容错语义，永不出错）
            sigroot = os.environ.get("IDA_SIG_DIR", "").strip() or None
            if sigroot is None:
                try:
                    sigroot = idaapi.idadir("sig")
                except Exception:  # noqa: BLE001
                    ida_dir = os.environ.get("IDA_DIR", "").strip()
                    sigroot = os.path.join(ida_dir, "sig") if ida_dir else None
            if sigroot is None:
                rec["errors"].append("no sig root (set IDA_SIG_DIR or IDA_DIR)")
            else:
                d = os.path.join(sigroot, _sig_dir_name(meta.get("procname")))
                sigs = sorted(os.path.basename(p)
                              for p in _glob.glob(os.path.join(d, "fwgraph_*.sig")))
                if not sigs:
                    rec["errors"].append("no fwgraph_*.sig in " + d)
        else:
            sigs = [s.strip() for s in spec.split(",") if s.strip()]
        rec["before"] = _name_counts()
        for sig in sigs:
            try:
                qty = ida_funcs.plan_to_apply_idasgn(sig)
                rec["planned"].append({"sig": sig, "plan_qty": qty})
                if not qty:
                    rec["errors"].append(sig + ": plan_to_apply_idasgn returned 0")
            except Exception as exc:  # noqa: BLE001
                rec["planned"].append({"sig": sig, "error": repr(exc)})
                rec["errors"].append(sig + ": " + repr(exc))
        if rec["planned"]:
            ida_auto.auto_wait()
        rec["after"] = _name_counts()
        rec["named_delta"] = rec["after"]["named"] - rec["before"]["named"]
        rec["lib_delta"] = rec["after"]["lib"] - rec["before"]["lib"]
    except Exception as exc:  # noqa: BLE001 - optional step, log only
        rec["errors"].append(repr(exc))
    return rec


def main():
    t0 = time.time()
    outdir = _resolve_outdir()
    funcs_dir = os.path.join(outdir, "functions")
    os.makedirs(funcs_dir, exist_ok=True)
    done = {
        "status": "ok",
        "input": idaapi.get_input_file_path(),
        "outdir": os.path.abspath(outdir),
        "functions": 0,
        "decompiled": 0,
        "decompile_failed": 0,
        "export_errors": 0,
        "lumina": None,
        "flirt": None,
        "raw_bootstrap": None,
        "naming": None,
        "elapsed_seconds": 0.0,
        "finished_at": None,
        "error": None,
    }
    try:
        raw_entry = _raw_entry_arg()
        raw_config = _configure_raw_arm_database() if raw_entry is not None else None
        ida_auto.auto_wait()
        done["raw_bootstrap"] = _bootstrap_raw_entry(raw_entry, raw_config)
        meta = _inf_meta()
        meta["hexrays"] = bool(ida_hexrays.init_hexrays_plugin())
        # M2b: optional naming recovery (lumina / FLIRT) before exporting so
        # recovered names land in functions/*.c and symbols_raw.json.
        done["lumina"] = _lumina_pull(outdir, meta["hexrays"])
        done["flirt"] = _apply_flirt(meta)
        entries = _entry_points()
        records = []
        for ea in idautils.Functions():
            try:
                rec = _export_function(ea, funcs_dir, meta, entries, meta["hexrays"])
            except Exception as exc:  # noqa: BLE001 - keep going no matter what
                done["export_errors"] += 1
                rec = {
                    "addr": hex(ea),
                    "name": idc.get_func_name(ea) or "",
                    "size": 0,
                    "lines": 0,
                    "calls": [],
                    "strings": [],
                    "is_exported": ea in entries,
                    "decompile_ok": False,
                    "decompile_error": "export error: " + repr(exc),
                }
            done["functions"] += 1
            if rec["decompile_ok"]:
                done["decompiled"] += 1
            else:
                done["decompile_failed"] += 1
            records.append(rec)
        _write_json(os.path.join(outdir, "symbols_raw.json"),
                    {"meta": meta, "functions": records})
        done["naming"] = _name_counts()
    except Exception as exc:  # noqa: BLE001 - fatal: still report, then exit 1
        done["status"] = "error"
        done["error"] = "{}: {}\n{}".format(type(exc).__name__, exc, traceback.format_exc())
        done["elapsed_seconds"] = round(time.time() - t0, 2)
        done["finished_at"] = _now()
        _write_json(os.path.join(outdir, "export_done.json"), done)
        os.sync()
        ida_pro.qexit(1)
        return
    done["elapsed_seconds"] = round(time.time() - t0, 2)
    done["finished_at"] = _now()
    _write_json(os.path.join(outdir, "export_done.json"), done)
    os.sync()
    ida_pro.qexit(0)


main()
