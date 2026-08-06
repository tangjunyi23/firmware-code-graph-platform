from __future__ import annotations
import argparse
import json
import os
import re
import sys
from typing import Dict, List, Set

try:
    from .config import ensure_ida_env
except ImportError:
    from config import ensure_ida_env

IDA_IMPORTED = False


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", errors="ignore") as f:
        f.write(text)


def _append_log(path: str, text: str) -> None:
    if not path:
        return
    with open(path, "a", encoding="utf-8", errors="ignore") as f:
        f.write(text)
        if not text.endswith("\n"):
            f.write("\n")


def _export_strings(out_dir: str) -> None:
    path = os.path.join(out_dir, "strings.txt")
    with open(path, "w", encoding="utf-8", errors="ignore") as f:
        f.write("# Strings\n")
        f.write("# Format: address | length | type | string\n")
        f.write("#" + "=" * 80 + "\n\n")
        for s in idautils.Strings():
            try:
                str_type = "ASCII"
                if s.strtype == ida_nalt.STRTYPE_C_16:
                    str_type = "UTF-16"
                elif s.strtype == ida_nalt.STRTYPE_C_32:
                    str_type = "UTF-32"
                content = str(s).replace("\n", "\\n").replace("\r", "\\r")
                f.write(f"{hex(s.ea)} | {s.length} | {str_type} | {content}\n")
            except Exception:
                continue


def _export_imports(out_dir: str) -> None:
    path = os.path.join(out_dir, "imports.txt")
    with open(path, "w", encoding="utf-8", errors="ignore") as f:
        f.write("# Imports\n")
        f.write("# Format: addr:name\n")
        f.write("#" + "=" * 60 + "\n\n")
        for i in range(ida_nalt.get_import_module_qty()):
            def _cb(ea, name, ordinal):
                if name:
                    f.write(f"{hex(ea)}:{name}\n")
                else:
                    f.write(f"{hex(ea)}:ordinal_{ordinal}\n")
                return True
            ida_nalt.enum_import_names(i, _cb)


def _export_exports(out_dir: str) -> None:
    path = os.path.join(out_dir, "exports.txt")
    with open(path, "w", encoding="utf-8", errors="ignore") as f:
        f.write("# Exports\n")
        f.write("# Format: addr:name\n")
        f.write("#" + "=" * 60 + "\n\n")
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal)
            if name:
                f.write(f"{hex(ea)}:{name}\n")
            else:
                f.write(f"{hex(ea)}:ordinal_{ordinal}\n")


def _export_data_symbols(out_dir: str) -> None:
    path = os.path.join(out_dir, "data_symbols.txt")
    with open(path, "w", encoding="utf-8", errors="ignore") as f:
        f.write("# Data symbols\n")
        f.write("# Format: address | size | segment | type | name | value\n")
        f.write("#" + "=" * 80 + "\n\n")
        for seg_idx in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(seg_idx)
            if seg is None:
                continue
            seg_name = ida_segment.get_segm_name(seg)
            ea = seg.start_ea
            while ea < seg.end_ea:
                flags = idc.get_full_flags(ea)
                if not idc.is_data(flags):
                    ea = idc.next_head(ea, seg.end_ea)
                    continue
                size = ida_bytes.get_item_size(ea)
                if size <= 0:
                    ea = idc.next_head(ea, seg.end_ea)
                    continue
                name = idc.get_name(ea) or f"data_{ea:X}"
                type_str = idc.get_type(ea) or ""
                value_str = ""
                if idc.is_strlit(flags):
                    s = idc.get_strlit_contents(ea, -1, idc.get_str_type(ea))
                    if s is not None:
                        try:
                            value_str = repr(s.decode("utf-8", errors="ignore"))
                        except AttributeError:
                            value_str = repr(s)
                # value 为空则不输出该行
                if not value_str:
                    ea += size
                    continue
                f.write(
                    f"{hex(ea)} | {size} | {seg_name} | {type_str} | {name} | {value_str}\n"
                )
                ea += size


def _filter_data_symbols_by_strings(out_dir: str) -> None:
    strings_path = os.path.join(out_dir, "strings.txt")
    data_path = os.path.join(out_dir, "data_symbols.txt")
    if not os.path.exists(strings_path) or not os.path.exists(data_path):
        return

    string_addrs = set()
    with open(strings_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            if not parts:
                continue
            addr_str = parts[0]
            if addr_str.startswith("0x"):
                try:
                    string_addrs.add(int(addr_str, 16))
                except ValueError:
                    pass

    kept_lines = []
    with open(data_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                kept_lines.append(line)
                continue
            parts = [p.strip() for p in line.split("|")]
            if not parts:
                kept_lines.append(line)
                continue
            addr_str = parts[0]
            if addr_str.startswith("0x"):
                try:
                    addr_val = int(addr_str, 16)
                except ValueError:
                    kept_lines.append(line)
                    continue
                if addr_val in string_addrs:
                    continue
            kept_lines.append(line)

    with open(data_path, "w", encoding="utf-8", errors="ignore") as f:
        f.writelines(kept_lines)


def _get_callers(func_ea: int) -> List[int]:
    callers: List[int] = []
    for ref in idautils.XrefsTo(func_ea, 0):
        if idc.is_code(idc.get_full_flags(ref.frm)):
            caller_func = ida_funcs.get_func(ref.frm)
            if caller_func:
                callers.append(caller_func.start_ea)
    return sorted(set(callers))


def _get_callees(func_ea: int) -> List[int]:
    callees: List[int] = []
    func = ida_funcs.get_func(func_ea)
    if not func:
        return callees
    for head in idautils.Heads(func.start_ea, func.end_ea):
        if idc.is_code(idc.get_full_flags(head)):
            for ref in idautils.XrefsFrom(head, 0):
                if ref.type in (ida_xref.fl_CF, ida_xref.fl_CN):
                    callee_func = ida_funcs.get_func(ref.to)
                    if callee_func:
                        callees.append(callee_func.start_ea)
    return sorted(set(callees))


def _build_entry_line_index(source_path: str, func_names: Set[str]) -> Dict[str, int]:
    entry_line: Dict[str, int] = {}
    try:
        with open(source_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return entry_line

    # Improved regex to match Hex-Rays function definitions
    # Matches: type name(args) or name(args)
    # Ex: int __cdecl main(int argc, ...)
    # Ex: sub_401000()
    pattern = re.compile(
        r"^\s*"  # leading whitespace
        r"(?:(?:[a-zA-Z_]\w*\s+)+)?"  # optional return type and modifiers (int __cdecl ...)
        r"(?P<name>[a-zA-Z_]\w*)"  # function name
        r"\s*\("  # opening parenthesis
    )
    
    for idx, line in enumerate(lines, start=1):
        if not line.strip() or line.strip().startswith("//") or line.strip().startswith("/*"):
            continue
            
        m = pattern.match(line)
        if not m:
            continue
            
        name = m.group("name")
        # Ensure it's not a function call by checking if it's followed by { or declaration ;
        # However, in source.c from decompile_many, definitions usually have { on same or next line.
        # But here we just match the header line.
        if name in func_names and name not in entry_line:
            entry_line[name] = idx
            
    return entry_line


def _is_entry_candidate(name: str) -> bool:
    lname = name.lower()
    if name in {"main", "_start", "start", "entry"}:
        return True
    
    # Common embedded/IoT entry points and service keywords
    keywords = {
        "init", "daemon", "server", "service", "http", "listen", 
        "handle", "process", "loop", "dispatch", "run", "exec",
        "rc", "handler", "callback"
    }
    
    for kw in keywords:
        if kw in lname:
            return True
            
    return False


def _export_function_index(out_dir: str, source_path: str) -> None:
    funcs = list(idautils.Functions())
    func_names = {idc.get_func_name(ea) for ea in funcs}
    entry_line_map = _build_entry_line_index(source_path, func_names)

    index_path = os.path.join(out_dir, "function_index.jsonl")
    with open(index_path, "w", encoding="utf-8", errors="ignore") as f:
        for ea in funcs:
            name = idc.get_func_name(ea)
            callers = _get_callers(ea)
            callees = _get_callees(ea)
            entry_line = entry_line_map.get(name, 0)
            is_entry = _is_entry_candidate(name)
            entry_reason = ""
            if is_entry:
                if name in {"main", "_start"}:
                    entry_reason = f"symbol {name}"
                elif "init" in name.lower():
                    entry_reason = "name contains init"
                elif "daemon" in name.lower():
                    entry_reason = "name contains daemon"
            obj = {
                "name": name,
                "address": hex(ea),
                "filename": "source.c",
                "entry_line": entry_line,
                "callers": [hex(x) for x in callers],
                "callees": [hex(x) for x in callees],
                "is_entry_candidate": is_entry,
                "entry_reason": entry_reason,
            }
            f.write(json.dumps(obj, ensure_ascii=False))
            f.write("\n")


def _export_decompiled_functions(out_dir: str) -> None:
    decompile_dir = os.path.join(out_dir, "decompile")
    _ensure_dir(decompile_dir)

    failed = []
    skipped = []

    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        name = idc.get_func_name(func_ea)
        if func is None:
            skipped.append((func_ea, name, "not a valid function"))
            continue
        if func.flags & ida_funcs.FUNC_LIB:
            skipped.append((func_ea, name, "library function"))
            continue

        try:
            dec_obj = ida_hexrays.decompile(func_ea)
            if dec_obj is None:
                failed.append((func_ea, name, "decompile returned None"))
                continue
            dec_str = str(dec_obj)
            if not dec_str or not dec_str.strip():
                failed.append((func_ea, name, "empty decompilation result"))
                continue

            callers = _get_callers(func_ea)
            callees = _get_callees(func_ea)

            safe_name = re.sub(r"[<>:\"/\\\\|?*]", "_", name).replace(".", "_")
            if len(safe_name) > 200:
                safe_name = safe_name[:200]
            output_filename = f"{safe_name}_{func_ea:X}.c"
            output_path = os.path.join(decompile_dir, output_filename)

            lines = [
                "/*",
                f" * func-name: {name}",
                f" * func-address: {hex(func_ea)}",
                f" * callers: {', '.join(hex(x) for x in callers) if callers else 'none'}",
                f" * callees: {', '.join(hex(x) for x in callees) if callees else 'none'}",
                " */",
                "",
                dec_str,
            ]
            _write_text(output_path, "\n".join(lines))
        except ida_hexrays.DecompilationFailure as exc:
            failed.append((func_ea, name, f"decompilation failure: {exc}"))
        except Exception as exc:
            failed.append((func_ea, name, f"unexpected error: {exc}"))

    if failed:
        path = os.path.join(out_dir, "decompile_failed.txt")
        with open(path, "w", encoding="utf-8", errors="ignore") as f:
            f.write("# Failed to decompile functions\n")
            f.write("# Format: address | function_name | reason\n")
            f.write("#" + "=" * 80 + "\n\n")
            for addr, name, reason in failed:
                f.write(f"{hex(addr)} | {name} | {reason}\n")

    if skipped:
        path = os.path.join(out_dir, "decompile_skipped.txt")
        with open(path, "w", encoding="utf-8", errors="ignore") as f:
            f.write("# Skipped functions\n")
            f.write("# Format: address | function_name | reason\n")
            f.write("#" + "=" * 80 + "\n\n")
            for addr, name, reason in skipped:
                f.write(f"{hex(addr)} | {name} | {reason}\n")


def _export_memory(out_dir: str) -> None:
    memory_dir = os.path.join(out_dir, "memory")
    _ensure_dir(memory_dir)

    chunk_size = 1 * 1024 * 1024
    bytes_per_line = 16

    for seg_idx in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(seg_idx)
        if seg is None:
            continue
        seg_name = ida_segment.get_segm_name(seg)
        seg_start = seg.start_ea
        seg_end = seg.end_ea

        current_addr = seg_start
        while current_addr < seg_end:
            chunk_end = min(current_addr + chunk_size, seg_end)
            filename = f"{current_addr:08X}--{chunk_end:08X}.txt"
            filepath = os.path.join(memory_dir, filename)
            with open(filepath, "w", encoding="utf-8", errors="ignore") as f:
                f.write(f"# Memory dump: {hex(current_addr)} - {hex(chunk_end)}\n")
                f.write(f"# Segment: {seg_name}\n")
                f.write("#" + "=" * 76 + "\n\n")
                f.write("# Address        | Hex Bytes                                       | ASCII\n")
                f.write("#" + "-" * 76 + "\n")

                addr = current_addr
                while addr < chunk_end:
                    line_bytes = []
                    for i in range(bytes_per_line):
                        if addr + i < chunk_end:
                            byte_val = ida_bytes.get_byte(addr + i)
                            line_bytes.append(byte_val if byte_val is not None else 0)
                        else:
                            break
                    if not line_bytes:
                        addr += bytes_per_line
                        continue
                    hex_part = ""
                    for i, b in enumerate(line_bytes):
                        hex_part += f"{b:02X} "
                        if i == 7:
                            hex_part += " "
                    remaining = bytes_per_line - len(line_bytes)
                    if remaining > 0:
                        if len(line_bytes) <= 8:
                            hex_part += " "
                        hex_part += "   " * remaining

                    ascii_part = ""
                    for b in line_bytes:
                        if 0x20 <= b <= 0x7E:
                            ascii_part += chr(b)
                        else:
                            ascii_part += "."

                    f.write(f"{addr:016X} | {hex_part.ljust(49)} | {ascii_part}\n")
                    addr += bytes_per_line

            current_addr = chunk_end


def _import_ida() -> None:
    global IDA_IMPORTED
    if IDA_IMPORTED:
        return
    ensure_ida_env()
    ida_dir = os.environ.get("IDADIR", "")
    if ida_dir:
        idalib_python = os.path.join(ida_dir, "idalib", "python")
        if os.path.isdir(idalib_python) and idalib_python not in sys.path:
            sys.path.insert(0, idalib_python)

    # Lazy import to allow setting IDADIR before loading idapro
    global idapro, ida_auto, ida_bytes, ida_entry, ida_funcs, ida_hexrays, ida_nalt
    global ida_segment, ida_xref, idautils, idc
    import idapro
    import ida_auto
    import ida_bytes
    import ida_entry
    import ida_funcs
    import ida_hexrays
    import ida_nalt
    import ida_segment
    import ida_xref
    import idautils
    import idc

    IDA_IMPORTED = True


def export_all(
    elf_path: str,
    out_dir: str,
    skip_memory: bool,
    no_decompile_funcs: bool,
    no_function_index: bool,
    log_path: str,
) -> None:
    _import_ida()
    _ensure_dir(out_dir)
    _append_log(log_path, f"[start] {elf_path}")
    idapro.enable_console_messages(False)

    # Create the database in the writable output directory to avoid
    # "Permission denied" when the source binary is on a read-only filesystem
    db_path = os.path.join(out_dir, "database.i64")
    idapro.open_database(elf_path, True, f"-o{db_path}")

    ida_auto.auto_wait()
    _append_log(log_path, "[analysis] auto_wait done")

    if ida_hexrays.init_hexrays_plugin():
        source_path = os.path.join(out_dir, "source.c")
        flags = (
            ida_hexrays.VDRUN_NEWFILE
            | ida_hexrays.VDRUN_SILENT
            | ida_hexrays.VDRUN_MAYSTOP
        )
        ida_hexrays.decompile_many(source_path, None, flags)
        _append_log(log_path, "[decompile] source.c exported")
    else:
        source_path = os.path.join(out_dir, "source.c")
        _write_text(source_path, "/* hexrays unavailable */\n")
        _append_log(log_path, "[decompile] hexrays unavailable")

    _export_strings(out_dir)
    _append_log(log_path, "[export] strings.txt")
    _export_imports(out_dir)
    _append_log(log_path, "[export] imports.txt")
    _export_exports(out_dir)
    _append_log(log_path, "[export] exports.txt")
    _export_data_symbols(out_dir)
    _append_log(log_path, "[export] data_symbols.txt")
    _filter_data_symbols_by_strings(out_dir)
    _append_log(log_path, "[export] data_symbols filtered")

    if not no_function_index:
        _export_function_index(out_dir, source_path)
        _append_log(log_path, "[export] function_index.jsonl")

    if not no_decompile_funcs:
        _export_decompiled_functions(out_dir)
        _append_log(log_path, "[export] decompile/*.c")

    if not skip_memory:
        _export_memory(out_dir)
        _append_log(log_path, "[export] memory/")

    idapro.close_database(False)
    _append_log(log_path, "[done]")


def main() -> None:
    ensure_ida_env()
    parser = argparse.ArgumentParser("IDA single-ELF exporter")
    parser.add_argument("--elf", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--skip-memory", action="store_true", default=False)
    parser.add_argument("--no-decompile-funcs", action="store_true", default=False)
    parser.add_argument("--no-function-index", action="store_true", default=False)
    parser.add_argument("--ida-dir", default=None, help="IDA install root for idalib")
    parser.add_argument("--log-path", default=None, help="Write progress log to file")
    args = parser.parse_args()

    if args.ida_dir:
        os.environ.setdefault("IDADIR", args.ida_dir)

    try:
        export_all(
            args.elf,
            args.out_dir,
            skip_memory=args.skip_memory,
            no_decompile_funcs=args.no_decompile_funcs,
            no_function_index=args.no_function_index,
            log_path=args.log_path or "",
        )
    except Exception as exc:
        _append_log(args.log_path or "", f"[error] {exc}")
        raise


if __name__ == "__main__":
    main()
