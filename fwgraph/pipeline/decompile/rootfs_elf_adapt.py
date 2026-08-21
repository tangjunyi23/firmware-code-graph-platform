"""Adapt rootfs_elf (ida_worker) output to fwgraph's symbols/functions layout.

rootfs_elf writes:
  function_index.jsonl
  decompile/<name>_<EA>.c     /* func-name / func-address / callers / callees */
  exports.txt                 addr:name
  source.c                    optional whole-binary Hex-Rays dump

fwgraph consumes:
  functions/<addr>.c          first line `// addr= name= arch= size=`
  symbols_raw.json            {meta, functions:[{addr,name,calls,strings,...}]}
  export_done.json
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

_FUNC_ADDR_RE = re.compile(r"func-address:\s*(0x[0-9a-fA-F]+)")
_FUNC_NAME_RE = re.compile(r"func-name:\s*(.+)")
_C_STRING_RE = re.compile(r'"((?:[^"\\]|\\.){4,200})"')
_MAX_STRINGS = 32


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ea(value) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value).strip(), 16) if str(value).strip().lower().startswith("0x") \
            else int(str(value).strip(), 0)
    except (TypeError, ValueError):
        return None


def _parse_function_index(path: Path) -> list[dict]:
    rows = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def _decompile_body(text: str) -> str:
    stripped = text.lstrip()
    if stripped.startswith("/*"):
        end = stripped.find("*/")
        if end != -1:
            return stripped[end + 2:].lstrip("\n")
    return text


def _index_decompile_files(decompile_dir: Path) -> dict[int, Path]:
    mapping: dict[int, Path] = {}
    if not decompile_dir.is_dir():
        return mapping
    for path in decompile_dir.glob("*.c"):
        try:
            head = path.read_text(encoding="utf-8", errors="ignore")[:800]
        except OSError:
            continue
        match = _FUNC_ADDR_RE.search(head)
        if match:
            mapping[int(match.group(1), 16)] = path
            continue
        stem = path.stem
        if "_" in stem:
            try:
                mapping[int(stem.rsplit("_", 1)[-1], 16)] = path
            except ValueError:
                continue
    return mapping


def _parse_exports(path: Path) -> set[int]:
    found: set[int] = set()
    if not path.is_file():
        return found
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        addr = line.split(":", 1)[0].strip()
        ea = _ea(addr)
        if ea is not None:
            found.add(ea)
    return found


def _extract_strings(text: str) -> list[str]:
    out = []
    seen = set()
    for match in _C_STRING_RE.finditer(text):
        raw = match.group(1)
        value = raw.encode("utf-8", "backslashreplace").decode("unicode_escape", "replace")
        value = value.strip()
        if len(value) < 4 or value in seen:
            continue
        seen.add(value)
        out.append(value[:200])
        if len(out) >= _MAX_STRINGS:
            break
    return out


def _records_from_decompile_dir(decomp_map: dict[int, Path]) -> list[dict]:
    rows = []
    for ea, path in sorted(decomp_map.items()):
        name = f"sub_{ea:X}"
        try:
            head = path.read_text(encoding="utf-8", errors="ignore")[:800]
        except OSError:
            head = ""
        match = _FUNC_NAME_RE.search(head)
        if match:
            name = match.group(1).strip()
        rows.append({
            "name": name,
            "address": hex(ea),
            "callees": [],
            "callers": [],
            "is_entry_candidate": name in {"main", "_start", "start", "entry"},
        })
    return rows


def adapt_rootfs_elf_outdir(outdir: Path, binary: dict | None = None) -> dict:
    """Write functions/<addr>.c, symbols_raw.json, export_done.json.

    Returns the export_done payload. status=error when the worker produced
    neither a function index nor any per-function decompile files.
    """
    outdir = Path(outdir)
    binary = binary or {}
    index = _parse_function_index(outdir / "function_index.jsonl")
    decomp_map = _index_decompile_files(outdir / "decompile")
    if not index:
        index = _records_from_decompile_dir(decomp_map)

    addr_to_name: dict[int, str] = {}
    for row in index:
        ea = _ea(row.get("address"))
        if ea is None:
            continue
        addr_to_name[ea] = str(row.get("name") or f"sub_{ea:X}")

    exports = _parse_exports(outdir / "exports.txt")
    arch = str(binary.get("arch") or "")
    bits = binary.get("bits") or ""
    endian = str(binary.get("endianness") or "")
    arch_tag = f"{arch}{bits}{endian}"

    funcs_dir = outdir / "functions"
    funcs_dir.mkdir(parents=True, exist_ok=True)

    records = []
    decompiled = 0
    for row in index:
        ea = _ea(row.get("address"))
        if ea is None:
            continue
        name = str(row.get("name") or addr_to_name.get(ea) or f"sub_{ea:X}")
        callees = []
        for callee in row.get("callees") or []:
            cea = _ea(callee)
            if cea is None:
                continue
            callees.append(addr_to_name.get(cea) or hex(cea))
        src_path = decomp_map.get(ea)
        decompile_ok = False
        decompile_error = None
        body = ""
        if src_path is not None and src_path.is_file():
            raw = src_path.read_text(encoding="utf-8", errors="replace")
            body = _decompile_body(raw)
            decompile_ok = bool(body.strip())
            if decompile_ok:
                decompiled += 1
            else:
                decompile_error = "empty decompilation result"
        else:
            decompile_error = "no per-function decompile"

        if decompile_ok:
            header = f"// addr={hex(ea)} name={name} arch={arch_tag} size=0\n"
            text = header + body
            if not text.endswith("\n"):
                text += "\n"
            (funcs_dir / f"{hex(ea)}.c").write_text(text, encoding="utf-8")

        is_exported = ea in exports or name in {"main", "_start"}
        records.append({
            "addr": hex(ea),
            "name": name,
            "size": 0,
            "lines": len(body.splitlines()) if decompile_ok else 0,
            "calls": callees,
            "strings": _extract_strings(body) if decompile_ok else [],
            "is_exported": is_exported,
            "decompile_ok": decompile_ok,
            "decompile_error": decompile_error,
        })

    meta = {
        "exporter": "rootfs_elf",
        "arch": arch or None,
        "bits": binary.get("bits"),
        "endianness": endian or None,
        "hexrays": decompiled > 0,
    }
    (outdir / "symbols_raw.json").write_text(
        json.dumps({"meta": meta, "functions": records}, indent=1),
        encoding="utf-8")

    done = {
        "status": "ok",
        "exporter": "rootfs_elf",
        "outdir": str(outdir.resolve()),
        "functions": len(records),
        "decompiled": decompiled,
        "decompile_failed": sum(1 for r in records if not r["decompile_ok"]),
        "export_errors": 0,
        "finished_at": _now(),
        "error": None,
    }
    if not records:
        done["status"] = "error"
        done["error"] = "rootfs_elf produced no functions"
    (outdir / "export_done.json").write_text(
        json.dumps(done, indent=2), encoding="utf-8")
    return done
