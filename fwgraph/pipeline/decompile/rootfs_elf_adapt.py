"""Adapt rootfs_elf (ida_worker) output to fwgraph's symbols/functions layout.

rootfs_elf writes:
  function_index.jsonl
  decompile/<name>_<EA>.c     /* func-name / func-address / callers / callees */
  functions/<addr>.asm        optional IDA disassembly (same header as ida_export)
  exports.txt                 addr:name
  source.c                    optional whole-binary Hex-Rays dump

fwgraph consumes:
  functions/<addr>.c          first line `// addr= name= arch= size=`
  functions/<addr>.asm        same header; CFG / 函数页汇编
  symbols_raw.json            {meta, functions:[{addr,name,calls,strings,...}]}
  export_done.json
"""

from __future__ import annotations
import json
import re
import shutil
import subprocess
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

_OBJDUMP_LINE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*\s+)?(\S.*)$"
)
_OBJDUMP_ARCH = {
    ("mips", 32, "be"): ("mips:isa32", "big"),
    ("mips", 32, "le"): ("mips:isa32", "little"),
    ("mips", 64, "be"): ("mips:isa64", "big"),
    ("mips", 64, "le"): ("mips:isa64", "little"),
    ("arm", 32, "le"): ("arm", "little"),
    ("arm", 32, "be"): ("arm", "big"),
    ("arm", 64, "le"): ("aarch64", "little"),
    ("arm", 64, "be"): ("aarch64", "big"),
    ("x86", 32, "le"): ("i386", "little"),
    ("x86", 64, "le"): ("i386:x86-64", "little"),
}


def _objdump_spec(binary: dict) -> tuple[str, str] | None:
    arch = str(binary.get("arch") or "").lower()
    bits = int(binary.get("bits") or 0)
    endian = str(binary.get("endianness") or "").lower()
    if arch in {"aarch64", "arm64"}:
        arch, bits = "arm", 64
    elif arch in {"i386", "i686"}:
        arch, bits = "x86", 32
    elif arch in {"amd64", "x86_64"}:
        arch, bits = "x86", 64
    elif arch.startswith("mips64"):
        bits = 64
        arch = "mips"
    elif arch.startswith("mips"):
        arch = "mips"
    elif arch.startswith("arm"):
        arch = "arm"
    return _OBJDUMP_ARCH.get((arch, bits, endian))


def _asm_header(ea: int, name: str, arch_tag: str, size: int) -> str:
    return f"// addr={hex(ea)} name={name} arch={arch_tag} size={size}\n"


def _rewrite_asm_header(path: Path, ea: int, name: str, arch_tag: str, size: int) -> None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    body = text
    if text.startswith("// addr="):
        nl = text.find("\n")
        body = text[nl + 1:] if nl != -1 else ""
    path.write_text(_asm_header(ea, name, arch_tag, size) + body, encoding="utf-8")


def _write_asm_via_objdump(elf: Path, dest: Path, ea: int, name: str,
                           arch_tag: str, size: int, binary: dict) -> bool:
    spec = _objdump_spec(binary)
    objdump = shutil.which("objdump")
    if spec is None or not objdump or not elf.is_file() or size <= 0:
        return False
    machine, endian = spec
    cmd = [
        objdump, "-d", "-z", "--no-show-raw-insn",
        f"--start-address={ea}", f"--stop-address={ea + size}",
        "-m", machine, f"--endian={endian}", str(elf),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False
    if proc.returncode != 0:
        return False
    lines = [_asm_header(ea, name, arch_tag, size)]
    for raw in proc.stdout.splitlines():
        match = _OBJDUMP_LINE.match(raw)
        if not match:
            continue
        addr = int(match.group(1), 16)
        if addr < ea or addr >= ea + size:
            continue
        insn = match.group(2).strip()
        if insn.startswith("..."):
            continue
        comment = insn.find("\t#")
        if comment != -1:
            insn = insn[:comment].rstrip()
        comment = insn.find("  #")
        if comment != -1:
            insn = insn[:comment].rstrip()
        lines.append(f"{addr:08x}: {insn}\n")
    if len(lines) < 2:
        return False
    dest.write_text("".join(lines), encoding="utf-8")
    return True

def _elf_section_end(elf: Path, ea: int) -> int | None:
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return None
    try:
        with elf.open("rb") as fh:
            elffile = ELFFile(fh)
            for sec in elffile.iter_sections():
                start = int(sec["sh_addr"])
                end = start + int(sec["sh_size"])
                if start <= ea < end:
                    return end
    except Exception:
        return None
    return None


def _infer_missing_sizes(index: list[dict], elf: Path | None) -> None:
    """Fill size=0 rows from the next function, else the ELF section end."""
    parsed: list[tuple[int, dict, int]] = []
    for row in index:
        ea = _ea(row.get("address"))
        if ea is None:
            continue
        try:
            size = int(row.get("size") or 0)
        except (TypeError, ValueError):
            size = 0
        parsed.append((ea, row, size))
    parsed.sort(key=lambda item: item[0])
    last_end: int | None = None
    for i, (ea, row, size) in enumerate(parsed):
        if size > 0:
            row["size"] = size
            continue
        if i + 1 < len(parsed):
            row["size"] = max(0, parsed[i + 1][0] - ea)
            continue
        if elf is not None and last_end is None:
            last_end = _elf_section_end(elf, ea)
        if last_end is not None and last_end > ea:
            row["size"] = last_end - ea
        else:
            row["size"] = 0

def adapt_rootfs_elf_outdir(outdir: Path, binary: dict | None = None,
                            elf_path: Path | None = None) -> dict:
    """Write functions/<addr>.c/.asm, symbols_raw.json, export_done.json.

    Returns the export_done payload. status=error when the worker produced
    neither a function index nor any per-function decompile files.
    """
    outdir = Path(outdir)
    binary = binary or {}
    index = _parse_function_index(outdir / "function_index.jsonl")
    decomp_map = _index_decompile_files(outdir / "decompile")
    if not index:
        index = _records_from_decompile_dir(decomp_map)

    elf = Path(elf_path) if elf_path else None
    _infer_missing_sizes(index, elf)

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
    asm_count = 0
    for row in index:
        ea = _ea(row.get("address"))
        if ea is None:
            continue
        name = str(row.get("name") or addr_to_name.get(ea) or f"sub_{ea:X}")
        size = int(row.get("size") or 0)
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
            header = _asm_header(ea, name, arch_tag, size)
            text = header + body
            if not text.endswith("\n"):
                text += "\n"
            (funcs_dir / f"{hex(ea)}.c").write_text(text, encoding="utf-8")

        asm_path = funcs_dir / f"{hex(ea)}.asm"
        if asm_path.is_file():
            _rewrite_asm_header(asm_path, ea, name, arch_tag, size)
            asm_count += 1
        elif elf is not None and _write_asm_via_objdump(
                elf, asm_path, ea, name, arch_tag, size, binary):
            asm_count += 1

        is_exported = ea in exports or name in {"main", "_start"}
        records.append({
            "addr": hex(ea),
            "name": name,
            "size": size,
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
        "asm_functions": asm_count,
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
