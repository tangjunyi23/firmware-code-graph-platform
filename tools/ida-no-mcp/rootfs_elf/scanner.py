from __future__ import annotations
import os
import re
import struct
import stat
from typing import Iterable, Optional, List, Callable

from .model_types import ElfInfo, RootfsAnalyzeOptions
from .utils import iter_files, sha256_file


_ELF_MAGIC = b"\x7fELF"

_ELF_TYPE_MAP = {
    2: "ET_EXEC",
    3: "ET_DYN",
}

_ARCH_MAP = {
    0x03: "x86",
    0x08: "mips",
    0x14: "powerpc",
    0x28: "arm",
    0x3E: "x86_64",
    0xB7: "aarch64",
    0xF3: "riscv",
}


class ElfParseError(RuntimeError):
    pass


def _read_elf_header(path: str) -> bytes:
    with open(path, "rb") as f:
        data = f.read(0x40)
    if len(data) < 0x20:
        raise ElfParseError("ELF header too small")
    if data[:4] != _ELF_MAGIC:
        raise ElfParseError("not an ELF file")
    return data


def parse_elf_info(path: str, rel_path: str) -> ElfInfo:
    header = _read_elf_header(path)
    ei_class = header[4]
    ei_data = header[5]

    bits = 32 if ei_class == 1 else 64 if ei_class == 2 else 0
    endian = "little" if ei_data == 1 else "big" if ei_data == 2 else "unknown"
    if bits == 0 or endian == "unknown":
        raise ElfParseError("unknown ELF class/endian")

    fmt_prefix = "<" if endian == "little" else ">"
    e_type, e_machine = struct.unpack(fmt_prefix + "HH", header[0x10:0x14])

    elf_type = _ELF_TYPE_MAP.get(e_type, f"UNKNOWN({e_type})")
    arch = _ARCH_MAP.get(e_machine, f"unknown(0x{e_machine:x})")

    size = os.path.getsize(path)
    sha256 = sha256_file(path)

    return ElfInfo(
        path=path,
        rel_path=rel_path,
        size=size,
        sha256=sha256,
        arch=arch,
        bits=bits,
        endian=endian,
        elf_type=elf_type,
    )


def _should_skip_type(elf_type: str, options: RootfsAnalyzeOptions) -> bool:
    if options.only_exec:
        return elf_type != "ET_EXEC"

    if options.include_so:
        return elf_type not in {"ET_EXEC", "ET_DYN"}

    return elf_type != "ET_EXEC"


def scan_rootfs(
    rootfs_dir: str,
    options: RootfsAnalyzeOptions,
    *,
    total_files: Optional[int] = None,
    progress_cb: Optional[Callable[[int, Optional[int], int], None]] = None,
) -> List[ElfInfo]:
    regex = re.compile(options.exclude) if options.exclude else None
    results: List[ElfInfo] = []
    scanned = 0

    for path in iter_files(rootfs_dir):
        scanned += 1
        rel_path = os.path.relpath(path, rootfs_dir)
        if regex and regex.search(rel_path):
            if progress_cb and scanned % options.progress_every == 0:
                progress_cb(scanned, total_files, len(results))
            continue

        try:
            try:
                st = os.lstat(path)
            except OSError:
                if progress_cb and scanned % options.progress_every == 0:
                    progress_cb(scanned, total_files, len(results))
                continue

            if not stat.S_ISREG(st.st_mode):
                if progress_cb and scanned % options.progress_every == 0:
                    progress_cb(scanned, total_files, len(results))
                continue

            if options.max_bytes is not None:
                if st.st_size > options.max_bytes:
                    continue

            with open(path, "rb") as f:
                if f.read(4) != _ELF_MAGIC:
                    if progress_cb and scanned % options.progress_every == 0:
                        progress_cb(scanned, total_files, len(results))
                    continue

            elf_info = parse_elf_info(path, rel_path)
            if _should_skip_type(elf_info.elf_type, options):
                continue

            results.append(elf_info)
            if progress_cb and scanned % options.progress_every == 0:
                progress_cb(scanned, total_files, len(results))
        except (OSError, ElfParseError):
            if progress_cb and scanned % options.progress_every == 0:
                progress_cb(scanned, total_files, len(results))
            continue

    if progress_cb:
        progress_cb(scanned, total_files, len(results))

    return results
