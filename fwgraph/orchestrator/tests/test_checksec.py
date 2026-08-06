"""Unit tests for pipeline.extract.checksec (native checksec).

Fixtures are synthetic minimal ELFs built byte by byte (ELF32/ELF64 LE),
so every check (nx/canary/pie/relro/fortify) is exercised deterministically
without pwntools or real firmware files. Also covers build_manifest wiring.
"""

import json
import struct

import pytest

from orchestrator.app import extractor
from pipeline.extract import checksec
from pipeline.extract.checksec import ChecksecError


def _build_elf32(e_type=2, gnu_stack_flags=None, relro=False,
                 bind_now=False, imports=()):
    strtab = b"\x00"
    name_offs = []
    for name in imports:
        name_offs.append(len(strtab))
        strtab += name.encode() + b"\x00"

    symtab = b"\x00" * 16  # null symbol
    for off in name_offs:
        symtab += struct.pack("<IIIBBH", off, 0, 0, 0x12, 0, 0)  # undef FUNC

    nchain = 1 + len(imports)
    hashsec = struct.pack("<II", 1, nchain) + b"\x00" * (4 + 4 * nchain)

    n_dirents = 5 + bool(bind_now) + 1
    phnum = 2 + (gnu_stack_flags is not None) + relro
    phoff = 52
    phentsize = 32
    dyn_off = phoff + phnum * phentsize
    hash_off = dyn_off + n_dirents * 8
    sym_off = hash_off + len(hashsec)
    str_off = sym_off + len(symtab)
    total = str_off + len(strtab)

    def va(off):
        return 0x1000 + off

    dyn_entries = [(4, va(hash_off)), (5, va(str_off)), (6, va(sym_off)),
                   (10, len(strtab)), (11, 16)]
    if bind_now:
        dyn_entries.append((30, 0x8))
    dyn_entries.append((0, 0))
    assert len(dyn_entries) == n_dirents
    dynamic = b"".join(struct.pack("<iI", t, v) for t, v in dyn_entries)

    phdrs = [struct.pack("<IIIIIIII", 1, 0, 0x1000, 0x1000, total, total, 5, 0x1000)]
    if gnu_stack_flags is not None:
        phdrs.append(struct.pack("<IIIIIIII", 0x6474E551, 0, 0, 0, 0, 0,
                                 gnu_stack_flags, 0))
    if relro:
        phdrs.append(struct.pack("<IIIIIIII", 0x6474E552, 0, 0x1000, 0x1000,
                                 0x100, 0x100, 4, 0x10))
    phdrs.append(struct.pack("<IIIIIIII", 2, dyn_off, va(dyn_off), va(dyn_off),
                             len(dynamic), len(dynamic), 6, 4))

    ehdr = b"\x7fELF" + bytes([1, 1, 1]) + b"\x00" * 9
    ehdr += struct.pack("<HHIIIIIHHHHHH", e_type, 8, 1, 0x1000, phoff, 0, 0,
                        52, phentsize, phnum, 0, 0, 0)
    blob = ehdr + b"".join(phdrs) + dynamic + hashsec + symtab + strtab
    assert len(blob) == total
    return blob


def _build_elf64(e_type=3, gnu_stack_flags=6):
    phoff, phentsize, phnum = 64, 56, 2
    total = phoff + phnum * phentsize
    ehdr = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9
    ehdr += struct.pack("<HHIQQQIHHHHHH", e_type, 0x3E, 1, 0x1000, phoff, 0, 0,
                        64, phentsize, phnum, 0, 0, 0)
    phdrs = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x1000, 0x1000, total, total, 0x1000)
    phdrs += struct.pack("<IIQQQQQQ", 0x6474E551, gnu_stack_flags, 0, 0, 0, 0, 0, 0)
    return ehdr + phdrs


def test_full_hardening(tmp_path):
    p = tmp_path / "full"
    p.write_bytes(_build_elf32(
        gnu_stack_flags=6, relro=True, bind_now=True,
        imports=("__stack_chk_guard", "__memcpy_chk", "memcpy", "system")))
    assert checksec.checksec(p) == {
        "canary": True, "nx": True, "pie": False, "relro": "full",
        "fortified": 1, "fortifyable": 1,
    }


def test_no_hardening(tmp_path):
    p = tmp_path / "weak"
    p.write_bytes(_build_elf32(gnu_stack_flags=7, imports=("strcpy", "gets")))
    out = checksec.checksec(p)
    assert out["canary"] is False
    assert out["nx"] is False
    assert out["pie"] is False
    assert out["relro"] == "none"
    assert out["fortified"] == 0
    assert out["fortifyable"] == 2


def test_partial_relro_and_pie(tmp_path):
    p = tmp_path / "pie"
    p.write_bytes(_build_elf32(e_type=3, gnu_stack_flags=6, relro=True))
    out = checksec.checksec(p)
    assert out["pie"] is True
    assert out["relro"] == "partial"


def test_nx_unknown_without_gnu_stack(tmp_path):
    p = tmp_path / "legacy"
    p.write_bytes(_build_elf32(gnu_stack_flags=None))
    assert checksec.checksec(p)["nx"] is None


def test_elf64_smoke(tmp_path):
    p = tmp_path / "pie64"
    p.write_bytes(_build_elf64())
    out = checksec.checksec(p)
    assert out["pie"] is True
    assert out["nx"] is True
    assert out["fortified"] == 0


def test_non_elf_rejected(tmp_path):
    p = tmp_path / "blob"
    p.write_bytes(b"not an elf")
    with pytest.raises(ChecksecError):
        checksec.checksec(p)


def test_build_manifest_adds_checksec(tmp_path):
    log_dir = tmp_path / "logs"
    csv_dir = log_dir / "csv_logs"
    csv_dir.mkdir(parents=True)
    elf = _build_elf32(gnu_stack_flags=6, imports=("__stack_chk_guard",))
    (log_dir / "firmware").mkdir()
    (log_dir / "firmware" / "httpd").write_bytes(elf)
    (csv_dir / "p99_prepare_analyzer.csv").write_text(
        "P99_prepare_analyzer;/logs/firmware/httpd;ELF32;"
        "2's complement, little endian;MIPSR3000;0x0,;NA;"
        "ELF 32-bit LSB executable, MIPS, MIPS-I version 1 (SYSV), "
        "statically linked, stripped;" + "a" * 32 + ";\n", encoding="utf-8")
    manifest = extractor.build_manifest("jobtest", "fw.bin", log_dir)
    binary = manifest["binaries"][0]
    assert binary["checksec"]["canary"] is True
    assert binary["checksec"]["nx"] is True


def test_build_manifest_checksec_failure_isolated(tmp_path):
    log_dir = tmp_path / "logs"
    csv_dir = log_dir / "csv_logs"
    csv_dir.mkdir(parents=True)
    (log_dir / "firmware").mkdir()
    # binary listed in the csv does not exist on disk -> checksec must not
    # break manifest generation
    (csv_dir / "p99_prepare_analyzer.csv").write_text(
        "P99_prepare_analyzer;/logs/firmware/missing;ELF32;"
        "2's complement, little endian;MIPSR3000;0x0,;NA;"
        "ELF 32-bit LSB executable, MIPS, MIPS-I version 1 (SYSV), "
        "statically linked, stripped;" + "b" * 32 + ";\n", encoding="utf-8")
    manifest = extractor.build_manifest("jobtest", "fw.bin", log_dir)
    assert manifest["binaries"][0]["checksec"] is None
