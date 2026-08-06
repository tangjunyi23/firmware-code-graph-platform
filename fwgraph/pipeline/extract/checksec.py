"""Native checksec for (possibly sstripped) ELF binaries.

Pure Python: parses program headers and the dynamic segment directly, so it
keeps working on firmware binaries whose section header table was removed
(sstrip) — exactly where the pwntools `checksec` binary degrades.

Checks and how they are decided:
  nx          PT_GNU_STACK: executable -> False, non-exec -> True, missing
              program header -> None (undecidable, e.g. pre-2004 toolchains)
  canary      dynamic imports reference __stack_chk_guard/__stack_chk_fail
  pie         e_type == ET_DYN (PIE executables and shared objects)
  relro       PT_GNU_RELRO present -> "partial"; plus DT_FLAGS/DF_BIND_NOW
              or DT_FLAGS_1/DF_1_NOW -> "full"; otherwise "none"
  fortified   number of imports ending in _chk (__memcpy_chk, ...)
  fortifyable number of imports from the usual fortify-able libc set that
              are NOT _chk variants (what FORTIFY_SOURCE could still cover)

checksec(path) -> dict; raises ChecksecError on non-ELF input.
"""

import struct
from pathlib import Path

PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PF_X = 1

DT_NEEDED = 1
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_STRSZ = 10
DT_GNU_HASH = 0x6FFFFEF5
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1

ET_DYN = 3

_CANARY_SYMBOLS = ("__stack_chk_guard", "__stack_chk_fail")
_FORTIFIABLE = (
    "memcpy", "memmove", "memset", "strcpy", "stpcpy", "strncpy", "strcat",
    "strncat", "sprintf", "snprintf", "vsprintf", "vsnprintf", "gets",
    "read", "recv", "recvfrom", "fgets", "getcwd", "realpath", "readlink",
    "wprintf", "mbstowcs", "wcscpy", "printf", "fprintf", "vprintf",
)


class ChecksecError(RuntimeError):
    pass


class _Elf:
    """Minimal ELF32/64 reader: program headers + dynamic imports."""

    def __init__(self, path):
        data = Path(path).read_bytes()
        if len(data) < 0x34 or data[:4] != b"\x7fELF":
            raise ChecksecError(f"not an ELF file: {path}")
        self.data = data
        self.is64 = data[4] == 2
        if data[4] not in (1, 2):
            raise ChecksecError(f"unknown ELF class {data[4]}: {path}")
        if data[5] == 1:
            self.e = "<"
        elif data[5] == 2:
            self.e = ">"
        else:
            raise ChecksecError(f"unknown ELF endianness {data[5]}: {path}")
        self.e_type = self._u16(16)
        phoff = self._u(32 if self.is64 else 28)
        phentsize = self._u16(54 if self.is64 else 42)
        phnum = self._u16(56 if self.is64 else 44)
        self.phdrs = []
        for i in range(phnum):
            base = phoff + i * phentsize
            if base + phentsize > len(data):
                break
            if self.is64:
                self.phdrs.append({
                    "type": self._u32(base), "flags": self._u32(base + 4),
                    "offset": self._u(base + 8), "vaddr": self._u(base + 16),
                    "filesz": self._u(base + 32),
                })
            else:
                self.phdrs.append({
                    "type": self._u32(base), "flags": self._u32(base + 24),
                    "offset": self._u32(base + 4), "vaddr": self._u32(base + 8),
                    "filesz": self._u32(base + 16),
                })

    def _u16(self, off):
        return struct.unpack_from(self.e + "H", self.data, off)[0]

    def _u32(self, off):
        return struct.unpack_from(self.e + "I", self.data, off)[0]

    def _u(self, off):
        fmt = "Q" if self.is64 else "I"
        return struct.unpack_from(self.e + fmt, self.data, off)[0]

    def _v2o(self, vaddr):
        for ph in self.phdrs:
            if ph["type"] == PT_LOAD and ph["vaddr"] <= vaddr < ph["vaddr"] + ph["filesz"]:
                return ph["offset"] + (vaddr - ph["vaddr"])
        return None

    def _dynamic_tags(self):
        dyn_off = next((ph["offset"] for ph in self.phdrs
                        if ph["type"] == PT_DYNAMIC), None)
        if dyn_off is None:
            return {}
        tags = {}
        step = 16 if self.is64 else 8
        off = dyn_off
        while off + step <= len(self.data):
            if self.is64:
                tag = struct.unpack_from(self.e + "q", self.data, off)[0]
                val = self._u(off + 8)
            else:
                tag = struct.unpack_from(self.e + "i", self.data, off)[0]
                val = self._u32(off + 4)
            off += step
            if tag == 0:
                break
            tags.setdefault(tag, val)
        return tags

    def _symbol_names(self, tags):
        """All dynamic symbol names that are undefined (imports)."""
        if DT_SYMTAB not in tags or DT_STRTAB not in tags:
            return []
        symtab = self._v2o(tags[DT_SYMTAB])
        strtab = self._v2o(tags[DT_STRTAB])
        strsz = tags.get(DT_STRSZ, 0)
        if symtab is None or strtab is None:
            return []
        syment = 24 if self.is64 else 16
        count = self._symbol_count(tags)
        names = []
        for i in range(count):
            base = symtab + i * syment
            if base + syment > len(self.data):
                break
            st_name = self._u32(base)
            if self.is64:
                st_shndx = self._u16(base + 6)
            else:
                st_shndx = self._u16(base + 14)
            if st_name == 0 or st_name >= strsz or st_shndx != 0:
                continue
            try:
                end = self.data.index(b"\x00", strtab + st_name)
            except ValueError:
                continue
            names.append(self.data[strtab + st_name:end]
                         .decode("ascii", "replace"))
        return names

    def _symbol_count(self, tags):
        if DT_HASH in tags:
            off = self._v2o(tags[DT_HASH])
            if off is not None:
                return self._u32(off + 4)  # nchain
        if DT_GNU_HASH in tags:
            off = self._v2o(tags[DT_GNU_HASH])
            if off is not None:
                return self._gnu_hash_count(off)
        return 0

    def _gnu_hash_count(self, off):
        """Largest chain index reachable from the GNU hash buckets."""
        nbuckets = self._u32(off)
        symoffset = self._u32(off + 4)
        bloom_size = self._u32(off + 8)
        bloom_words = bloom_size * (8 if self.is64 else 4)
        buckets_off = off + 16 + bloom_words
        chains_off = buckets_off + 4 * nbuckets
        best = 0
        for i in range(nbuckets):
            idx = self._u32(buckets_off + 4 * i)
            if idx < symoffset:
                continue
            chain = chains_off + 4 * (idx - symoffset)
            while chain + 4 <= len(self.data):
                value = self._u32(chain)
                chain += 4
                idx += 1
                if value & 1:
                    break
            best = max(best, idx)
        return best

    def imports(self):
        return self._symbol_names(self._dynamic_tags())


def checksec(path):
    """Return the native hardening profile of one ELF."""
    elf = _Elf(path)
    gnu_stack = next((ph for ph in elf.phdrs if ph["type"] == PT_GNU_STACK),
                     None)
    nx = None if gnu_stack is None else not bool(gnu_stack["flags"] & PF_X)
    tags = elf._dynamic_tags()
    imports = elf._symbol_names(tags)
    has_relro = any(ph["type"] == PT_GNU_RELRO for ph in elf.phdrs)
    bind_now = bool(tags.get(DT_FLAGS, 0) & DF_BIND_NOW
                    or tags.get(DT_FLAGS_1, 0) & DF_1_NOW)
    relro = "none"
    if has_relro:
        relro = "full" if bind_now else "partial"
    fortified = sum(1 for name in imports if name.endswith("_chk"))
    fortifyable = sum(1 for name in imports
                      if name in _FORTIFIABLE and not name.endswith("_chk"))
    return {
        "canary": any(sym in imports for sym in _CANARY_SYMBOLS),
        "nx": nx,
        "pie": elf.e_type == ET_DYN,
        "relro": relro,
        "fortified": fortified,
        "fortifyable": fortifyable,
    }
