"""ELF facts for the processing/dispatch chain of an input entry.

pyelftools only, works on any host arch. Provides:
  - needed_libs(path)         DT_NEEDED sonames resolved to rootfs file names
  - undefined_symbols(path)   imported symbol names (socket API evidence)
  - exec_paths(path, rootfs)  absolute executable paths referenced in the
                              binary's read-only strings (dispatch detection)
"""

import re
from pathlib import Path

try:
    from elftools.elf.elffile import ELFFile
except ImportError:  # pragma: no cover
    ELFFile = None

# lib search order inside a rootfs (ld.so default paths)
LIB_DIRS = ("lib", "usr/lib", "lib64", "usr/lib64",
            "lib/aarch64-linux-gnu", "lib/arm-linux-gnueabihf",
            "lib/x86_64-linux-gnu", "lib/i386-linux-gnu",
            "lib/mips-linux-gnu", "lib/mipsel-linux-gnu",
            "usr/local/lib")

SOCKET_SYMS = {"socket", "bind", "listen", "accept", "accept4",
               "recvfrom", "recvmsg", "sendmsg", "sendto",
               "getaddrinfo", "socketpair"}

_EXEC_RX = re.compile(rb"(?:/(?:usr/)?s?bin|/usr/local/s?bin|/opt/\S+?/s?bin)"
                      rb"/[A-Za-z0-9_.+@-]{2,64}")


def _open_elf(path):
    if ELFFile is None:
        return None
    try:
        f = open(path, "rb")
    except OSError:
        return None
    try:
        elf = ELFFile(f)
        if not elf.header.e_type in ("ET_EXEC", "ET_DYN"):
            f.close()
            return None
        return f, elf
    except Exception:
        f.close()
        return None


def elf_facts(path):
    """Return (needed_sonames, undefined_symbols) for an ELF, else ([], [])."""
    opened = _open_elf(path)
    if not opened:
        return [], []
    f, elf = opened
    needed, undef = [], []
    try:
        for seg in elf.iter_segments():
            if seg.header.p_type != "PT_DYNAMIC":
                continue
            for tag in seg.iter_tags():
                if tag.entry.d_tag == "DT_NEEDED":
                    needed.append(tag.needed)
        dyn = elf.get_section_by_name(".dynsym")
        if dyn is not None:
            for sym in dyn.iter_symbols():
                if (sym.entry.st_shndx == "SHN_UNDEF" and sym.name
                        and sym.name in SOCKET_SYMS):
                    undef.append(sym.name)
    except Exception:
        pass
    finally:
        f.close()
    return needed, sorted(undef)


def resolve_libs(rootfs, sonames):
    """Map DT_NEEDED sonames to rootfs-relative library paths."""
    rootfs = Path(rootfs)
    out = []
    for so in sonames:
        found = None
        for d in LIB_DIRS:
            cand = rootfs / d / so
            if cand.exists():
                found = f"{d}/{so}"
                break
        # DSM-style: /lib -> /usr/lib symlinks are fine, but keep soname when
        # the file cannot be located so the chain is still auditable
        out.append(found if found else so)
    return out


def unresolved_needed(needed, mapped):
    """Sonames that resolve_libs left unresolved (returned as the soname)."""
    out = []
    for so, path in zip(needed, mapped):
        if not path or path == so:
            out.append(so)
    return out


def exec_paths(path, rootfs, limit=8):
    """Absolute executable paths referenced in binary strings that exist in
    the rootfs (candidate dispatch targets)."""
    try:
        data = Path(path).read_bytes()
    except OSError:
        return []
    rootfs = Path(rootfs)
    out = []
    for m in _EXEC_RX.finditer(data):
        p = m.group(0).decode("ascii", "replace")
        if (rootfs / p.lstrip("/")).exists() and p not in out:
            out.append(p)
            if len(out) >= limit:
                break
    return out


# ---------------------------------------------------------------------------
# multicall (busybox-style) helpers
# ---------------------------------------------------------------------------

def is_multicall_name(rel_path):
    """True when a rootfs-relative path names a busybox-style multicall
    binary (the real binary behind applet symlinks)."""
    base = str(rel_path).rsplit("/", 1)[-1].lower()
    return base == "busybox" or base.startswith("busybox.")


def resolve_real(rootfs, rel_path):
    """Resolve a rootfs-relative path through symlinks inside the rootfs.

    Returns (abs_path, rel, multicall) — multicall is True when the resolved
    target is a busybox-style binary, meaning applet-level facts (imports,
    strings) cannot be read off the shared binary."""
    rootfs = Path(rootfs)
    full = rootfs / rel_path
    real, real_rel = full, rel_path
    try:
        if full.is_symlink():
            target = full.resolve()
            root_resolved = rootfs.resolve()
            if target.is_file() and \
                    str(target).startswith(str(root_resolved)):
                rel = str(target.relative_to(root_resolved)) \
                    .replace("\\", "/")
                if rel != rel_path:
                    real, real_rel = target, rel
    except OSError:
        pass
    return real, real_rel, is_multicall_name(real_rel)


def applet_present(multicall_path, applet):
    """True when the applet name literally appears in a multicall binary's
    bytes (applet name table / usage strings). A dangling symlink to a
    busybox build that lacks the applet is strong phantom evidence."""
    if not applet or any(c in applet for c in "/\\"):
        return False
    try:
        data = Path(multicall_path).read_bytes()
    except OSError:
        return False
    needle = applet.encode("ascii", "replace")
    name_bytes = set(b"abcdefghijklmnopqrstuvwxyz0123456789_.+-")
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx < 0:
            return False
        before = data[idx - 1] if idx > 0 else None
        after_idx = idx + len(needle)
        after = data[after_idx] if after_idx < len(data) else None
        if (before is None or before not in name_bytes) and \
                (after is None or after not in name_bytes):
            return True
        start = idx + 1
