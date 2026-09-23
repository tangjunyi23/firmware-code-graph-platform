#!/usr/bin/env python
"""One-time setup for the rootfs_elf skill. Machine-independent, stdlib only.

- Extracts the rootfs_elf package from the tarball bundled with this skill
  (assets/rootfs_elf.tar.gz) to ~/.zcode/tools/rootfs_elf. Override the
  source with --tarball (e.g. a newer build) and the destination with
  --target. The archive is a plain POSIX tar despite its .tar.gz name;
  tarfile's "r:*" auto-detection handles that. Stale bundled output/ and
  __pycache__/ members are skipped so runs never mix with old results.
- Locates a suitable IDA Pro installation (rootfs_elf needs the idalib API
  from IDA 9.1+; IDA 9.0's idalib has been observed to crash natively in
  open_database) and runs its py-activate-idalib.py so the per-user idalib
  config points at it. Force a specific install with --ida-dir; skip with
  --no-ida (scan-only mode needs no IDA at all).

Idempotent: re-running keeps an existing extraction unless --force.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tarfile

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARBALL = os.path.join(SKILL_DIR, "assets", "rootfs_elf.tar.gz")
DEFAULT_TARGET = os.path.join(os.path.expanduser("~"), ".zcode", "tools", "rootfs_elf")


def extract_package(tarball: str, target: str, force: bool) -> bool:
    pkg_dir = os.path.join(target, "rootfs_elf")
    marker = os.path.join(pkg_dir, "cli.py")
    if os.path.exists(marker) and not force:
        print(f"[setup] package already extracted at {pkg_dir} (use --force to redo)")
        return False

    os.makedirs(target, exist_ok=True)
    # tarfile auto-detects compression; a plain tar named .tar.gz opens fine
    # with mode "r:*" (no gzip header required).
    with tarfile.open(tarball, "r:*") as tf:
        members = [
            m
            for m in tf.getmembers()
            if m.name.startswith("rootfs_elf/")
            and not re.search(r"rootfs_elf/(output/|__pycache__/|\.codex)", m.name)
        ]
        if not members:
            raise SystemExit(f"[setup] no rootfs_elf/ members found in {tarball}")
        tf.extractall(target, members=members)
    print(f"[setup] extracted {len(members)} members -> {pkg_dir}")
    return True


def find_ida_candidates(extra_roots: list | None = None) -> list:
    roots = []
    if extra_roots:
        roots.extend(extra_roots)
    env = os.environ.get("IDADIR")
    if env:
        roots.append(env)
    home = os.path.expanduser("~")
    for base in (home, os.path.join(home, "Desktop"), r"C:\Program Files", r"C:\Program Files (x86)"):
        try:
            for name in sorted(os.listdir(base)):
                if name.lower().startswith("ida"):
                    roots.append(os.path.join(base, name))
        except OSError:
            continue

    cands = []
    seen = set()
    for root in roots:
        root = os.path.normpath(root)
        if root in seen or not os.path.isdir(root):
            continue
        seen.add(root)
        activator = os.path.join(root, "idalib", "python", "py-activate-idalib.py")
        if os.path.isfile(activator):
            m = re.search(r"(\d+(?:\.\d+)+)", root)
            version = tuple(int(x) for x in m.group(1).split(".")) if m else (0,)
            cands.append((version, root, activator))
    return sorted(cands, reverse=True)


def activate_idalib(ida_dir: str | None = None) -> str | None:
    cands = find_ida_candidates([ida_dir] if ida_dir else None)
    if not cands:
        print("[setup] no IDA Pro with idalib found; IDA export (--run-ida) unavailable, "
              "scan-only mode still works")
        return None

    chosen = None
    for version, root, activator in cands:
        if version >= (9, 1):
            chosen = (version, root, activator)
            break
    if chosen is None:
        chosen = cands[0]
        print(f"[setup] WARNING: newest idalib is {chosen[0]} at {chosen[1]}; "
              "rootfs_elf needs IDA 9.1+ idalib API (9.0 crashes in open_database)")
    version, root, activator = chosen

    rc = subprocess.run([sys.executable, activator], capture_output=True, text=True).returncode
    if rc != 0:
        print(f"[setup] WARNING: py-activate-idalib.py exited {rc} for {root}")
    print(f"[setup] idalib activation -> IDA {'.'.join(map(str, version))} at {root}")
    return root


def main() -> int:
    ap = argparse.ArgumentParser(description="Setup tool for the rootfs-elf skill")
    ap.add_argument("--tarball", default=DEFAULT_TARBALL,
                    help="rootfs_elf tarball (default: bundled with this skill)")
    ap.add_argument("--target", default=DEFAULT_TARGET,
                    help="extraction parent directory (default: %s)" % DEFAULT_TARGET)
    ap.add_argument("--ida-dir", help="use this IDA installation instead of auto-detect")
    ap.add_argument("--force", action="store_true", help="re-extract even if present")
    ap.add_argument("--no-ida", action="store_true", help="skip IDA idalib activation")
    args = ap.parse_args()

    if not os.path.isfile(args.tarball):
        raise SystemExit(f"[setup] tarball not found: {args.tarball}")
    extract_package(args.tarball, args.target, args.force)

    if args.ida_dir and not os.path.isfile(
        os.path.join(args.ida_dir, "idalib", "python", "py-activate-idalib.py")
    ):
        print(f"[setup] WARNING: {args.ida_dir} has no idalib/python/py-activate-idalib.py")

    if args.no_ida:
        ida_dir = None
    else:
        ida_dir = activate_idalib(args.ida_dir)

    print("\n[setup] done. Run the tool like this (Git Bash):")
    print(f'  cd "{args.target}"')
    if ida_dir:
        print(f'  IDADIR="{ida_dir}" python -m rootfs_elf <rootfs-dir> -o <out-dir> '
              "--run-ida --skip-memory --ida-log -j 4 --timeout 900 --retry 1 --progress")
    else:
        print("  python -m rootfs_elf <rootfs-dir> -o <out-dir> --progress")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
