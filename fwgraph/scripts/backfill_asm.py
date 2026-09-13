#!/usr/bin/env python3
"""Fill missing functions/<addr>.asm for rootfs_elf jobs via objdump.

Usage (from fwgraph/):
  .venv/bin/python scripts/backfill_asm.py [job_id ...]
"""
from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pipeline.decompile.rootfs_elf_adapt import adapt_rootfs_elf_outdir  # noqa: E402


def _jobs(data: Path, wanted: list[str]) -> list[str]:
    if wanted:
        return wanted
    root = data / "pseudocode"
    if not root.is_dir():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_dir())


def _backfill_one(data: Path, job_id: str, md5: str, info: dict) -> dict:
    outdir = data / "pseudocode" / job_id / md5
    funcs = outdir / "functions"
    if not outdir.is_dir():
        return {"md5": md5, "status": "skip", "reason": "no outdir"}
    if funcs.is_dir() and any(funcs.glob("*.asm")):
        return {"md5": md5, "status": "skip", "reason": "asm present"}
    elf = data / "extracted" / job_id / str(info.get("path") or "")
    binary = {
        "arch": info.get("arch"),
        "bits": info.get("bits"),
        "endianness": info.get("endianness"),
    }
    done = adapt_rootfs_elf_outdir(outdir, binary, elf_path=elf if elf.is_file() else None)
    return {
        "md5": md5,
        "status": done.get("status"),
        "asm": done.get("asm_functions", 0),
        "functions": done.get("functions", 0),
    }


def backfill_job(data: Path, job_id: str) -> dict:
    symbols_path = data / "pseudocode" / job_id / "symbols.json"
    if not symbols_path.is_file():
        return {"job_id": job_id, "status": "skip", "reason": "no symbols.json"}
    symbols = json.loads(symbols_path.read_text(encoding="utf-8"))
    binaries = symbols.get("binaries") or {}
    results = []
    workers = min(4, max(1, len(binaries)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {
            pool.submit(_backfill_one, data, job_id, md5, info): md5
            for md5, info in binaries.items()
        }
        for fut in as_completed(futs):
            results.append(fut.result())
    asm = sum(int(r.get("asm") or 0) for r in results)
    return {
        "job_id": job_id,
        "status": "ok",
        "binaries": len(results),
        "asm_functions": asm,
        "results": results,
    }


def main(argv: list[str]) -> int:
    data = Path(__file__).resolve().parents[1] / "data"
    jobs = _jobs(data, argv[1:])
    if not jobs:
        print("no jobs")
        return 1
    for job_id in jobs:
        summary = backfill_job(data, job_id)
        print(json.dumps({k: v for k, v in summary.items() if k != "results"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
