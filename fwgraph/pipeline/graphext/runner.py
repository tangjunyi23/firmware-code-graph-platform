"""graphext runner (M4b): per-function CFG (from .asm) + AST (from pseudo-C).

Artifacts: data/graphext/<job>/cfg/<md5>.json  {addr: {blocks, edges}}
           data/graphext/<job>/ast/<md5>.json  {addr: ast}
           data/graphext/<job>/graphext_done.json

graphext_done.json carries quality metrics alongside the counters:
    cfg_failed            .asm files whose parse produced no blocks
    cfg_stats             total_blocks / orphan_blocks / orphan_rate /
                          ret_edges / indirect_jump_edges
    ast_stats             total / has_error / error_nodes / error_rate /
                          truncated
    ast_error_samples     up to 5 functions still containing ERROR nodes
                          after pseudo-C preprocessing (for debugging)
    ast_failed_samples    up to 5 functions whose parse returned nothing
"""

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from pipeline.graphext import ast as ast_mod
from pipeline.graphext import cfg as cfg_mod

FWGRAPH_ROOT = Path(__file__).resolve().parents[2]

_NAME_RX = re.compile(r"\bname=(\S+)")
MAX_SAMPLES = 5


def _now():
    return datetime.now(timezone.utc).isoformat()


def _func_name(c_file, addr):
    """Best-effort function name from the pseudo-C header comment."""
    try:
        with open(c_file, encoding="utf-8", errors="replace") as fh:
            head = fh.readline()
        m = _NAME_RX.search(head)
        if m:
            return m.group(1)
    except OSError:
        pass
    return addr


def run_job(job_id, data_dir, with_ast=True):
    data_dir = Path(data_dir)
    started = time.time()
    pseudo_root = data_dir / "pseudocode" / job_id
    symbols = json.loads((pseudo_root / "symbols.json").read_text(
        encoding="utf-8"))

    out_root = data_dir / "graphext" / job_id
    (out_root / "cfg").mkdir(parents=True, exist_ok=True)
    (out_root / "ast").mkdir(parents=True, exist_ok=True)

    stats = {"binaries": 0, "cfg_functions": 0, "ast_functions": 0,
             "ast_skipped": 0, "cfg_failed": 0}
    cfg_stats = {"total_blocks": 0, "orphan_blocks": 0, "ret_edges": 0,
                 "indirect_jump_edges": 0}
    ast_stats = {"total": 0, "has_error": 0, "error_nodes": 0,
                 "truncated": 0}
    ast_error_samples, ast_failed_samples = [], []
    for md5, info in symbols.get("binaries", {}).items():
        arch = info.get("arch", "")
        fn_dir = pseudo_root / md5 / "functions"
        if not fn_dir.is_dir():
            continue
        stats["binaries"] += 1
        cfg_map, ast_map = {}, {}
        for asm_file in sorted(fn_dir.glob("*.asm")):
            addr = asm_file.stem
            _, blocks, edges = cfg_mod.parse_asm(
                asm_file.read_text(encoding="utf-8", errors="replace"), arch)
            if not blocks:
                stats["cfg_failed"] += 1
                continue
            cfg_map[addr] = {"blocks": blocks, "edges": edges}
            stats["cfg_functions"] += 1
            incoming = {e[1] for e in edges if e[1]}
            cfg_stats["total_blocks"] += len(blocks)
            cfg_stats["orphan_blocks"] += sum(
                1 for b in blocks[1:] if b["start"] not in incoming)
            cfg_stats["ret_edges"] += sum(1 for e in edges if e[2] == "ret")
            cfg_stats["indirect_jump_edges"] += sum(
                1 for e in edges if e[2] == "indirect_jump")
        if with_ast:
            for c_file in sorted(fn_dir.glob("*.c")):
                addr = c_file.stem
                tree = ast_mod.parse_c(
                    c_file.read_text(encoding="utf-8", errors="replace"))
                if tree is None:
                    stats["ast_skipped"] += 1
                    if len(ast_failed_samples) < MAX_SAMPLES:
                        ast_failed_samples.append(
                            f"{_func_name(c_file, addr)}({md5[:8]}:{addr})")
                    continue
                ast_map[addr] = tree
                stats["ast_functions"] += 1
                ast_stats["total"] += 1
                ast_stats["error_nodes"] += tree.get("error_nodes", 0)
                if tree.get("has_error"):
                    ast_stats["has_error"] += 1
                    if len(ast_error_samples) < MAX_SAMPLES:
                        ast_error_samples.append(
                            f"{_func_name(c_file, addr)}({md5[:8]}:{addr})")
                if tree.get("truncated"):
                    ast_stats["truncated"] += 1
        if cfg_map:
            (out_root / "cfg" / f"{md5}.json").write_text(
                json.dumps(cfg_map), encoding="utf-8")
        if ast_map:
            (out_root / "ast" / f"{md5}.json").write_text(
                json.dumps(ast_map), encoding="utf-8")

    total_blocks = cfg_stats["total_blocks"]
    cfg_stats["orphan_rate"] = (
        round(cfg_stats["orphan_blocks"] / total_blocks, 4)
        if total_blocks else 0.0)
    ast_stats["error_rate"] = (
        round(ast_stats["has_error"] / ast_stats["total"], 4)
        if ast_stats["total"] else 0.0)
    summary = {"job_id": job_id, "status": "ok", "generated_at": _now(),
               **stats, "cfg_stats": cfg_stats, "ast_stats": ast_stats,
               "ast_error_samples": ast_error_samples,
               "ast_failed_samples": ast_failed_samples,
               "elapsed_seconds": round(time.time() - started, 2)}
    (out_root / "graphext_done.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def get_cfg(job_id, data_dir, md5, addr):
    f = Path(data_dir) / "graphext" / job_id / "cfg" / f"{md5}.json"
    if not f.is_file():
        raise KeyError(f"no CFG for {md5}")
    data = json.loads(f.read_text(encoding="utf-8"))
    if addr not in data:
        raise KeyError(f"no CFG for {md5}:{addr}")
    return data[addr]


def get_ast(job_id, data_dir, md5, addr):
    f = Path(data_dir) / "graphext" / job_id / "ast" / f"{md5}.json"
    if not f.is_file():
        raise KeyError(f"no AST for {md5}")
    data = json.loads(f.read_text(encoding="utf-8"))
    if addr not in data:
        raise KeyError(f"no AST for {md5}:{addr}")
    return data[addr]
