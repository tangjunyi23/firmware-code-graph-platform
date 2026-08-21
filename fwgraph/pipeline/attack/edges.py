"""Extra call-graph edges for attack-path BFS (union, never drop IDA edges).

Sources, all restricted to the same binary_md5:
  - CBM CALLS: Function→Function after ingest metadata injection
  - CFG call: graphext cfg/<md5>.json edges whose kind is `call`, mapped
    onto function entries via addr+size (indirect_jump is not a call)
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from pipeline.attack.surface import function_key
from pipeline.graph import ingest as graph_ingest


def _md5_prefix(md5: str) -> str:
    return md5[:8]


def _int_addr(value) -> int | None:
    try:
        return int(str(value), 16)
    except (TypeError, ValueError):
        return None


def _dir_for(md5: str, entry: dict) -> str:
    return graph_ingest._binary_dirname(md5, entry)


def _func_ranges(symbols: dict) -> dict:
    """md5 -> list of (start, end, key) for decompiled functions with size."""
    ranges = {}
    for md5, entry in (symbols.get("binaries") or {}).items():
        items = []
        for func in entry.get("functions") or []:
            if not func.get("decompile_ok"):
                continue
            start = _int_addr(func.get("addr"))
            if start is None:
                continue
            try:
                size = int(func.get("size") or 0)
            except (TypeError, ValueError):
                size = 0
            end = start + size if size > 0 else start + 1
            items.append((start, end, function_key(md5, func.get("addr"))))
        items.sort()
        ranges[md5] = items
    return ranges


def _lookup_range(items, addr: int):
    lo, hi = 0, len(items)
    while lo < hi:
        mid = (lo + hi) // 2
        start, end, key = items[mid]
        if addr < start:
            hi = mid
        elif addr >= end:
            lo = mid + 1
        else:
            return key
    return None


def collect_cbm_calls(job_id: str, symbols: dict) -> tuple[set, int]:
    """Return (edges as (src_key, dst_key), scanned_row_count)."""
    proj = graph_ingest.project_name(job_id)
    dbfile = graph_ingest.db_path(proj)
    if not dbfile.is_file():
        return set(), 0
    prefix_to_md5 = {}
    for md5, entry in (symbols.get("binaries") or {}).items():
        prefix_to_md5[_dir_for(md5, entry)] = md5
    db = None
    try:
        db = sqlite3.connect(str(dbfile))
        rows = db.execute(
            "SELECT s.file_path, json_extract(s.properties, '$.addr'),"
            "       t.file_path, json_extract(t.properties, '$.addr') "
            "FROM edges e"
            "  JOIN nodes s ON s.id = e.source_id"
            "  JOIN nodes t ON t.id = e.target_id "
            "WHERE e.project = ? AND e.type = 'CALLS'"
            "  AND s.label = 'Function' AND t.label = 'Function'",
            (proj,),
        ).fetchall()
    except sqlite3.Error:
        return set(), 0
    finally:
        if db is not None:
            db.close()
    edges = set()
    for s_path, s_addr, t_path, t_addr in rows:
        if not s_path or not t_path or not s_addr or not t_addr:
            continue
        s_dir = str(s_path).split("/", 1)[0]
        t_dir = str(t_path).split("/", 1)[0]
        if s_dir != t_dir:
            continue
        md5 = prefix_to_md5.get(s_dir)
        if not md5:
            continue
        edges.add((function_key(md5, s_addr), function_key(md5, t_addr)))
    return edges, len(rows)


def collect_cfg_calls(job_id: str, data_dir, symbols: dict) -> tuple[set, int]:
    """CFG `call` edges mapped onto function entries (same md5)."""
    cfg_root = Path(data_dir) / "graphext" / job_id / "cfg"
    if not cfg_root.is_dir():
        return set(), 0
    ranges = _func_ranges(symbols)
    edges = set()
    scanned = 0
    for md5, items in ranges.items():
        path = cfg_root / f"{md5}.json"
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        for addr, cfg in payload.items():
            src_key = _lookup_range(items, _int_addr(addr) or -1)
            if src_key is None:
                src_key = function_key(md5, addr)
            for edge in cfg.get("edges") or []:
                if not isinstance(edge, (list, tuple)) or len(edge) < 3:
                    continue
                if edge[2] != "call":
                    continue
                scanned += 1
                tgt = _int_addr(edge[1])
                if tgt is None:
                    continue
                dst_key = _lookup_range(items, tgt)
                if dst_key and dst_key != src_key:
                    edges.add((src_key, dst_key))
    return edges, scanned


def collect_extra(job_id: str, data_dir, symbols: dict) -> dict:
    cbm_edges, cbm_scanned = collect_cbm_calls(job_id, symbols)
    cfg_edges, cfg_scanned = collect_cfg_calls(job_id, data_dir, symbols)
    union = cbm_edges | cfg_edges
    return {
        "cbm": len(cbm_edges),
        "cbm_scanned": cbm_scanned,
        "cfg": len(cfg_edges),
        "cfg_scanned": cfg_scanned,
        "extra": union,
    }
