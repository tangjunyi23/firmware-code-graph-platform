"""Run IDA route discovery and inject Route -[ROUTE]-> Function edges."""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from orchestrator.app import config
from pipeline.graph import ingest as graph_ingest

FWGRAPH_ROOT = Path(__file__).resolve().parents[2]
IDA_SCRIPT = FWGRAPH_ROOT / "pipeline" / "routes" / "ida_routes.py"
PRODUCER = "fwgraph.routes.v1"


def _now():
    return datetime.now(timezone.utc).isoformat()


def _cfg(name, default):
    return os.getenv(name, default)


def _function_paths(symbols):
    paths = {}
    for md5, entry in symbols.get("binaries", {}).items():
        dirname = graph_ingest._binary_dirname(md5, entry)
        for func in entry.get("functions", []):
            if not func.get("decompile_ok"):
                continue
            name = graph_ingest._SAFE_NAME_RE.sub(
                "_", func.get("name") or "unnamed")
            paths[(md5, str(func.get("addr")).lower())] = \
                f"{dirname}/{func['addr']}_{name}.c"
    return paths


def resolve_ida_input(data_dir, job_id, md5, entry) -> Path:
    """Pick a writable IDA input for route scan.

    rootfs_elf decompile no longer writes data/idb/<job>/<md5>.i64 (and
    discards database.i64). Prefer a saved IDB when present, otherwise
    stage the extracted ELF next to where idat can create a new .i64.
    """
    data_dir = Path(data_dir)
    idb = data_dir / "idb" / job_id / f"{md5}.i64"
    if idb.is_file():
        return idb
    saved = data_dir / "pseudocode" / job_id / md5 / "database.i64"
    if saved.is_file():
        return saved
    elf = data_dir / "extracted" / job_id / (entry.get("path") or "")
    if not elf.is_file():
        raise FileNotFoundError(
            f"no IDA input for {md5}: missing {idb.name} and ELF {elf}")
    idb_dir = data_dir / "idb" / job_id
    idb_dir.mkdir(parents=True, exist_ok=True)
    staged = idb_dir / md5
    if not staged.exists():
        shutil.copy2(elf, staged)
    return staged


def inject_routes(dbfile, symbols, project, routes):
    """Replace only fwgraph-managed Route nodes/edges in one transaction."""
    function_paths = _function_paths(symbols)
    database = sqlite3.connect(str(dbfile))
    inserted = 0
    unmatched = []
    try:
        with database:
            managed = [row[0] for row in database.execute(
                "SELECT id FROM nodes WHERE project=? AND label='Route' "
                "AND json_extract(properties, '$.producer')=?",
                (project, PRODUCER))]
            if managed:
                placeholders = ",".join("?" for _ in managed)
                database.execute(
                    f"DELETE FROM edges WHERE project=? AND type='ROUTE' "
                    f"AND source_id IN ({placeholders})", (project, *managed))
                database.execute(
                    f"DELETE FROM nodes WHERE id IN ({placeholders})", managed)
            for route in routes:
                md5 = route["binary_md5"]
                handler_addr = str(route["handler_addr"]).lower()
                fpath = function_paths.get((md5, handler_addr))
                function = database.execute(
                    "SELECT id FROM nodes WHERE project=? AND label='Function' "
                    "AND file_path=?", (project, fpath)).fetchone() if fpath else None
                if function is None:
                    unmatched.append({"binary_md5": md5,
                                      "handler_addr": handler_addr,
                                      "route": route["route"]})
                    continue
                qualified = (f"route::{md5}::{route['entry_addr']}::"
                             f"{route['string_addr']}")
                properties = {**route, "producer": PRODUCER}
                cursor = database.execute(
                    "INSERT INTO nodes(project,label,name,qualified_name,"
                    "file_path,properties) VALUES (?, 'Route', ?, ?, '', ?)",
                    (project, route["route"], qualified,
                     json.dumps(properties, sort_keys=True)))
                route_id = cursor.lastrowid
                edge_props = json.dumps({
                    "producer": PRODUCER,
                    "confidence": route.get("confidence"),
                    "entry_addr": route.get("entry_addr"),
                    "evidence": route.get("evidence"),
                }, sort_keys=True)
                database.execute(
                    "INSERT INTO edges(project,source_id,target_id,type,properties) "
                    "VALUES (?,?,?,'ROUTE',?)",
                    (project, route_id, function[0], edge_props))
                inserted += 1
    finally:
        database.close()
    return {"routes": len(routes), "inserted": inserted,
            "unmatched": len(unmatched), "unmatched_handlers": unmatched}


def run_job(job_id, data_dir, scan=True):
    data_dir = Path(data_dir)
    started = time.time()
    symbols_path = data_dir / "pseudocode" / job_id / "symbols.json"
    symbols = json.loads(symbols_path.read_text(encoding="utf-8"))
    output_root = data_dir / "routes" / job_id
    output_root.mkdir(parents=True, exist_ok=True)
    results = []
    routes = []
    if scan:
        ida_dir = config.ida_dir()
        if ida_dir is None:
            raise RuntimeError(
                "未配置 IDA_DIR：请在 fwgraph/.env 或环境变量中设置 IDA 安装目录")
        idat = ida_dir / "idat"
        timeout = int(_cfg("ROUTE_SCAN_TIMEOUT", "900"))
        for md5, entry in sorted(symbols.get("binaries", {}).items()):
            outdir = output_root / md5
            outdir.mkdir(parents=True, exist_ok=True)
            artifact = outdir / "routes_raw.json"
            log_path = outdir / "idat.log"
            try:
                ida_input = resolve_ida_input(data_dir, job_id, md5, entry)
            except FileNotFoundError as exc:
                results.append({"binary_md5": md5, "status": "failed",
                                "error": str(exc), "routes": 0})
                continue
            env = dict(os.environ, TVHEADLESS="1",
                       FWGRAPH_ROUTE_OUTPUT=str(artifact))
            command = [str(idat), "-A", f"-S{IDA_SCRIPT}", str(ida_input)]
            try:
                with open(log_path, "wb") as log_handle:
                    proc = subprocess.run(
                        command, stdout=log_handle, stderr=subprocess.STDOUT,
                        env=env, timeout=timeout, check=False)
            except subprocess.TimeoutExpired:
                results.append({"binary_md5": md5, "status": "timeout",
                                "error": f"killed after {timeout}s",
                                "routes": 0})
                continue
            if proc.returncode != 0 or not artifact.is_file():
                results.append({
                    "binary_md5": md5, "status": "failed",
                    "error": (f"rc={proc.returncode} input={ida_input} "
                              f"(see {log_path.name})"),
                    "routes": 0,
                })
                continue
            raw = json.loads(artifact.read_text(encoding="utf-8"))
            if raw.get("status") != "ok":
                results.append({"binary_md5": md5, "status": "failed",
                                "error": str(raw.get("error") or "export failed"),
                                "routes": 0})
                continue
            binary_routes = []
            for route in raw.get("routes", []):
                binary_routes.append({**route, "binary_md5": md5,
                                      "binary_path": entry.get("path"),
                                      "arch": entry.get("arch")})
            routes.extend(binary_routes)
            results.append({"binary_md5": md5, "status": "ok",
                            "routes": len(binary_routes), "meta": raw.get("meta")})
    else:
        for md5, entry in sorted(symbols.get("binaries", {}).items()):
            artifact = output_root / md5 / "routes_raw.json"
            if not artifact.is_file():
                continue
            raw = json.loads(artifact.read_text(encoding="utf-8"))
            binary_routes = [{**route, "binary_md5": md5,
                              "binary_path": entry.get("path"),
                              "arch": entry.get("arch")}
                             for route in raw.get("routes", [])]
            routes.extend(binary_routes)
            results.append({"binary_md5": md5, "status": raw.get("status"),
                            "routes": len(binary_routes), "meta": raw.get("meta")})
    routes.sort(key=lambda route: (
        route["binary_md5"], route["route"], route["entry_addr"],
        route["handler_addr"]))
    project = graph_ingest.project_name(job_id)
    database = graph_ingest.db_path(project)
    if not database.is_file():
        raise FileNotFoundError(f"CBM database not found: {database}")
    injection = inject_routes(database, symbols, project, routes)
    artifact = {"job_id": job_id, "generated_at": _now(),
                "producer": PRODUCER, "binaries": results, "routes": routes,
                "summary": {"routes": len(routes), **injection}}
    (output_root / "routes.json").write_text(
        json.dumps(artifact, indent=2), encoding="utf-8")
    done = {"job_id": job_id, "status": "ok",
            "generated_at": artifact["generated_at"],
            "binaries": results, "injection": injection,
            "elapsed_seconds": round(time.time() - started, 2)}
    (output_root / "routes_done.json").write_text(
        json.dumps(done, indent=2), encoding="utf-8")
    return done


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    from dotenv import load_dotenv
    load_dotenv(FWGRAPH_ROOT / ".env")
    data_dir = Path(os.getenv("FWGRAPH_DATA", str(FWGRAPH_ROOT / "data")))
    print(json.dumps(run_job(argv[1], data_dir,
                             scan="--no-scan" not in argv[2:]), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
