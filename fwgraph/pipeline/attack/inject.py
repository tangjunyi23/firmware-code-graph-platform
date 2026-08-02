"""Inject attack-surface properties into CBM Function nodes."""

import json
import sqlite3

from pipeline.graph.ingest import _SAFE_NAME_RE, _binary_dirname


def inject_metadata(dbfile, symbols, project):
    rows = []
    for md5, entry in symbols.get("binaries", {}).items():
        dirname = _binary_dirname(md5, entry)
        for func in entry.get("functions", []):
            if not func.get("decompile_ok"):
                continue
            filename = (f"{func['addr']}_"
                        f"{_SAFE_NAME_RE.sub('_', func.get('name') or 'unnamed')}.c")
            rows.append((
                json.dumps(func.get("asrc") or []),
                json.dumps(func.get("asink") or []),
                1 if func.get("on_attack_path") else 0,
                json.dumps(func.get("path_ids") or []),
                1 if func.get("observed_in_trace") else 0,
                1 if func.get("verified_reachable") else 0,
                json.dumps(func.get("trace_ids") or []),
                project, f"{dirname}/{filename}"))
    database = sqlite3.connect(str(dbfile))
    try:
        with database:
            cursor = database.executemany(
                "UPDATE nodes SET properties = json_set(properties, "
                "'$.asrc', json(?), '$.asink', json(?), "
                "'$.on_attack_path', ?, '$.path_ids', json(?), "
                "'$.observed_in_trace', ?, '$.verified_reachable', ?, "
                "'$.trace_ids', json(?)) "
                "WHERE project = ? AND label = 'Function' AND file_path = ?",
                rows)
            matched = cursor.rowcount
    finally:
        database.close()
    return {
        "wanted": len(rows), "matched": matched,
        "sources": sum(bool(json.loads(row[0])) for row in rows),
        "sinks": sum(bool(json.loads(row[1])) for row in rows),
        "on_paths": sum(bool(row[2]) for row in rows),
        "observed": sum(bool(row[4]) for row in rows),
        "verified": sum(bool(row[5]) for row in rows),
    }
