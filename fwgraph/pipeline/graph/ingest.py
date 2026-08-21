"""M4 graph ingest: pseudocode tree -> CBM index -> metadata injection.

Steps (run_job):
  a. copy data/pseudocode/<job>/<md5>/functions/<addr>.c into a CBM-friendly
     tree  data/cbm/<job>/<binary_name>_<md5[:8]>/<addr>_<name>.c
     (the name in the filename makes search results and browsing readable;
     the // addr=.. name=.. header line rides along unchanged)
  b. git init + commit in data/cbm/<job>/ so CBM's watcher/incremental mode
     has a repository to work with (local fwgraph user, idempotent)
  c. index with `codebase-memory-mcp cli index_repository --name fwgraph_<job>`
  d. inject addr/arch/tags/ai_confidence/ai_name/rule_source/libc_equiv from
     symbols.json straight into the CBM SQLite nodes.properties JSON
     (json_set; one transaction; idempotent; failures degrade to a warning,
     never abort)
  e. propagate libc_equiv across SIMILAR_TO edges (one round, both
     directions; clones of a known libc implementation inherit it, marked
     libc_equiv_propagated=1)
  f. write data/cbm/<job>/graph_done.json

CLI: python -m pipeline.graph.ingest <job_id>
"""

import json
import hashlib
import os
import re
import sqlite3
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from pipeline.graph import query as cbm

FWGRAPH_ROOT = Path(__file__).resolve().parents[2]
CBM_CACHE_DIR = Path(
    os.getenv("CBM_CACHE_DIR", str(Path.home() / ".cache" / "codebase-memory-mcp")))

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]")
_MAX_FUNCTION_NAME_COMPONENT = 180


def _cfg(name, default):
    return os.getenv(name, default)


def _now():
    return datetime.now(timezone.utc).isoformat()


def project_name(job_id: str) -> str:
    return f"fwgraph_{job_id}"


def db_path(proj: str) -> Path:
    return CBM_CACHE_DIR / f"{proj}.db"


# ---------------------------------------------------------------------------
# a. tree building
# ---------------------------------------------------------------------------

def _binary_dirname(md5: str, entry: dict) -> str:
    base = Path(entry.get("path", "")).name or "binary"
    return f"{_SAFE_NAME_RE.sub('_', base)}_{md5[:8]}"


def _function_filename(func: dict) -> str:
    """Return a deterministic, filesystem-safe CBM filename.

    The address remains the primary identity. Long IDA/C++ names are shortened
    only in the path; the complete name stays in the source header and symbols.
    """
    addr = str(func.get("addr") or "0x0")
    original = str(func.get("name") or "unnamed")
    safe = _SAFE_NAME_RE.sub("_", original)
    if len(safe) > _MAX_FUNCTION_NAME_COMPONENT:
        digest = hashlib.sha256(original.encode("utf-8")).hexdigest()[:12]
        safe = safe[:_MAX_FUNCTION_NAME_COMPONENT - len(digest) - 1] + "_" + digest
    return f"{addr}_{safe}.c"


# Hex-Rays emits MSVC-flavoured annotations that tree-sitter (CBM's parser)
# chokes on. Sanitizing is deliberately line-targeted: files that already
# parse are copied byte-identical.
_IDA_KW_RE = re.compile(
    r"__(fastcall|stdcall|cdecl|thiscall|usercall|noreturn|forceinline)\b")
_BUILTIN_TYPES = {
    "void", "int", "float", "char", "const", "unsigned", "double", "signed",
    "short", "long", "struct", "enum", "union", "bool", "_Bool", "size_t",
    "wchar_t",
}
_ASM_BLOCK_RE = re.compile(r"^[ \t]*__asm\s*\{[^}]*\}\n?", re.MULTILINE)
_REGVAR_RE = re.compile(r"_\$([A-Za-z0-9]+)")        # _$V0 pseudovariables
_REGANNOT_RE = re.compile(r"@<\$[A-Za-z0-9_]+>")     # name@<$v0> annotations


def _sanitize_source(text: str):
    """Make one pseudocode file palatable to tree-sitter. Returns
    (text, fixes) where fixes lists what was applied:

    - signature: `UNKNOWN_TYPE *__fastcall f(...)` does not parse (probe-
      verified), so calling-convention keywords are stripped from the
      signature line when the return type is not a C builtin; __noreturn /
      __usercall are always stripped there. Function names are immutable.
    - asm: `__asm { ... }` blocks (MIPS FCSR fiddling in libm) removed
    - regvar: `_$V0` register pseudovars renamed `_REGV0`
    - regannot: `f@<$v0>(a@<$f12>)` register annotations removed
    """
    fixes = []
    lines = text.splitlines(keepends=True)
    if len(lines) >= 2:
        sig = lines[1]
        new = sig
        first = sig.split(" ", 1)[0].lstrip("*")
        if _IDA_KW_RE.search(sig) and (first not in _BUILTIN_TYPES
                                       or "__noreturn" in sig
                                       or "__usercall" in sig):
            new = re.sub(r" {2,}", " ", _IDA_KW_RE.sub("", new))
        if new != sig:
            lines[1] = new
            fixes.append("signature")
    text = "".join(lines)
    if "__asm" in text:
        text = _ASM_BLOCK_RE.sub("", text)
        fixes.append("asm")
    if "_$" in text:
        text = _REGVAR_RE.sub(r"_REG\1", text)
        fixes.append("regvar")
    if "@<$" in text:
        text = _REGANNOT_RE.sub("", text)
        fixes.append("regannot")
    return text, fixes


_KEEP_TREE_FILES = frozenset({"graph_done.json"})


def build_tree(job_id: str, data_dir) -> dict:
    """Copy pseudocode into data/cbm/<job>/; return per-binary stats.

    Incremental: skip writes when the sanitized dest already matches, and
    delete dest files that are no longer in symbols. `.git` and
    `graph_done.json` are left in place.
    """
    data_dir = Path(data_dir)
    pseudo_root = data_dir / "pseudocode" / job_id
    symbols = json.loads((pseudo_root / "symbols.json").read_text(encoding="utf-8"))
    tree_root = data_dir / "cbm" / job_id
    tree_root.mkdir(parents=True, exist_ok=True)
    stats = {"tree_root": str(tree_root), "binaries": {}, "files_copied": 0,
             "skipped": 0, "sanitized": 0, "written": 0, "unchanged": 0,
             "deleted": 0}
    wanted = set()
    for md5 in sorted(symbols.get("binaries", {})):
        entry = symbols["binaries"][md5]
        dirname = _binary_dirname(md5, entry)
        dest_dir = tree_root / dirname
        dest_dir.mkdir(parents=True, exist_ok=True)
        funcs_dir = pseudo_root / md5 / "functions"
        copied = 0
        for func in entry.get("functions", []):
            if not func.get("decompile_ok"):
                stats["skipped"] += 1
                continue
            src = funcs_dir / f"{func['addr']}.c"
            if not src.is_file():
                stats["skipped"] += 1
                continue
            fname = _function_filename(func)
            rel = f"{dirname}/{fname}"
            wanted.add(rel)
            text = src.read_text(encoding="utf-8", errors="replace")
            text, fixes = _sanitize_source(text)
            if fixes:
                stats["sanitized"] += 1
            dest = dest_dir / fname
            if dest.is_file() and dest.read_text(
                    encoding="utf-8", errors="replace") == text:
                stats["unchanged"] += 1
            else:
                dest.write_text(text, encoding="utf-8")
                stats["written"] += 1
            copied += 1
        stats["binaries"][md5] = {"dir": dirname, "arch": entry.get("arch"),
                                  "files": copied}
        stats["files_copied"] += copied
    if tree_root.is_dir():
        for path in tree_root.rglob("*"):
            if not path.is_file() or ".git" in path.parts:
                continue
            if path.name in _KEEP_TREE_FILES:
                continue
            rel = path.relative_to(tree_root).as_posix()
            if rel not in wanted:
                path.unlink()
                stats["deleted"] += 1
        for path in sorted(tree_root.rglob("*"), reverse=True):
            if not path.is_dir() or ".git" in path.parts or path == tree_root:
                continue
            try:
                next(path.iterdir())
            except StopIteration:
                path.rmdir()
    return stats


# ---------------------------------------------------------------------------
# b. git init (enables CBM watcher/incremental indexing)
# ---------------------------------------------------------------------------

def _git(tree_root: Path, *args, timeout=600):
    return subprocess.run(
        ["git", "-C", str(tree_root), *args], capture_output=True, text=True,
        timeout=timeout)


def git_init_commit(tree_root, files_copied=0) -> dict:
    """git init + commit-all; idempotent (skips the commit when clean).

    CBM index_repository does not require git. Skip when CBM_GIT=0 or the
    tree is larger than CBM_GIT_MAX_FILES (default 20000) so large firmware
    ingest is not blocked by `git add -A`.
    """
    tree_root = Path(tree_root)
    if _cfg("CBM_GIT", "1") == "0":
        return {"ok": True, "committed": False, "skipped": "CBM_GIT=0"}
    max_files = max(0, int(_cfg("CBM_GIT_MAX_FILES", "20000")))
    if files_copied > max_files:
        return {"ok": True, "committed": False,
                "skipped": f"files_copied={files_copied}>{max_files}"}
    if not (tree_root / ".git").is_dir():
        proc = _git(tree_root, "init")
        if proc.returncode != 0:
            return {"ok": False, "error": proc.stderr.strip()[-300:]}
    proc = _git(tree_root, "add", "-A")
    if proc.returncode != 0:
        return {"ok": False, "error": proc.stderr.strip()[-300:]}
    if not _git(tree_root, "status", "--porcelain").stdout.strip():
        return {"ok": True, "committed": False}  # nothing new
    proc = _git(tree_root, "-c", "user.name=fwgraph",
                "-c", "user.email=fwgraph@localhost",
                "commit", "-q", "-m", "fwgraph pseudocode snapshot")
    if proc.returncode != 0:
        return {"ok": False, "error": proc.stderr.strip()[-300:]}
    return {"ok": True, "committed": True}


# ---------------------------------------------------------------------------
# d/e. metadata injection into the CBM SQLite store
# ---------------------------------------------------------------------------

def inject_metadata(dbfile, symbols: dict, proj: str) -> dict:
    """json_set addr/arch/tags/AI tags/rule_source/libc_equiv
    onto Function nodes, matched by (project, file_path) — the tree layout
    makes file_path deterministic: <binary_name>_<md5[:8]>/<addr>_<name>.c.

    addr/arch/tags are always written; ai_* / rule_source / libc_equiv only
    when present (a JSON null would read back as "0" in CBM's numeric cypher
    comparisons, making every untagged function look like ai_confidence < x).
    Absent ai_* keys are actively json_remove'd so re-runs also clean up
    legacy nulls; libc_equiv keys are left alone when absent (propagation
    may have set them — removing would only force a re-propagation).
    One transaction; overwriting identical values keeps it idempotent.
    """
    base, ai, rule, no_ai, no_rule, libc, domain, no_domain = \
        [], [], [], [], [], [], [], []
    for md5 in sorted(symbols.get("binaries", {})):
        entry = symbols["binaries"][md5]
        dirname = _binary_dirname(md5, entry)
        for func in entry.get("functions", []):
            if not func.get("decompile_ok"):
                continue
            fname = _function_filename(func)
            fpath = f"{dirname}/{fname}"
            base.append((func.get("addr"), entry.get("arch"),
                         json.dumps(func.get("tags") or []), proj, fpath))
            if func.get("ai_name") is not None:
                ai.append((func.get("ai_name"), func.get("ai_confidence"),
                           proj, fpath))
            else:
                no_ai.append((proj, fpath))
            if func.get("rule_source"):
                rule.append((func["rule_source"], proj, fpath))
            else:
                no_rule.append((proj, fpath))
            if func.get("libc_equiv"):
                libc.append((func["libc_equiv"], proj, fpath))
            if func.get("domain"):
                domain.append((func["domain"], proj, fpath))
            else:
                no_domain.append((proj, fpath))
    where = " WHERE project = ? AND label = 'Function' AND file_path = ?"
    db = sqlite3.connect(str(dbfile))
    try:
        with db:  # commits on success, rolls back on exception
            cur = db.executemany(
                "UPDATE nodes SET properties = json_set(properties,"
                "  '$.addr', ?, '$.arch', ?, '$.tags', json(?))" + where, base)
            matched = cur.rowcount
            db.executemany(
                "UPDATE nodes SET properties = json_set(properties,"
                "  '$.ai_name', ?, '$.ai_confidence', ?)" + where, ai)
            db.executemany(
                "UPDATE nodes SET properties = json_set(properties,"
                "  '$.rule_source', ?)" + where, rule)
            db.executemany(
                "UPDATE nodes SET properties = json_set(properties,"
                "  '$.libc_equiv', ?)" + where, libc)
            db.executemany(
                "UPDATE nodes SET properties = json_set(properties,"
                "  '$.domain', ?)" + where, domain)
            # clear legacy null injections so re-runs converge
            db.executemany(
                "UPDATE nodes SET properties = json_remove(properties,"
                "  '$.ai_name', '$.ai_confidence')" + where, no_ai)
            db.executemany(
                "UPDATE nodes SET properties = json_remove(properties,"
                "  '$.rule_source')" + where, no_rule)
            db.executemany(
                "UPDATE nodes SET properties = json_remove(properties,"
                "  '$.domain')" + where, no_domain)
    finally:
        db.close()
    return {"wanted": len(base), "matched": matched,
            "ai_named": len(ai), "rule_named": len(rule),
            "libc_equiv": len(libc), "domain": len(domain)}


# ---------------------------------------------------------------------------
# e. libc_equiv propagation across SIMILAR_TO edges
# ---------------------------------------------------------------------------

def propagate_libc_equiv(dbfile, proj: str) -> dict:
    """Copy libc_equiv over SIMILAR_TO edges, one round, both directions.

    A near-clone of a known libc implementation is the same libc function:
    when exactly one endpoint of a SIMILAR_TO edge carries libc_equiv, the
    other endpoint gets a copy plus a libc_equiv_propagated=1 marker. Only
    authoritative donors (libc_equiv from symbols.json injection, i.e. the
    AI answer or the backfill) propagate; nodes that got their libc_equiv
    from propagation itself are never donors. That keeps every run to one
    hop from verified sources, makes re-runs a true fixpoint (second run
    propagates 0), and stops noisy clone chains from smearing libc_equiv
    further on each re-ingest. SIMILAR_TO is undirected in practice, so
    both orientations of every edge are considered.
    """
    db = sqlite3.connect(str(dbfile))
    db.row_factory = sqlite3.Row
    try:
        rows = db.execute(
            "SELECT e.source_id AS sid, e.target_id AS tid,"
            "  json_extract(s.properties, '$.libc_equiv') AS s_eq,"
            "  json_extract(s.properties, '$.libc_equiv_propagated') AS s_pp,"
            "  json_extract(t.properties, '$.libc_equiv') AS t_eq,"
            "  json_extract(t.properties, '$.libc_equiv_propagated') AS t_pp "
            "FROM edges e"
            "  JOIN nodes s ON s.id = e.source_id"
            "  JOIN nodes t ON t.id = e.target_id "
            "WHERE e.project = ? AND e.type = 'SIMILAR_TO'"
            "  AND s.label = 'Function' AND t.label = 'Function'",
            (proj,)).fetchall()
        updates = {}  # node_id -> equiv; first donor wins on conflicts
        for row in rows:
            # authoritative donor: has libc_equiv, not itself propagated
            s_donor = row["s_eq"] if row["s_eq"] and not row["s_pp"] else None
            t_donor = row["t_eq"] if row["t_eq"] and not row["t_pp"] else None
            if s_donor and not row["t_eq"]:
                updates.setdefault(row["tid"], s_donor)
            if t_donor and not row["s_eq"]:
                updates.setdefault(row["sid"], t_donor)
        with db:
            db.executemany(
                "UPDATE nodes SET properties = json_set(properties,"
                "  '$.libc_equiv', ?, '$.libc_equiv_propagated', 1)"
                " WHERE id = ?",
                [(eq, nid) for nid, eq in updates.items()])
    finally:
        db.close()
    return {"edges_scanned": len(rows), "propagated": len(updates)}


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------

def run_job(job_id: str, data_dir) -> dict:
    data_dir = Path(data_dir)
    t0 = time.time()
    proj = project_name(job_id)
    summary = {"job_id": job_id, "project": proj, "started_at": _now(),
               "finished_at": None, "status": "ok", "warnings": []}

    # a. CBM-friendly tree
    tree = build_tree(job_id, data_dir)
    summary["tree"] = tree
    if tree["files_copied"] == 0:
        raise RuntimeError(f"no pseudocode files found for job {job_id}")
    tree_root = Path(tree["tree_root"])

    # b. git init + commit (watcher/incremental support)
    git_res = git_init_commit(tree_root, files_copied=tree["files_copied"])
    summary["git"] = git_res
    if git_res.get("skipped"):
        summary["warnings"].append(f"git skipped: {git_res['skipped']}")
    if not git_res.get("ok"):
        summary["warnings"].append(f"git init/commit failed: "
                                   f"{git_res.get('error')}")

    # c. CBM index (30 min timeout inside query.py). FULL retains an
    # all-functions working set for similarity/semantic edges. FAST preserves
    # structural parsing, calls and usages while skipping those optional
    # corpus-wide passes, which keeps large firmware graphs memory-bounded.
    full_max_files = max(0, int(_cfg(
        "CBM_FULL_INDEX_MAX_FILES",
        _cfg("CBM_SEMANTIC_MAX_FILES", "50000"))))
    index_mode = "full" if tree["files_copied"] <= full_max_files else "fast"
    if index_mode == "fast":
        summary["warnings"].append(
            "CBM fast mode selected: files_copied={} exceeds full-index "
            "limit={}; structural nodes, calls and usages remain indexed; "
            "similarity/semantic edges are omitted".format(
                tree["files_copied"], full_max_files))
    try:
        index_res = cbm.index_repository(str(tree_root), proj, mode=index_mode)
    except cbm.CBMError as exc:
        message = str(exc)
        killed = "signal=9" in message or '"outcome":"killed"' in message
        if index_mode == "fast" or not killed:
            raise
        summary["warnings"].append(
            "CBM full-mode worker was killed; retried in fast mode without "
            "similarity/semantic edges")
        index_mode = "fast"
        index_res = cbm.index_repository(str(tree_root), proj, mode=index_mode)
    summary["index"] = {k: index_res.get(k) for k in
                        ("nodes", "edges", "skipped_count", "status")}
    summary["index"]["mode"] = index_mode
    summary["index"]["semantic_enabled"] = index_mode != "fast"

    # d/e. metadata injection + libc_equiv propagation (never aborts the run)
    pseudo_root = data_dir / "pseudocode" / job_id
    symbols = json.loads((pseudo_root / "symbols.json").read_text(encoding="utf-8"))
    dbfile = db_path(proj)
    if dbfile.is_file():
        try:
            summary["meta_injected"] = inject_metadata(dbfile, symbols, proj)
            summary["libc_propagated"] = propagate_libc_equiv(dbfile, proj)
        except Exception as exc:  # noqa: BLE001 - injection is best-effort
            summary["meta_injected"] = None
            summary["libc_propagated"] = None
            summary["warnings"].append(
                f"metadata injection failed: {type(exc).__name__}: {exc}")
    else:
        summary["meta_injected"] = None
        summary["libc_propagated"] = None
        summary["warnings"].append(f"CBM db not found: {dbfile}")

    # f. done marker
    summary["finished_at"] = _now()
    summary["elapsed_seconds"] = round(time.time() - t0, 2)
    (tree_root / "graph_done.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    from dotenv import load_dotenv
    load_dotenv(FWGRAPH_ROOT / ".env")
    data_dir = Path(_cfg("FWGRAPH_DATA", str(FWGRAPH_ROOT / "data")))
    summary = run_job(argv[1], data_dir)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv))
