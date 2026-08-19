"""M4: thin wrapper around the codebase-memory-mcp (CBM) CLI.

Every function shells out to `codebase-memory-mcp cli <tool> --key value ...`,
captures stderr, enforces a timeout and parses the single JSON object printed
on stdout. Index runs get CBM_INDEX_TIMEOUT (default 1800s), everything else
CBM_QUERY_TIMEOUT (default 30s).

Verified against CBM 0.9.0:
  index_repository --repo-path DIR --name PROJ     -> {"nodes":N,"edges":M,...}
  search_graph     --project P --name-pattern RX   -> {"total","results":[...]}
  query_graph      --project P --query CYPHER      -> {"columns","rows","total"}
  trace_path       --project P --function-name F [--direction in|out|both]
  get_code_snippet --project P --qualified-name QN -> {"source":...,...}
  list_projects

get_code_snippet has no --name flag, so snippet() resolves a plain function
name to a qualified_name via search_graph first (exact match preferred).
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

DEFAULT_DANGEROUS = [
    "strcpy", "strcat", "sprintf", "vsprintf", "gets",
    "system", "popen", "execl", "execlp", "execle", "execv", "execvp",
    "execve", "scanf", "sscanf", "mktemp",
]


class CBMError(RuntimeError):
    """CLI failure: non-zero exit, timeout, or unparseable output."""


def _cfg(name: str, default: str) -> str:
    return os.getenv(name, default)


def _cbm_bin() -> str:
    """CBM CLI 路径：CBM_BIN env -> PATH 查找 -> ~/.local/bin 兜底。"""
    explicit = os.getenv("CBM_BIN", "").strip()
    if explicit:
        return explicit
    found = shutil.which("codebase-memory-mcp")
    return found or str(Path.home() / ".local" / "bin" / "codebase-memory-mcp")


def index_timeout() -> int:
    return int(_cfg("CBM_INDEX_TIMEOUT", "1800"))


def query_timeout() -> int:
    return int(_cfg("CBM_QUERY_TIMEOUT", "30"))


def _parse_stdout(stdout: str):
    """CBM prints one JSON object on stdout; logs go to stderr. Be lenient:
    fall back to the last non-empty line if the whole blob does not parse."""
    text = (stdout or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    return None


def _run_cli(args, timeout: int, extra_env=None):
    """Run `codebase-memory-mcp cli <args>`; return the parsed stdout JSON."""
    cmd = [_cbm_bin(), "cli", *[str(a) for a in args]]
    env = dict(os.environ)
    if extra_env:
        for key, value in extra_env.items():
            if value is None:
                env.pop(key, None)
            else:
                env[key] = value
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, env=env)
    except subprocess.TimeoutExpired as exc:
        raise CBMError(f"cbm cli timed out after {timeout}s: {args[0]}") from exc
    except OSError as exc:
        raise CBMError(f"cbm cli not runnable ({_cbm_bin()}): {exc}") from exc
    if proc.returncode != 0:
        raise CBMError(
            f"cbm cli {args[0]} exited rc={proc.returncode}: "
            f"{(proc.stderr or proc.stdout or '')[-500:]}")
    parsed = _parse_stdout(proc.stdout)
    if parsed is None:
        raise CBMError(
            f"cbm cli {args[0]} produced no JSON on stdout "
            f"(stderr: {(proc.stderr or '')[-300:]})")
    if isinstance(parsed, dict) and parsed.get("error"):
        raise CBMError(f"cbm cli {args[0]}: {parsed['error']}"
                       f" ({parsed.get('hint', '')})".strip())
    return parsed


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def index_repository(repo_path, project: str, timeout: int | None = None,
                     mode: str = "full"):
    if mode not in {"full", "moderate", "fast"}:
        raise ValueError(f"unsupported CBM index mode: {mode!r}")
    return _run_cli(["index_repository", "--repo-path", repo_path,
                     "--name", project, "--mode", mode],
                    timeout=timeout or index_timeout())


def search(project: str, pattern: str, label: str | None = None,
           limit: int | None = None, timeout: int | None = None):
    args = ["search_graph", "--project", project, "--name-pattern", pattern,
            "--format", "json"]
    if label:
        args += ["--label", label]
    if limit:
        args += ["--limit", str(limit)]
    out = _run_cli(args, timeout=timeout or query_timeout())
    if "results" not in out and isinstance(out.get("groups"), list):
        # CBM >=0.9 tree model: groups of column-ordered rows; flatten to the
        # classic results list (qn = group prefix + "." + name)
        cols = out.get("cols") or []
        name_idx = cols.index("name") if "name" in cols else 0
        label_idx = cols.index("label") if "label" in cols else None
        results = []
        for group in out["groups"]:
            prefix = group.get("qn_prefix", "")
            for row in group.get("rows", []):
                name = row[name_idx] if len(row) > name_idx else ""
                results.append({
                    "name": name,
                    "qualified_name": f"{prefix}.{name}",
                    "label": row[label_idx]
                    if label_idx is not None and len(row) > label_idx else None,
                })
        out["results"] = results
    return out


def cypher(project: str, query: str, timeout: int | None = None):
    # CBM >=0.9 defaults query_graph to a TOON text table; the legacy
    # columns/rows JSON is restored by format:"json", which the CLI only
    # accepts inside the raw-JSON args form (no --format flag here).
    raw_args = json.dumps({"project": project, "query": query,
                           "format": "json"})
    return _run_cli(["query_graph", raw_args],
                    timeout=timeout or query_timeout())


def trace(project: str, name: str, direction: str = "both",
          timeout: int | None = None):
    return _run_cli(["trace_path", "--project", project,
                     "--function-name", name, "--direction", direction,
                     "--format", "json"],
                    timeout=timeout or query_timeout())


def snippet(project: str, name: str, timeout: int | None = None):
    """Resolve `name` -> qualified_name via search_graph, then read source."""
    timeout = timeout or query_timeout()
    found = search(project, name, label="Function", timeout=timeout)
    results = found.get("results", [])
    if not results:
        raise CBMError(f"no Function named like {name!r} in project {project}")
    exact = [r for r in results if r.get("name") == name]
    qname = (exact[0] if exact else results[0])["qualified_name"]
    return _run_cli(["get_code_snippet", "--project", project,
                     "--qualified-name", qname], timeout=timeout)


def dangerous_callsites(project: str, functions=None, limit: int = 50,
                        timeout: int | None = None):
    """Callers of dangerous functions: MATCH (f:Function)-[:CALLS]->(g:Function)
    WHERE g.name IN [...] OR g.libc_equiv IN [...]. The libc_equiv clause is
    what makes statically linked stripped binaries searchable: their libc
    implementations carry libc_equiv (AI/backfill/propagated) instead of the
    real symbol name. Nodes without the key simply never match that clause
    (verified: missing string keys in IN evaluate to no-match, no error), so
    no IS NOT NULL guard is needed. Statically linked callees with neither a
    matching name nor libc_equiv still never appear -- an empty rows list
    means 'no resolved callee nodes', not 'no dangerous calls'."""
    functions = functions or DEFAULT_DANGEROUS
    names = ", ".join("'" + f.replace("'", "") + "'" for f in functions)
    query = ("MATCH (f:Function)-[:CALLS]->(g:Function) "
             f"WHERE g.name IN [{names}] OR g.libc_equiv IN [{names}] "
             "RETURN f.name, f.file_path, g.name "
             f"LIMIT {int(limit)}")
    return cypher(project, query, timeout=timeout)


def list_projects(timeout: int | None = None):
    return _run_cli(["list_projects"], timeout=timeout or query_timeout())


def ingest_traces(project: str, traces, timeout: int | None = None):
    """M7: hand runtime traces to CBM. NOTE: a stub in CBM 0.9.0 — it
    acknowledges with {"traces_received":0,"note":"Runtime edge creation
    from traces not yet implemented"}, so callers must treat this as
    best-effort and keep their own trace store."""
    return _run_cli(["ingest_traces", "--project", project,
                     "--traces", json.dumps(traces)],
                    timeout=timeout or query_timeout())
