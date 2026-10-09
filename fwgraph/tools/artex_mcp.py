#!/usr/bin/env python3
"""fwgraph MCP bridge — expose firmware code-graph capability to external
pen-test agents (ARTEX) over MCP Streamable HTTP.

Read-only view of an already-analyzed firmware job plus the registered
findings; the receiving agent gets white-box context (routes, handlers,
decompiled sources, raw bytes, differential traces) while it attacks a
live emulated device.

Env:
  FWGRAPH_BASE_URL  orchestrator base (default http://127.0.0.1:8000)
  FWGRAPH_TOKEN     bearer token; ALSO gates this bridge itself — clients
                    must send the exact same Authorization header.
  FWGRAPH_JOB_ID    default job for tools that omit job_id.
  FWGRAPH_MCP_PORT  listen port (default 8900).

Run:  .venv/bin/python -m tools.artex_mcp   (cwd = fwgraph/)
"""
from __future__ import annotations

import json
import os

import httpx
from mcp.server.fastmcp import FastMCP

BASE_URL = os.environ.get("FWGRAPH_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
TOKEN = os.environ.get("FWGRAPH_TOKEN", "")
DEFAULT_JOB = os.environ.get("FWGRAPH_JOB_ID", "")
PORT = int(os.environ.get("FWGRAPH_MCP_PORT", "8900"))
MAX_CHARS = 24_000

_client = httpx.Client(
    base_url=BASE_URL,
    headers={"Authorization": f"Bearer {TOKEN}"},
    timeout=90.0,
)

mcp = FastMCP("fwgraph", host="0.0.0.0", port=PORT)


def _cap(value, limit: int = MAX_CHARS) -> str:
    text = value if isinstance(value, str) else json.dumps(
        value, ensure_ascii=False, indent=1, default=str)
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated {len(text) - limit} chars]"


def _fw(method: str, path: str, *, params: dict | None = None,
        json_body: dict | None = None):
    try:
        resp = _client.request(method, path, params=params, json=json_body)
    except httpx.HTTPError as exc:
        return {"status": "error", "detail": f"orchestrator unreachable: {exc}"}
    if resp.status_code >= 400:
        return {"status": "error", "http": resp.status_code,
                "detail": resp.text[:500]}
    try:
        return resp.json()
    except ValueError:
        return {"status": "ok", "raw": resp.text[:2000]}


def _job(job_id: str = "") -> str:
    jid = (job_id or DEFAULT_JOB).strip()
    if not jid:
        raise ValueError("job_id required (no FWGRAPH_JOB_ID default configured)")
    return jid


@mcp.tool()
def fw_jobs() -> str:
    """List firmware analysis jobs (id, firmware name, status)."""
    return _cap(_fw("GET", "/jobs"))


@mcp.tool()
def fw_manifest(job_id: str = "") -> str:
    """Binaries of a job: path, md5, arch, bits, checksec. Use md5 in other tools."""
    out = _fw("GET", f"/jobs/{_job(job_id)}/manifest")
    if not isinstance(out, dict) or "binaries" not in out:
        return _cap(out)
    bins = out["binaries"][:60]
    slim = [{k: b.get(k) for k in ("name", "path", "md5", "arch", "bits",
                                   "endian", "size", "checksec")}
            for b in bins]
    return _cap({"total": len(out["binaries"]), "showing": len(slim),
                 "binaries": slim})


@mcp.tool()
def fw_routes(job_id: str = "", pattern: str = "", method: str = "",
              binary_md5: str = "", limit: int = 50) -> str:
    """Static HTTP route map (path→method→handler function→binary) recovered
    from the firmware web stack. The single most useful map before fuzzing an
    emulated device's HTTP service."""
    body = {"job_id": _job(job_id), "op": "routes", "limit": min(int(limit), 200)}
    if pattern:
        body["pattern"] = pattern
    if method:
        body["method"] = method
    if binary_md5:
        body["binary_md5"] = binary_md5
    return _cap(_fw("POST", "/graph/query", json_body=body))


@mcp.tool()
def fw_search(job_id: str = "", pattern: str = "", label: str = "",
              limit: int = 30) -> str:
    """Search functions/files in the firmware code graph by name pattern."""
    body = {"job_id": _job(job_id), "op": "search", "pattern": pattern,
            "limit": int(limit)}
    if label:
        body["label"] = label
    return _cap(_fw("POST", "/graph/query", json_body=body))


@mcp.tool()
def fw_attack_surface(job_id: str = "", source: str = "", sink: str = "",
                      verified_only: bool = False, brief: bool = True,
                      limit: int = 20) -> str:
    """Scored source→sink attack paths of the firmware. brief=true gives the
    triage view; brief=false returns full call chains."""
    body = {"job_id": _job(job_id), "op": "attack_surface",
            "verified_only": bool(verified_only), "brief": bool(brief),
            "limit": min(int(limit), 50)}
    if source:
        body["source"] = source
    if sink:
        body["sink"] = sink
    return _cap(_fw("POST", "/graph/query", json_body=body))


@mcp.tool()
def fw_function_brief(binary_md5: str, addr: str, job_id: str = "") -> str:
    """~1KB triage card of one function: attack-surface metadata, pseudocode
    head, dangerous-call lines, direct callees. addr is hex like 0x408a0c."""
    return _cap(_fw("GET", f"/jobs/{_job(job_id)}/functions/"
                           f"{binary_md5}/{addr}/brief"))


@mcp.tool()
def fw_function_source(binary_md5: str, addr: str, job_id: str = "",
                       asm: bool = False) -> str:
    """Full Hex-Rays pseudocode (or asm) of one function."""
    suffix = "?asm=1" if asm else ""
    return _cap(_fw("GET", f"/jobs/{_job(job_id)}/functions/"
                           f"{binary_md5}/{addr}/source{suffix}"))


@mcp.tool()
def fw_read_bytes(vaddr: str, job_id: str = "", binary_md5: str = "",
                  path: str = "", length: int = 32) -> str:
    """Raw bytes at a virtual address of any extracted ELF (.data/.rodata/
    .got): auth-flag bytes, action tables, hardcoded pointers the decompiler
    cannot recover. vaddr like 0x4ed9b0; length 1..512."""
    params = {"vaddr": vaddr, "length": min(max(int(length), 1), 512)}
    if binary_md5:
        params["binary_md5"] = binary_md5
    if path:
        params["path"] = path
    return _cap(_fw("GET", f"/jobs/{_job(job_id)}/read-bytes", params=params))


@mcp.tool()
def fw_decompile_single(job_id: str = "", binary_md5: str = "", path: str = "",
                        function: str = "") -> str:
    """Decompile ONE ELF that is not in the code graph (factory daemons).
    Without function: function list. With function=0x…: radare2 pseudo-C."""
    body = {}
    if binary_md5:
        body["binary_md5"] = binary_md5
    if path:
        body["path"] = path
    if function:
        body["function"] = function
    return _cap(_fw("POST", f"/jobs/{_job(job_id)}/decompile-single",
                    json_body=body))


@mcp.tool()
def fw_traces(job_id: str = "", trace_id: str = "") -> str:
    """Differential qemu-user coverage traces. Without trace_id: list. With
    trace_id: one trace incl. functions only reached with the payload."""
    jid = _job(job_id)
    if trace_id:
        return _cap(_fw("GET", f"/jobs/{jid}/traces/{trace_id}"))
    return _cap(_fw("GET", f"/jobs/{jid}/traces"))


@mcp.tool()
def fw_findings(job_id: str = "") -> str:
    """Findings already registered on this firmware job (title, severity,
    reachability, poc). Attack candidates: try to confirm static-only ones
    against the live emulated device."""
    out = _fw("GET", "/vulnagent/findings")
    if not isinstance(out, dict):
        return _cap(out)
    items = out.get("items") or out.get("findings") or out
    if isinstance(items, list):
        wanted = items if not job_id else [
            f for f in items if f.get("job_id") == job_id]
        slim = [{k: f.get(k) for k in ("id", "job_id", "title", "severity",
                                       "vuln_class", "reachability",
                                       "binary_path", "poc", "call_chain")}
                for f in wanted[:40]]
        return _cap({"total": len(wanted), "findings": slim})
    return _cap(out)


class _AuthCheck:
    """Require the same bearer token fwgraph itself uses."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http" and TOKEN:
            headers = {k.decode().lower(): v.decode()
                       for k, v in scope.get("headers", [])}
            if headers.get("authorization") != f"Bearer {TOKEN}":
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"application/json")]})
                await send({"type": "http.response.body",
                            "body": b'{"detail":"invalid bridge token"}'})
                return
        await self.app(scope, receive, send)


def main() -> None:
    import uvicorn
    if not TOKEN:
        raise SystemExit("FWGRAPH_TOKEN is required (it also gates the bridge)")
    app = _AuthCheck(mcp.streamable_http_app())
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")


if __name__ == "__main__":
    main()
