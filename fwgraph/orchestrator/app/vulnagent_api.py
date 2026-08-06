"""Vuln-mining agent API: operate the upstream vulnagent from the web UI.

The agent itself is the Node harness in <repo>/vulnagent/ (Managed Agents
layout: agent.json = Agent, environment.json = Environment, sessions/<id> =
Session, sessions/<id>/events.sse = Events). This module only launches
sessions, streams their SSE event log, and serves their findings/report —
it never touches the agent's reasoning or the downstream evidence.

Endpoints (all Bearer-auth via the orchestrator's require_token):
  POST /vulnagent/sessions               {task, max_turns?} -> 202 {session_id}
  GET  /vulnagent/sessions               session list (newest first)
  GET  /vulnagent/sessions/{sid}         state.json + resolved findings
  GET  /vulnagent/sessions/{sid}/events  SSE stream (live-follow while running)
  GET  /vulnagent/sessions/{sid}/report  Markdown report
  POST /vulnagent/sessions/{sid}/stop    best-effort terminate (managed only)
  GET  /vulnagent/findings               all findings (index.jsonl, newest first)
  GET  /vulnagent/findings/{fid}         one finding
  GET  /vulnagent/agent                  Agent/Environment manifests summary
"""

import asyncio
import json
import os
import re
import subprocess
import time
from pathlib import Path

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.responses import PlainTextResponse, StreamingResponse

FWGRAPH_ROOT = Path(__file__).resolve().parents[2]
VULNAGENT_HOME = Path(os.getenv(
    "VULNAGENT_HOME", str(FWGRAPH_ROOT.parent / "vulnagent")))
NODE_BIN = os.getenv("VULNAGENT_NODE_BIN", "node")
MAX_PARALLEL = int(os.getenv("VULNAGENT_MAX_SESSIONS", "2"))
MAX_TURNS_CAP = int(os.getenv("VULNAGENT_MAX_TURNS_CAP", "100"))

_SID_RE = re.compile(r"^s-[a-z0-9]+-[a-f0-9]{4}$")
_FID_RE = re.compile(r"^F-[a-z0-9-]+$")

# session_id -> subprocess.Popen of the CLI runner (dies with this process'
# knowledge only; the child itself is start_new_session=True so a service
# restart leaves it running but unmanageable).
_procs: dict[str, subprocess.Popen] = {}


def _b36(ts_ms: int) -> str:
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    out = ""
    while ts_ms:
        ts_ms, r = divmod(ts_ms, 36)
        out = digits[r] + out
    return out or "0"


def _new_sid() -> str:
    return f"s-{_b36(int(time.time() * 1000))}-{os.urandom(2).hex()}"


def _session_dir(sid: str) -> Path:
    if not _SID_RE.match(sid):
        raise HTTPException(status_code=400, detail="bad session id format")
    d = VULNAGENT_HOME / "sessions" / sid
    if not d.is_dir():
        raise HTTPException(status_code=404, detail="session not found")
    return d


def _read_state(sdir: Path) -> dict:
    state_file = sdir / "state.json"
    if not state_file.is_file():
        return {}
    try:
        return json.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _alive(sid: str) -> bool:
    proc = _procs.get(sid)
    return proc is not None and proc.poll() is None


def _effective_status(sid: str, state: dict) -> str:
    if _alive(sid):
        return "running"
    status = state.get("status", "unknown")
    # A service restart orphans the runner: state.json may stay "running"
    # forever. Without a managed process we cannot tell liveness, so report
    # what the state file says unless it is a stale "running" with no proc.
    if status == "running" and sid not in _procs:
        return "interrupted"
    return status


def _session_summary(sdir: Path) -> dict:
    state = _read_state(sdir)
    sid = state.get("session_id", sdir.name)
    return {
        "session_id": sid,
        "task": state.get("task", ""),
        "status": _effective_status(sid, state),
        "turns": state.get("turns", 0),
        "findings": state.get("findings", []),
        "usage": state.get("usage", {}),
        "created_at": state.get("created_at"),
        "updated_at": state.get("updated_at"),
        "managed": _alive(sid),
    }


def _load_finding(fid: str) -> dict | None:
    if not _FID_RE.match(fid):
        return None
    f = VULNAGENT_HOME / "findings" / f"{fid}.json"
    if not f.is_file():
        return None
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def setup(app: FastAPI, require_token) -> None:
    """Register vulnagent routes. Call BEFORE webui.setup(app) so the SPA
    catch-all does not shadow them."""
    auth = [Depends(require_token)]

    @app.post("/vulnagent/sessions", status_code=202, dependencies=auth)
    def start_session(payload: dict = Body(...)):
        task = str(payload.get("task") or "").strip()
        if not task:
            raise HTTPException(status_code=400, detail="'task' required")
        if len(task) > 4000:
            raise HTTPException(status_code=400, detail="task too long (4000)")
        max_turns = int(payload.get("max_turns") or 40)
        if not 1 <= max_turns <= MAX_TURNS_CAP:
            raise HTTPException(status_code=400,
                                detail=f"max_turns must be 1..{MAX_TURNS_CAP}")
        if not (VULNAGENT_HOME / "src" / "cli.js").is_file():
            raise HTTPException(status_code=503,
                                detail=f"vulnagent not deployed at {VULNAGENT_HOME}")
        running = [sid for sid in _procs if _alive(sid)]
        if len(running) >= MAX_PARALLEL:
            raise HTTPException(
                status_code=409,
                detail=f"{len(running)} sessions already running (cap {MAX_PARALLEL}): "
                       + ", ".join(running))
        sid = _new_sid()
        sdir = VULNAGENT_HOME / "sessions" / sid
        sdir.mkdir(parents=True, exist_ok=True)
        log_file = open(sdir / "runner.log", "ab")
        cmd = [NODE_BIN, "src/cli.js", "run", task,
               "--max-turns", str(max_turns), "--session", sid, "--quiet"]
        try:
            proc = subprocess.Popen(
                cmd, cwd=str(VULNAGENT_HOME), stdout=log_file,
                stderr=subprocess.STDOUT, start_new_session=True)
        except OSError as exc:
            log_file.close()
            raise HTTPException(status_code=500,
                                detail=f"failed to spawn node: {exc}") from exc
        _procs[sid] = proc
        # Fail fast if the runner dies immediately (bad env, syntax error).
        time.sleep(0.8)
        if proc.poll() is not None:
            tail = (sdir / "runner.log").read_text(
                encoding="utf-8", errors="replace")[-500:]
            raise HTTPException(status_code=500,
                                detail=f"runner exited rc={proc.returncode}: {tail}")
        return {"session_id": sid, "status": "running", "max_turns": max_turns}

    @app.get("/vulnagent/sessions", dependencies=auth)
    def list_sessions():
        base = VULNAGENT_HOME / "sessions"
        out = [_session_summary(d) for d in sorted(base.iterdir(), reverse=True)
               if d.is_dir()] if base.is_dir() else []
        out.sort(key=lambda s: s.get("created_at") or "", reverse=True)
        return out

    @app.get("/vulnagent/sessions/{sid}", dependencies=auth)
    def get_session(sid: str):
        sdir = _session_dir(sid)
        summary = _session_summary(sdir)
        summary["finding_objects"] = [
            f for f in (_load_finding(fid) for fid in summary["findings"]) if f]
        return summary

    @app.get("/vulnagent/sessions/{sid}/events", dependencies=auth)
    async def session_events(sid: str, follow: int = 1, after: int = 0):
        sdir = _session_dir(sid)
        events_file = sdir / "events.sse"

        async def stream():
            # The file is already in text/event-stream format (the CLI writes
            # `event:`/`data:` pairs) — relay raw bytes, heartbeat in between.
            offset = max(0, after)
            pos = offset
            deadline = time.monotonic() + 20
            while not events_file.is_file():
                if time.monotonic() > deadline:
                    yield ": no events\n\n"
                    return
                await asyncio.sleep(0.3)
            while True:
                try:
                    with open(events_file, "r", encoding="utf-8",
                              errors="replace") as fh:
                        fh.seek(pos)
                        chunk = fh.read()
                        pos = fh.tell()
                except OSError:
                    chunk = ""
                if chunk:
                    yield chunk
                    continue
                state = _read_state(sdir)
                status = _effective_status(sid, state)
                if not follow or status not in ("running",):
                    break
                yield ": ping\n\n"
                await asyncio.sleep(1.0)
            # final drain after the runner exits
            try:
                with open(events_file, "r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(pos)
                    tail = fh.read()
                if tail:
                    yield tail
            except OSError:
                pass

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache",
                                          "X-Accel-Buffering": "no"})

    @app.get("/vulnagent/sessions/{sid}/report", dependencies=auth)
    def session_report(sid: str):
        sdir = _session_dir(sid)
        report = sdir / "report.md"
        if not report.is_file():
            raise HTTPException(status_code=404,
                                detail="no report (no findings recorded yet)")
        return PlainTextResponse(report.read_text(encoding="utf-8",
                                                  errors="replace"))

    @app.post("/vulnagent/sessions/{sid}/stop", dependencies=auth)
    def stop_session(sid: str):
        _session_dir(sid)
        proc = _procs.get(sid)
        if proc is None or proc.poll() is not None:
            raise HTTPException(status_code=409,
                                detail="session not running (or not managed "
                                       "by this service process)")
        proc.terminate()
        return {"session_id": sid, "status": "terminating"}

    @app.get("/vulnagent/findings", dependencies=auth)
    def list_findings():
        index = VULNAGENT_HOME / "findings" / "index.jsonl"
        out = []
        if index.is_file():
            for line in index.read_text(encoding="utf-8",
                                        errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        out.reverse()
        return out

    @app.get("/vulnagent/findings/{fid}", dependencies=auth)
    def get_finding(fid: str):
        finding = _load_finding(fid)
        if finding is None:
            raise HTTPException(status_code=404, detail="finding not found")
        return finding

    @app.get("/vulnagent/agent", dependencies=auth)
    def agent_info():
        def _load(name):
            p = VULNAGENT_HOME / name
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return None
        agent = _load("agent.json") or {}
        env = _load("environment.json") or {}
        return {
            "home": str(VULNAGENT_HOME),
            "agent": {k: agent.get(k) for k in
                      ("id", "name", "model", "skills", "tools")},
            "environment": {k: env.get(k) for k in ("id", "name", "runtime")},
            "max_parallel": MAX_PARALLEL,
        }
