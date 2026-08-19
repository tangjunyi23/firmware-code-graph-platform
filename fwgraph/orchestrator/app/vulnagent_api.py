"""Vuln-mining agent API: operate the upstream vulnagent from the web UI.

The agent itself is the Node harness in <repo>/vulnagent/ (Managed Agents
layout: agent.json = Agent, environment.json = Environment, sessions/<id> =
Session, sessions/<id>/events.sse = Events). This module only launches
sessions, streams their SSE event log, and serves their findings/report —
it never touches the agent's reasoning or the downstream evidence.

Endpoints (all Bearer-auth via the orchestrator's require_token):
  POST /vulnagent/sessions               {task, max_turns?} -> 202 {session_id}
  GET  /vulnagent/sessions               session list (newest first;
                                         non-admin: own sessions only)
  GET  /vulnagent/sessions/{sid}         state.json + resolved findings
  GET  /vulnagent/sessions/{sid}/events  SSE stream (live-follow while running)
  GET  /vulnagent/sessions/{sid}/report  Markdown report
  POST /vulnagent/sessions/{sid}/stop    best-effort terminate
  POST /vulnagent/findings               server-validated finding intake -> 201
  PATCH /vulnagent/findings/{fid}        {status, note?} + history[] entry
  GET  /vulnagent/findings               all findings (index.jsonl, newest first;
                                         non-admin: findings on own jobs only)
  GET  /vulnagent/findings/{fid}         one finding
  GET  /vulnagent/agent                  Agent/Environment manifests summary

Ownership: POST /vulnagent/sessions stamps state.json with
owner = principal.username; sessions created before this field existed are
treated as admin-owned. Non-admin users get a 404 (not 403) for sessions,
findings and reports they do not own, so existence is not disclosed.
"""

import asyncio
import json
import os
import re
import signal
import subprocess
import threading
import time
from pathlib import Path

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.responses import PlainTextResponse, StreamingResponse

from . import accounts, config

FWGRAPH_ROOT = Path(__file__).resolve().parents[2]
VULNAGENT_HOME = Path(os.getenv(
    "VULNAGENT_HOME", str(FWGRAPH_ROOT.parent / "vulnagent")))
NODE_BIN = os.getenv("VULNAGENT_NODE_BIN", "node")
MAX_PARALLEL = int(os.getenv("VULNAGENT_MAX_SESSIONS", "2"))
MAX_TURNS_CAP = int(os.getenv("VULNAGENT_MAX_TURNS_CAP", "100"))
# Session engine: "dsh" (DeepSeek Harness fwgraph profile, default) or
# "builtin" (the zero-dep agent loop in vulnagent/src). dsh falls back to
# builtin automatically when the harness checkout is missing.
VULNAGENT_ENGINE = os.getenv("VULNAGENT_ENGINE", "dsh")
DSH_REPO = Path(os.getenv("DSH_REPO", str(Path.home() / "deepseek-harness")))
DSH_HOME = os.getenv("DSH_HOME", str(Path.home() / ".dsh"))

_SID_RE = re.compile(r"^s-[a-z0-9]+-[a-f0-9]{4}$")
_FID_RE = re.compile(r"^F-[a-z0-9-]+$")

# finding intake validation (POST /vulnagent/findings)
_SEVERITIES = ("critical", "high", "medium", "low", "info")
_REACHABILITY = ("static", "static-only", "observed", "verified")
_CWE_RE = re.compile(r"^CWE-\d+$")
_VULN_CLASS_BAD_RE = re.compile(r"[/,、]")  # no mixed-class bundles
_STATIC_CONFIDENCE_CAP = 0.7
# path-component whitelists (no '/', no '.') so ids can never traverse
_JOB_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_TRACE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

_FINDINGS_LOCK = threading.Lock()

# session_id -> subprocess.Popen of the CLI runner (dies with this process'
# knowledge only; the child itself is start_new_session=True so a service
# restart leaves it running but unmanageable).
_procs: dict[str, subprocess.Popen] = {}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _data_dir() -> Path:
    """Resolve FWGRAPH_DATA at call time (tests monkeypatch the env var)."""
    return config.data_dir()


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
    """Liveness: the in-process Popen first, then the pid file left on disk
    (survives service restarts — the runner is start_new_session=True)."""
    proc = _procs.get(sid)
    if proc is not None:
        return proc.poll() is None
    pid = _read_pid(VULNAGENT_HOME / "sessions" / sid)
    return pid is not None and _pid_alive(pid)


def _read_pid(sdir: Path) -> int | None:
    try:
        return int((sdir / "runner.pid").read_text().strip())
    except (OSError, ValueError):
        return None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists but owned by someone else
    except OSError:
        return False
    return True


def _live_sessions() -> list:
    """Session ids with a live runner, from _procs + pid files (a restart
    no longer resets the MAX_PARALLEL count)."""
    base = VULNAGENT_HOME / "sessions"
    if not base.is_dir():
        return []
    return sorted(d.name for d in base.iterdir()
                  if d.is_dir() and _alive(d.name))


def _session_owner(sdir: Path) -> str:
    """Owner of a session; pre-ownership sessions count as admin-owned."""
    return _read_state(sdir).get("owner") or "admin"


def _require_session_access(sdir: Path, principal: dict):
    """404 (not 403) for other users' sessions — no existence disclosure."""
    if not accounts.can_access(principal, _session_owner(sdir)):
        raise HTTPException(status_code=404, detail="session not found")


def _migrate_legacy_owners():
    """Stamp owner='admin' onto pre-ownership session state.json files."""
    base = VULNAGENT_HOME / "sessions"
    if not base.is_dir():
        return
    for sdir in base.iterdir():
        state_file = sdir / "state.json"
        if not sdir.is_dir() or not state_file.is_file():
            continue
        state = _read_state(sdir)
        if not state or state.get("owner"):
            continue
        state["owner"] = "admin"
        try:
            state_file.write_text(json.dumps(state, indent=2),
                                  encoding="utf-8")
        except OSError:
            continue


def _effective_status(sid: str, state: dict) -> str:
    if _alive(sid):
        return "running"
    status = state.get("status", "unknown")
    # state.json may stay "running" forever when the service restarts; with
    # no live process (managed or pid-file) report it as interrupted.
    if status == "running":
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
        "owner": state.get("owner") or "admin",
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


def _new_fid() -> str:
    return f"F-{_b36(int(time.time() * 1000))}-{os.urandom(2).hex()}"


def _index_lines(fdir: Path) -> list:
    index = fdir / "index.jsonl"
    if not index.is_file():
        return []
    return index.read_text(encoding="utf-8", errors="replace").splitlines()


def _save_finding(finding: dict, is_new: bool) -> None:
    """Persist one finding: findings/<id>.json (atomic) plus the index.jsonl
    line (append for new, in-place replace for updates — both atomic)."""
    fdir = VULNAGENT_HOME / "findings"
    with _FINDINGS_LOCK:
        fdir.mkdir(parents=True, exist_ok=True)
        accounts._write_json(fdir / f"{finding['id']}.json", finding)
        lines = _index_lines(fdir)
        row = json.dumps(finding, ensure_ascii=False)
        if not is_new:
            for i, line in enumerate(lines):
                try:
                    if json.loads(line).get("id") == finding["id"]:
                        lines[i] = row
                        break
                except json.JSONDecodeError:
                    continue
            else:
                lines.append(row)
        else:
            lines.append(row)
        tmp = fdir / "index.jsonl.tmp"
        tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.replace(tmp, fdir / "index.jsonl")


def _job_owner(job_id: str):
    """(job, owner) from main._jobs; job=None when the job id is unknown."""
    from . import main as _main
    with _main._jobs_lock:
        job = _main._jobs.get(job_id)
        return job, (job.get("owner") if job else None)


def _finding_visible(finding: dict, principal: dict) -> bool:
    """Non-admins only see findings on jobs they own; findings without a
    (known) job association are hidden from them entirely."""
    if principal.get("role") == "admin":
        return True
    job_id = finding.get("job_id")
    if not job_id:
        return False
    job, owner = _job_owner(job_id)
    if job is None:
        return False
    return accounts.can_access(principal, owner)


def _validate_finding(payload: dict) -> dict:
    """Server-side validation for POST /vulnagent/findings.

    Every rejection is a 422 whose Chinese detail names the offending field.
    Returns the normalized finding fields (confidence cap applied, with the
    pre-cap value kept under confidence_reported).
    """
    def bad(detail: str):
        raise HTTPException(status_code=422, detail=detail)

    def req_str(field: str) -> str:
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip():
            bad(f"{field} 必填且必须是非空字符串")
        return value.strip()

    job_id = req_str("job_id")
    if not _JOB_ID_RE.match(job_id):
        bad("job_id 格式非法")
    from . import main as _main
    with _main._jobs_lock:
        job_known = job_id in _main._jobs
    if not job_known and not (
            _data_dir() / "firmware" / job_id / "job.json").is_file():
        bad(f"job_id 对应的任务不存在: {job_id}")

    title = req_str("title")
    summary = req_str("summary")
    binary_path = req_str("binary_path")

    severity = payload.get("severity")
    if severity not in _SEVERITIES:
        bad("severity 必须是 critical|high|medium|low|info 之一")
    reachability = payload.get("reachability")
    if reachability not in _REACHABILITY:
        bad("reachability 必须是 static|static-only|observed|verified 之一")

    vuln_class = req_str("vuln_class")
    if _VULN_CLASS_BAD_RE.search(vuln_class):
        bad("vuln_class 不允许混类（不得含 /、,、等分隔符），请拆成多条 finding")
    cwe = req_str("cwe")
    if not _CWE_RE.match(cwe):
        bad("cwe 必须是单个 CWE 编号，形如 CWE-120")

    binary_md5 = req_str("binary_md5")
    manifest_file = _data_dir() / "extracted" / job_id / "manifest.json"
    manifest = None
    if manifest_file.is_file():
        try:
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            manifest = None
    if manifest is None:
        bad(f"任务 {job_id} 尚无解包 manifest，无法核验 binary_md5")
    known_md5s = {b.get("md5") for b in manifest.get("binaries", [])}
    if binary_md5 not in known_md5s:
        bad(f"binary_md5 不在任务 {job_id} 的 manifest 中: {binary_md5}")

    function_addr = payload.get("function_addr")
    if function_addr is not None:
        if not isinstance(function_addr, str) or not function_addr.strip():
            bad("function_addr 必须是非空字符串（或省略）")
        function_addr = function_addr.strip().lower()
        symbols_file = _data_dir() / "pseudocode" / job_id / "symbols.json"
        symbols = None
        if symbols_file.is_file():
            try:
                symbols = json.loads(symbols_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                symbols = None
        info = (symbols or {}).get("binaries", {}).get(binary_md5)
        if info is None:
            bad(f"任务 {job_id} 无二进制 {binary_md5} 的符号表，"
                "无法核验 function_addr")
        addrs = {str(fn.get("addr") or "").lower()
                 for fn in info.get("functions", [])}
        if function_addr not in addrs:
            bad(f"function_addr 不在该二进制的符号表中: {function_addr}")

    evidence = payload.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        bad("evidence 必须是非空数组")
    if not all(isinstance(e, str) and e.strip() for e in evidence):
        bad("evidence 的每一项都必须是非空字符串")

    confidence = payload.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        bad("confidence 必须是 [0,1] 区间的数值")
    confidence = float(confidence)
    if not 0.0 <= confidence <= 1.0:
        bad("confidence 必须在 [0,1] 区间")

    trace_id = payload.get("trace_id")
    if trace_id is not None:
        if not isinstance(trace_id, str) or not trace_id.strip():
            bad("trace_id 必须是非空字符串（或省略）")
        trace_id = trace_id.strip()
        if not _TRACE_ID_RE.match(trace_id):
            bad("trace_id 格式非法")
    if reachability in ("observed", "verified"):
        if not trace_id:
            bad(f"reachability={reachability} 必须附带 trace_id 作为动态证据")
        trace_file = _data_dir() / "traces" / job_id / trace_id / "trace.json"
        if not trace_file.is_file():
            bad(f"trace_id 对应的 trace 不存在: {trace_id}")

    confidence_reported = None
    if reachability in ("static", "static-only") and confidence > _STATIC_CONFIDENCE_CAP:
        # 静态证据封顶 0.7：原值留痕，落库值封顶
        confidence_reported = confidence
        confidence = _STATIC_CONFIDENCE_CAP

    doc = {
        "job_id": job_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "vuln_class": vuln_class,
        "cwe": cwe,
        "binary_md5": binary_md5,
        "binary_path": binary_path,
        "reachability": reachability,
        "summary": summary,
        "evidence": [e.strip() for e in evidence],
    }
    if confidence_reported is not None:
        doc["confidence_reported"] = confidence_reported
    for field in ("session_id", "function_name", "preconditions",
                  "exploit_sketch", "remediation"):
        value = payload.get(field)
        if value is not None:
            if not isinstance(value, str):
                bad(f"{field} 必须是字符串（或省略）")
            if value.strip():
                doc[field] = value.strip()
    if function_addr is not None:
        doc["function_addr"] = function_addr
    if trace_id is not None:
        doc["trace_id"] = trace_id
    return doc


def _write_report(sdir: Path, state: dict) -> None:
    """Standard Chinese vuln report for dsh-engine sessions (builtin writes
    its own via Session.writeReport). Both mining modes produce it."""
    findings = []
    for fid in state.get("findings", []):
        f = VULNAGENT_HOME / "findings" / f"{fid}.json"
        if f.is_file():
            try:
                findings.append(json.loads(f.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                continue
    if not findings:
        return
    sev_label = {"critical": "严重", "high": "高危", "medium": "中危",
                 "low": "低危", "info": "提示"}
    rank = {s: i for i, s in enumerate(
        ["critical", "high", "medium", "low", "info"])}
    findings.sort(key=lambda f: (rank.get(f.get("severity"), 9),
                                 -(f.get("confidence") or 0)))
    counts = {}
    for f in findings:
        counts[f.get("severity", "info")] = counts.get(
            f.get("severity", "info"), 0) + 1
    lines = ["# 漏洞挖掘报告", "", "## 一、任务信息", "",
             f"- 会话：{state.get('session_id', sdir.name)}",
             f"- 任务：{state.get('task', '')}",
             f"- 引擎：dsh（模式：{state.get('mode', 'dynamic')}）",
             f"- 固件任务：{state.get('job_id', '')}",
             f"- 报告时间：{state.get('updated_at', '')}", "",
             "## 二、发现统计", "",
             f"- 共 {len(findings)} 个漏洞：" + "，".join(
                 f"{sev_label.get(k, k)} {v} 个" for k, v in counts.items()),
             "", "## 三、漏洞详情", ""]
    for i, f in enumerate(findings, 1):
        lines += [f"### 漏洞 {i}：{f.get('title')}（{f.get('id')}）", "",
                  f"- **漏洞类型**：{f.get('vuln_class', '')}"
                  + (f"（{f['cwe']}）" if f.get("cwe") else ""),
                  f"- **危害等级**：{sev_label.get(f.get('severity'), f.get('severity'))}"
                  f"（置信度 {f.get('confidence')}）",
                  f"- **影响组件**：{f.get('binary_path') or f.get('binary_md5')}"
                  f"（md5: {f.get('binary_md5')}）",
                  f"- **漏洞位置**：{f.get('function_name') or '?'} @ {f.get('function_addr')}",
                  f"- **可达性**：{f.get('reachability', 'static-only')}",
                  f"- **漏洞描述**：{f.get('summary', '')}"]
        if f.get("source_summary") or f.get("sink_function"):
            lines.append(f"- **攻击路径**：{f.get('source_summary') or '?'} → "
                         f"sink：{f.get('sink_function') or '?'}")
        if f.get("sanitization"):
            lines.append(f"- **消毒与防护现状**：{f['sanitization']}")
        lines.append("- **漏洞证据**：")
        for j, e in enumerate(f.get("evidence", []), 1):
            lines.append(f"  {j}. {e}")
        if f.get("exploit_sketch"):
            lines.append(f"- **利用思路**：{f['exploit_sketch']}")
        if f.get("remediation"):
            lines.append(f"- **修复建议**：{f['remediation']}")
        lines.append("")
    (sdir / "report.md").write_text(chr(10).join(lines), encoding="utf-8")


def _vulnagent_env() -> dict:
    """vulnagent/.env as a dict (last value wins)."""
    env = {}
    dotenv = VULNAGENT_HOME / ".env"
    if dotenv.is_file():
        for line in dotenv.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip()
    return env


def _spawn_dsh(sid: str, sdir: Path, task: str, mode: str = "dynamic",
               job_id: str | None = None, max_turns: int = 40,
               owner: str = "admin"):
    """Launch one vuln-mining session on the DeepSeek Harness engine.

    The fwgraph profile (vulnagent/dsh/) composes dsh-base + dsh-headless +
    our tools/events plugins; the events plugin writes events.sse in the
    vulnagent format, and this wrapper maintains state.json + session_end so
    the sessions API works identically for both engines. max_turns reaches
    the harness through FWGRAPH_MAX_TURNS (the dsh CLI has no such flag);
    the tools plugin stamps findings with FWGRAPH_SESSION_ID, which _watch
    uses to attribute findings to this session."""
    env_file = _vulnagent_env()
    env = dict(os.environ)
    env.update({
        "PATH": str(Path.home() / ".local/bin") + ":" + env.get("PATH", ""),
        "DSH_HOME": DSH_HOME,
        "DEEPSEEK_API_KEY": env_file.get("LLM_API_KEY", ""),
        "DEEPSEEK_BASE_URL": env_file.get("LLM_BASE_URL", ""),
        "FWGRAPH_BASE_URL": env_file.get("FWGRAPH_BASE_URL", ""),
        "FWGRAPH_TOKEN": env_file.get("FWGRAPH_TOKEN", ""),
        "FWGRAPH_JOB_ID": job_id or env_file.get("FWGRAPH_JOB_ID", ""),
        "FWGRAPH_FINDINGS_DIR": str(VULNAGENT_HOME / "findings"),
        "FWGRAPH_EVENTS_FILE": str(sdir / "events.sse"),
        "FWGRAPH_SESSION_ID": sid,
        "FWGRAPH_TASK": task,
        "FWGRAPH_MODE": mode,
        "FWGRAPH_MAX_TURNS": str(max_turns),
    })
    cmd = [NODE_BIN, "--import", "tsx/esm", "apps/cli/src/bin.ts",
           "--profile", "fwgraph", task]
    log_file = open(sdir / "runner.log", "ab")
    proc = subprocess.Popen(cmd, cwd=str(DSH_REPO), env=env,
                            stdout=log_file, stderr=subprocess.STDOUT,
                            start_new_session=True)
    log_file.close()
    try:
        (sdir / "runner.pid").write_text(str(proc.pid), encoding="utf-8")
    except OSError:
        pass

    now = _now()
    state = {
        "session_id": sid,
        "agent_id": "vuln-miner-fwgraph (dsh)",
        "environment_id": "fwgraph-dsh",
        "task": task, "status": "running", "turns": 0,
        "usage": {}, "findings": [],
        "created_at": now, "updated_at": now, "engine": "dsh",
        "mode": mode, "job_id": job_id or env_file.get("FWGRAPH_JOB_ID", ""),
        "max_turns": max_turns, "owner": owner or "admin",
    }
    (sdir / "state.json").write_text(json.dumps(state, indent=2),
                                     encoding="utf-8")

    def _watch():
        rc = proc.wait()
        end = _now()
        # findings the dsh tools plugin recorded under this session id
        # (no more timestamp guessing — FWGRAPH_SESSION_ID is authoritative)
        found = []
        fdir = VULNAGENT_HOME / "findings"
        if fdir.is_dir():
            for f in sorted(fdir.glob("F-*.json")):
                try:
                    doc = json.loads(f.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if doc.get("session_id") == sid and doc.get("id"):
                    found.append(doc["id"])
        state["status"] = "done" if rc == 0 else "error"
        state["findings"] = found
        state["updated_at"] = end
        try:
            _write_report(sdir, state)
        except Exception as exc:  # noqa: BLE001 - report must never break finalize
            msg = f"report generation failed: {type(exc).__name__}: {exc}"
            for target in ("runner.log",):
                try:
                    with open(sdir / target, "a", encoding="utf-8") as fh:
                        fh.write(f"[vulnagent_api] {msg}\n")
                except OSError:
                    pass
            try:
                with open(sdir / "events.sse", "a", encoding="utf-8") as fh:
                    fh.write("event: error\ndata: "
                             + json.dumps({"seq": 10**9 - 1, "ts": end,
                                           "error": msg}) + "\n\n")
            except OSError:
                pass
        (sdir / "state.json").write_text(json.dumps(state, indent=2),
                                         encoding="utf-8")
        try:
            with open(sdir / "events.sse", "a", encoding="utf-8") as fh:
                fh.write("event: session_end\ndata: "
                         + json.dumps({"seq": 10**9, "ts": end,
                                       "summary": f"dsh engine exited rc={rc}",
                                       "findings": found}) + "\n\n")
        except OSError:
            pass

    threading.Thread(target=_watch, daemon=True).start()
    return proc


def setup(app: FastAPI, require_token) -> None:
    """Register vulnagent routes. Call BEFORE webui.setup(app) so the SPA
    catch-all does not shadow them."""
    auth = [Depends(require_token)]
    _migrate_legacy_owners()

    @app.post("/vulnagent/sessions", status_code=202)
    def start_session(payload: dict = Body(...),
                      principal: dict = Depends(require_token)):
        task = str(payload.get("task") or "").strip()
        if not task:
            raise HTTPException(status_code=400, detail="'task' required")
        if len(task) > 4000:
            raise HTTPException(status_code=400, detail="task too long (4000)")
        mode = str(payload.get("mode") or "dynamic")
        if mode not in ("static", "dynamic"):
            raise HTTPException(status_code=400,
                                detail="mode must be static|dynamic")
        job_id = str(payload.get("job_id") or "").strip() or None
        # 前置门禁：漏洞挖掘必须建立在攻击面分析 + 图谱构建之上，禁止裸跑
        gate_job = job_id or _vulnagent_env().get("FWGRAPH_JOB_ID", "")
        data_dir = _data_dir()
        if not gate_job:
            raise HTTPException(
                status_code=400,
                detail="缺少 job_id：漏洞挖掘必须绑定固件任务"
                       "（payload.job_id 或 vulnagent/.env 的 FWGRAPH_JOB_ID）")
        if not (data_dir / "cbm" / gate_job / "graph_done.json").is_file() \
                and not list((data_dir / "cbm").glob(f"{gate_job}/*/graph_done.json")):
            raise HTTPException(
                status_code=409,
                detail="job 尚未完成图谱构建——先做图谱构建与攻击面分析")
        if not (data_dir / "attack" / gate_job / "attack_done.json").is_file():
            raise HTTPException(
                status_code=409,
                detail="job 尚未完成攻击面分析——漏洞挖掘必须从攻击面与图谱取数")
        max_turns = int(payload.get("max_turns") or 40)
        if not 1 <= max_turns <= MAX_TURNS_CAP:
            raise HTTPException(status_code=400,
                                detail=f"max_turns must be 1..{MAX_TURNS_CAP}")
        if not (VULNAGENT_HOME / "src" / "cli.js").is_file():
            raise HTTPException(status_code=503,
                                detail=f"vulnagent not deployed at {VULNAGENT_HOME}")
        running = _live_sessions()
        if len(running) >= MAX_PARALLEL:
            raise HTTPException(
                status_code=409,
                detail=f"{len(running)} sessions already running (cap {MAX_PARALLEL}): "
                       + ", ".join(running))
        sid = _new_sid()
        sdir = VULNAGENT_HOME / "sessions" / sid
        sdir.mkdir(parents=True, exist_ok=True)
        if VULNAGENT_ENGINE == "dsh" and (DSH_REPO / "apps/cli").is_dir():
            try:
                proc = _spawn_dsh(sid, sdir, task, mode=mode, job_id=job_id,
                                  max_turns=max_turns,
                                  owner=principal["username"])
            except OSError as exc:
                raise HTTPException(
                    status_code=500,
                    detail=f"failed to spawn dsh: {exc}") from exc
            _procs[sid] = proc
            time.sleep(1.2)
            if proc.poll() is not None:
                tail = (sdir / "runner.log").read_text(
                    encoding="utf-8", errors="replace")[-500:]
                raise HTTPException(
                    status_code=500,
                    detail=f"dsh runner exited rc={proc.returncode}: {tail}")
            accounts.audit(principal["username"], "session_start",
                           f"{sid} engine=dsh job={gate_job} mode={mode}")
            return {"session_id": sid, "status": "running",
                    "engine": "dsh", "max_turns": max_turns}
        log_file = open(sdir / "runner.log", "ab")
        cmd = [NODE_BIN, "src/cli.js", "run", task,
               "--max-turns", str(max_turns), "--session", sid, "--quiet",
               "--mode", mode]
        spawn_env = dict(os.environ)
        if job_id:
            spawn_env["FWGRAPH_JOB_ID"] = job_id
        try:
            proc = subprocess.Popen(
                cmd, cwd=str(VULNAGENT_HOME), stdout=log_file,
                stderr=subprocess.STDOUT, start_new_session=True,
                env=spawn_env)
        except OSError as exc:
            log_file.close()
            raise HTTPException(status_code=500,
                                detail=f"failed to spawn node: {exc}") from exc
        _procs[sid] = proc
        try:
            (sdir / "runner.pid").write_text(str(proc.pid), encoding="utf-8")
        except OSError:
            pass
        # Fail fast if the runner dies immediately (bad env, syntax error).
        time.sleep(0.8)
        if proc.poll() is not None:
            tail = (sdir / "runner.log").read_text(
                encoding="utf-8", errors="replace")[-500:]
            raise HTTPException(status_code=500,
                                detail=f"runner exited rc={proc.returncode}: {tail}")
        # the builtin CLI owns state.json; stamp owner onto it best-effort
        # (the vulnagent-side patch keeps it on later rewrites)
        state = _read_state(sdir)
        if state and not state.get("owner"):
            state["owner"] = principal["username"]
            try:
                (sdir / "state.json").write_text(json.dumps(state, indent=2),
                                                 encoding="utf-8")
            except OSError:
                pass
        accounts.audit(principal["username"], "session_start",
                       f"{sid} engine=builtin job={gate_job} mode={mode}")
        return {"session_id": sid, "status": "running", "max_turns": max_turns}

    @app.get("/vulnagent/sessions")
    def list_sessions(principal: dict = Depends(require_token)):
        base = VULNAGENT_HOME / "sessions"
        out = [_session_summary(d) for d in sorted(base.iterdir(), reverse=True)
               if d.is_dir()] if base.is_dir() else []
        out = [s for s in out if accounts.can_access(principal, s["owner"])]
        out.sort(key=lambda s: s.get("created_at") or "", reverse=True)
        return out

    @app.get("/vulnagent/sessions/{sid}")
    def get_session(sid: str, principal: dict = Depends(require_token)):
        sdir = _session_dir(sid)
        _require_session_access(sdir, principal)
        summary = _session_summary(sdir)
        summary["finding_objects"] = [
            f for f in (_load_finding(fid) for fid in summary["findings"]) if f]
        return summary

    @app.get("/vulnagent/sessions/{sid}/events")
    async def session_events(sid: str, follow: int = 1, after: int = 0,
                             principal: dict = Depends(require_token)):
        sdir = _session_dir(sid)
        _require_session_access(sdir, principal)
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

    @app.get("/vulnagent/sessions/{sid}/report")
    def session_report(sid: str, principal: dict = Depends(require_token)):
        sdir = _session_dir(sid)
        _require_session_access(sdir, principal)
        report = sdir / "report.md"
        if not report.is_file():
            raise HTTPException(status_code=404,
                                detail="no report (no findings recorded yet)")
        return PlainTextResponse(report.read_text(encoding="utf-8",
                                                  errors="replace"))

    @app.post("/vulnagent/sessions/{sid}/stop")
    def stop_session(sid: str, principal: dict = Depends(require_token)):
        sdir = _session_dir(sid)
        _require_session_access(sdir, principal)
        proc = _procs.get(sid)
        if proc is not None and proc.poll() is None:
            proc.terminate()
            accounts.audit(principal["username"], "session_stop", sid)
            return {"session_id": sid, "status": "terminating"}
        # unmanaged but alive (service restarted): SIGTERM via the pid file
        pid = _read_pid(sdir)
        if pid is not None and _pid_alive(pid):
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError as exc:
                raise HTTPException(
                    status_code=500,
                    detail=f"SIGTERM pid={pid} 失败: {exc}") from exc
            accounts.audit(principal["username"], "session_stop",
                           f"{sid} pid={pid}")
            return {"session_id": sid, "status": "terminating"}
        raise HTTPException(status_code=409,
                            detail="session not running (or not managed "
                                   "by this service process)")

    @app.post("/vulnagent/findings", status_code=201)
    def create_finding(payload: dict = Body(...),
                       principal: dict = Depends(require_token)):
        """Server-validated finding intake for the mining agent.

        Every field is checked against the job's actual artifacts
        (manifest / symbols.json / traces) so the model cannot invent
        binaries, addresses or dynamic evidence. All rejections are 422
        with a Chinese detail naming the field.
        """
        doc = _validate_finding(payload)
        fdir = VULNAGENT_HOME / "findings"
        fdir.mkdir(parents=True, exist_ok=True)
        fid = _new_fid()
        while (fdir / f"{fid}.json").is_file():
            fid = _new_fid()  # collision: re-roll
        doc.update({
            "id": fid,
            "status": "draft",
            "owner": principal["username"],
            "recorded_at": _now(),
            "history": [],
        })
        _save_finding(doc, is_new=True)
        accounts.audit(principal["username"], "finding_create",
                       f"{fid} job={doc['job_id']} severity={doc['severity']}")
        return doc

    @app.patch("/vulnagent/findings/{fid}")
    def update_finding_status(fid: str, payload: dict = Body(...),
                              principal: dict = Depends(require_token)):
        finding = _load_finding(fid)
        if finding is None or not _finding_visible(finding, principal):
            raise HTTPException(status_code=404, detail="finding not found")
        status = str(payload.get("status") or "")
        if status not in ("draft", "verified", "disputed", "retracted"):
            raise HTTPException(
                status_code=400,
                detail="status 必须是 draft|verified|disputed|retracted 之一")
        note = payload.get("note")
        if note is not None and not isinstance(note, str):
            raise HTTPException(status_code=400, detail="note 必须是字符串")
        finding["id"] = fid  # the URL fid passed _FID_RE; never trust content
        finding["status"] = status
        finding.setdefault("history", []).append({
            "ts": _now(), "status": status, "note": note or "",
            "user": principal["username"],
        })
        _save_finding(finding, is_new=False)
        accounts.audit(principal["username"], "finding_status",
                       f"{fid} -> {status}")
        return finding

    @app.get("/vulnagent/findings")
    def list_findings(principal: dict = Depends(require_token)):
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
        if principal.get("role") != "admin":
            out = [f for f in out if _finding_visible(f, principal)]
        return out

    @app.get("/vulnagent/findings/{fid}")
    def get_finding(fid: str, principal: dict = Depends(require_token)):
        finding = _load_finding(fid)
        if finding is None or not _finding_visible(finding, principal):
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
