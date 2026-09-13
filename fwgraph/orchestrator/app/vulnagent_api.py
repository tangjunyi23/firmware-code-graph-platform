"""Vuln-mining agent API: operate the upstream vulnagent from the web UI.

The agent itself is the Node harness in <repo>/vulnagent/ (Managed Agents
layout: agent.json = Agent, environment.json = Environment, sessions/<id> =
Session, sessions/<id>/events.sse = Events). This module only launches
sessions, streams their SSE event log, and serves their findings/report —
it never touches the agent's reasoning or the downstream evidence.

Endpoints (all Bearer-auth via the orchestrator's require_token):
  POST /vulnagent/sessions               {task, max_turns?} -> 202 {session_id}
                                         （dsh web host 模式：每会话一个 harness
                                         web host 进程，preset=fwgraph）
  GET  /vulnagent/sessions               session list (newest first;
                                         non-admin: own sessions only)
  GET  /vulnagent/sessions/{sid}         state.json + resolved findings
  GET  /vulnagent/sessions/{sid}/events  SSE stream (live-follow while running)
  POST /vulnagent/sessions/{sid}/rpc/{method}  harness JSON-RPC 透传（白名单：
                                         prompt/history/cancel/updateQueue/fork/
                                         rename/models/selectModel/list 等）
  GET  /vulnagent/sessions/{sid}/mux     harness 事件流（WS→SSE 桥）
  POST /vulnagent/sessions/{sid}/respond 审批/提问答复转发
  GET  /vulnagent/sessions/{sid}/report  Markdown report
  POST /vulnagent/sessions/{sid}/stop    best-effort terminate
  POST /vulnagent/sessions/{sid}/resume  用户在暂停/结束后发消息：拉活再 prompt
  POST /vulnagent/sessions/{sid}/continue 到顶后续跑（放宽 max_turns）
  PATCH /vulnagent/sessions/{sid}        {archived: bool} hide/restore in the list
  POST /vulnagent/sessions/purge-archived  delete every archived session the caller can see
  DELETE /vulnagent/sessions/{sid}       stop if running, then remove session dir
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
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.responses import PlainTextResponse, StreamingResponse

from . import accounts, config
from . import dsh_host as _dsh_host

FWGRAPH_ROOT = Path(__file__).resolve().parents[2]
VULNAGENT_HOME = Path(os.getenv(
    "VULNAGENT_HOME", str(FWGRAPH_ROOT.parent / "vulnagent")))
NODE_BIN = os.getenv("VULNAGENT_NODE_BIN", "node")
MAX_PARALLEL = int(os.getenv("VULNAGENT_MAX_SESSIONS", "2"))
MAX_TURNS_CAP = int(os.getenv("VULNAGENT_MAX_TURNS_CAP", "200"))
# Session engine is DeepSeek Harness only (fwgraph profile). The builtin
# loop remains in vulnagent/src for offline CLI tests (`--engine builtin`).
VULNAGENT_ENGINE = "dsh"
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
    """Liveness: managed dsh host, in-process CLI Popen, then the pid file
    left on disk (survives service restarts — the runner is
    start_new_session=True)."""
    proc = _procs.get(sid)
    if proc is not None:
        return proc.poll() is None
    mgr = _dsh_manager
    if mgr is not None and sid in mgr.live_sids():
        return True
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
    """Session ids with a live hunt. Hosts spawned only to serve history
    on an already-done session do not consume MAX_PARALLEL. A session
    that is still booting (status=running, no pid file yet) counts so
    two overlapping POSTs cannot skip the cap."""
    base = VULNAGENT_HOME / "sessions"
    if not base.is_dir():
        return []
    out = []
    for d in base.iterdir():
        if not d.is_dir():
            continue
        if _read_state(d).get("status") != "running":
            continue
        if _alive(d.name) or not (d / "runner.pid").is_file():
            out.append(d.name)
    return sorted(out)


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
    status = state.get("status", "unknown")
    # 已结束的会话可能为了 history 再拉起 host；不要把「能回放」当成还在挖。
    if status in ("done", "error", "awaiting_continue"):
        return status
    if _alive(sid):
        return "running"
    # still booting: state is running but the pid file is not there yet
    if status == "running":
        sdir = VULNAGENT_HOME / "sessions" / sid
        if not (sdir / "runner.pid").is_file():
            return "running"
        return "interrupted"
    return status


def _session_finding_ids(sid: str) -> list:
    """Live finding ids for a session (disk is source of truth while running)."""
    found = []
    fdir = VULNAGENT_HOME / "findings"
    if not fdir.is_dir():
        return found
    for f in sorted(fdir.glob("F-*.json")):
        try:
            doc = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if doc.get("session_id") == sid and _FID_RE.match(str(doc.get("id") or "")):
            found.append(doc["id"])
    return found


def _session_summary(sdir: Path) -> dict:
    state = _read_state(sdir)
    sid = state.get("session_id", sdir.name)
    return {
        "session_id": sid,
        "task": state.get("task", ""),
        "status": _effective_status(sid, state),
        "turns": state.get("turns", 0),
        "findings": _session_finding_ids(sid) or state.get("findings", []),
        "usage": state.get("usage", {}),
        "created_at": state.get("created_at"),
        "updated_at": state.get("updated_at"),
        "managed": _alive(sid),
        "owner": state.get("owner") or "admin",
        "job_id": state.get("job_id") or "",
        "mode": state.get("mode") or "dynamic",
        "engine": state.get("engine") or "",
        "archived": bool(state.get("archived")),
        "dsh_session_id": state.get("dsh_session_id") or "",
        "error": state.get("error") or "",
        "approval_policy": state.get("approval_policy") or "auto",
        "max_turns": int(state.get("max_turns") or 80),
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


def _bind_hunt_session(job_id: str, sid: str) -> None:
    if not job_id or not sid:
        return
    from . import main as _main
    with _main._jobs_lock:
        job = _main._jobs.get(job_id)
        if not job:
            return
        job["hunt_session_id"] = sid
        _main._save_job(job)


def _unbind_hunt_session(job_id: str, sid: str) -> None:
    if not job_id or not sid:
        return
    from . import main as _main
    with _main._jobs_lock:
        job = _main._jobs.get(job_id)
        if not job or job.get("hunt_session_id") != sid:
            return
        job.pop("hunt_session_id", None)
        _main._save_job(job)


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

    chain = payload.get("call_chain")
    if not isinstance(chain, str) or not chain.strip():
        bad("call_chain 必填，用 → 连接函数名与地址")
    if "→" not in chain and "->" not in chain:
        bad("call_chain 须用 → 连接调用路径（函数名+地址）")
    poc = payload.get("poc") or payload.get("exploit_sketch")
    if not isinstance(poc, str) or not poc.strip():
        bad("poc 必填，须给出可复现请求或命令")

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
                  "exploit_sketch", "remediation", "poc", "call_chain",
                  "source_summary", "sink_function", "sanitization"):
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


def _trace_digest(job_id: str, limit: int = 24) -> list[dict]:
    """Newest traces for the session report (status/via/diff only)."""
    if not job_id:
        return []
    root = _data_dir() / "traces" / job_id
    if not root.is_dir():
        return []
    rows = []
    files = sorted(root.glob("*/trace.json"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    for path in files[:limit]:
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        req = doc.get("request") or {}
        diff = doc.get("diff") or {}
        rows.append({
            "trace_id": doc.get("trace_id") or path.parent.name,
            "status": doc.get("status") or "",
            "via": req.get("via") or "",
            "port": req.get("port"),
            "functions": diff.get("function_count"),
            "error": (doc.get("error") or "")[:160],
        })
    return rows


def _write_report(sdir: Path, state: dict) -> None:
    """Always write a Chinese hunt report, even when nothing was recorded."""
    findings = []
    for fid in state.get("findings", []):
        f = VULNAGENT_HOME / "findings" / f"{fid}.json"
        if f.is_file():
            try:
                findings.append(json.loads(f.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                continue
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
    traces = _trace_digest(str(state.get("job_id") or ""))
    with_diff = sum(1 for t in traces if (t.get("functions") or 0) > 0)

    def cell(v):
        return str(v if v is not None else "").replace("|", "\\|") \
            .replace("\n", " ").strip() or "-"

    sid = state.get("session_id", sdir.name)
    job_id = state.get("job_id", "")
    lines = [
        "# 漏洞挖掘报告", "",
        f"> 会话 `{cell(sid)}` · 固件任务 `{cell(job_id)}` · "
        f"{cell(state.get('updated_at', ''))}",
        "",
        "## 一、任务信息", "",
        "| 项 | 内容 |", "| --- | --- |",
        f"| 任务目标 | {cell(state.get('task', ''))} |",
        f"| 引擎 | dsh（模式：{cell(state.get('mode', 'dynamic'))}） |",
        f"| 轮次 | {state.get('turns', 0)} / {state.get('max_turns', '')} |",
        "",
        "## 二、发现统计", "",
    ]
    if findings:
        lines += ["| 危害等级 | 数量 |", "| --- | --- |"]
        for k in ("critical", "high", "medium", "low", "info"):
            if k in counts:
                lines.append(f"| **{sev_label[k]}** | {counts[k]} |")
        lines.append(f"| 合计 | {len(findings)} |")
    else:
        lines.append("- 本轮没有入库漏洞。空差分、连通、启动崩溃不是漏洞，未做投机记录。")
    lines += ["", "## 三、动态验证", "",
              f"- 摘录最近 {len(traces)} 条 trace，其中非空差分 {with_diff} 条。"]
    if traces:
        lines += ["",
                  "| Trace | 状态 | 入口 | 差分函数 | 备注 |",
                  "| --- | --- | --- | --- | --- |"]
        for t in traces:
            port = f":{t['port']}" if t.get("port") else ""
            nfn = t.get("functions")
            nfn_s = "-" if nfn is None else str(nfn)
            via = f"{t.get('via') or '-'}{port}"
            lines.append(
                f"| `{cell(t.get('trace_id'))}` | {cell(t.get('status'))} "
                f"| `{cell(via)}` | {nfn_s} | {cell(t.get('error'))} |")
    else:
        lines.append("- （还没有 trace 记录）")
    lines += ["", "## 四、漏洞详情", ""]
    if not findings:
        lines += ["（无入库条目）", ""]
    for i, f in enumerate(findings, 1):
        cwe = f.get("cwe") or ""
        addr = f.get("function_addr") or ""
        md5 = f.get("binary_md5") or ""
        sev = sev_label.get(f.get("severity"), f.get("severity"))
        lines += [
            f"### 漏洞 {i}：{f.get('title')}（`{f.get('id')}`）", "",
            "| 字段 | 内容 |", "| --- | --- |",
            f"| 漏洞类型 | {cell(f.get('vuln_class', ''))}"
            + (f" `{cell(cwe)}`" if cwe else "") + " |",
            f"| 危害等级 | **{cell(sev)}**"
            f"（置信度 {cell(f.get('confidence'))}） |",
            f"| 影响组件 | `{cell(f.get('binary_path') or md5)}` |",
            f"| 二进制指纹 | `{cell(md5)}` |",
            f"| 漏洞位置 | `{cell(f.get('function_name') or '?')}` @ "
            f"`{cell(addr)}` |",
            f"| 可达性 | {cell(f.get('reachability', 'static-only'))} |",
            "",
            f"**漏洞描述**：{f.get('summary', '')}",
            "",
        ]
        if f.get("sanitization"):
            lines += [f"**消毒与防护现状**：{f['sanitization']}", ""]
        evid = f.get("evidence") or []
        if evid:
            lines.append("**漏洞证据**：")
            lines.append("")
            for j, e in enumerate(evid, 1):
                lines.append(f"{j}. {e}")
            lines.append("")
        chain = (f.get("call_chain") or "").strip()
        if not chain:
            src = (f.get("source_summary") or "").strip()
            sink = (f.get("sink_function") or "").strip()
            if src or sink:
                chain = f"{src or '入口未知'} → {sink or 'sink 未知'}"
        lines += ["**调用链**：", ""]
        if chain:
            lines += ["```", chain.replace("```", "'''"), "```", ""]
        else:
            lines += ["（未给出调用链）", ""]
        poc = (f.get("poc") or f.get("exploit_sketch") or "").strip()
        lines += ["**漏洞 PoC**：", ""]
        if poc:
            lines += ["```", poc.replace("```", "'''"), "```", ""]
        else:
            lines += ["（未给出可复现 PoC）", ""]
        if f.get("remediation"):
            lines += [f"**修复建议**：{f['remediation']}", ""]
        lines.append("")
    (sdir / "report.md").write_text(chr(10).join(lines), encoding="utf-8")


def _parse_sse_file(path: Path) -> list[tuple[str, dict]]:
    """Parse vulnagent events.sse into (type, data) pairs."""
    if not path.is_file():
        return []
    out: list[tuple[str, dict]] = []
    ev = None
    buf: list[str] = []

    def flush():
        nonlocal ev, buf
        if ev is None:
            buf = []
            return
        raw = "\n".join(buf).strip()
        buf = []
        typ, ev = ev, None
        if not raw:
            return
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return
        if isinstance(data, dict):
            out.append((typ, data))

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    for line in text.splitlines():
        if line.startswith("event:"):
            flush()
            ev = line[6:].strip()
        elif line.startswith("data:"):
            buf.append(line[5:].lstrip())
        elif not line.strip():
            flush()
    flush()
    return out


def _history_from_sse(sdir: Path, payload: dict | None = None) -> dict:
    """Replay events.sse as harness session.history, without booting dsh.

    stream:true 中间帧丢掉，只留 block 终态，打开已结束会话不必等宿主。
    """
    payload = payload or {}
    try:
        cap = int(payload.get("maxMessages") or 160)
    except (TypeError, ValueError):
        cap = 160
    cap = max(20, min(cap, 800))
    harness: list[dict] = []

    def add(typ: str, data: dict, seq=None):
        harness.append({
            "event": {"type": typ, "seq": len(harness) + 1, "data": data},
        })

    for typ, data in _parse_sse_file(sdir / "events.sse"):
        seq = data.get("seq")
        if typ == "session_start":
            task = str(data.get("task") or "").strip()
            if task:
                add("user/message",
                    {"content": task, "source": {"kind": "user"}}, seq)
        elif typ in ("thinking", "text"):
            if data.get("stream") is True:
                continue
            text = str(data.get("text") or "")
            if not text:
                continue
            kind = "reasoning" if typ == "thinking" else "text"
            turn = int(seq or len(harness) + 1)
            add("assistant/chunk", {
                "turn": turn, "step": 0,
                "chunk": {"type": "block-start", "index": 0, "blockType": kind},
            }, seq)
            delta = "reasoning-delta" if kind == "reasoning" else "text-delta"
            add("assistant/chunk", {
                "turn": turn, "step": 0,
                "chunk": {"type": delta, "index": 0, "text": text},
            }, seq)
            add("assistant/chunk", {
                "turn": turn, "step": 0,
                "chunk": {"type": "block-end", "index": 0},
            }, seq)
        elif typ == "tool_call":
            args = data.get("input")
            if not isinstance(args, str):
                try:
                    args = json.dumps(args or {}, ensure_ascii=False)
                except (TypeError, ValueError):
                    args = "{}"
            add("tool/call", {
                "callId": data.get("id"),
                "name": data.get("name") or "",
                "arguments": args,
            }, seq)
        elif typ == "tool_result":
            add("tool/result", {
                "callId": data.get("id"),
                "name": data.get("name") or "",
                "message": {
                    "toolCallId": data.get("id"),
                    "content": data.get("preview") or "",
                    "isError": bool(data.get("is_error")),
                },
            }, seq)
        elif typ == "session_end":
            add("turn/end", {"reason": data.get("reason") or "completed"}, seq)
    has_more = False
    if len(harness) > cap:
        head = []
        if harness and harness[0]["event"]["type"] == "user/message":
            head = harness[:1]
        harness = head + harness[-(cap - len(head)):]
        has_more = True
    return {"events": harness, "hasMore": has_more, "source": "sse"}


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


def _inject_node_ca(env: dict, env_file: dict) -> None:
    """Node fetch 必须信任编排器自签证书，否则 fw_* HTTP 工具全部失败。"""
    for candidate in (
        env_file.get("NODE_EXTRA_CA_CERTS"),
        env.get("NODE_EXTRA_CA_CERTS"),
        str(_data_dir() / "tls" / "cert.pem"),
        str(FWGRAPH_ROOT / "data" / "tls" / "cert.pem"),
    ):
        if candidate and Path(candidate).is_file():
            env["NODE_EXTRA_CA_CERTS"] = candidate
            return


def _refresh_job_report(job_id: str) -> None:
    """finding 入库后刷新任务漏洞报告（失败不影响入库）。"""
    if not job_id:
        return
    try:
        from pipeline import report as job_report
        job_report.generate_job_report(job_id, _data_dir())
    except Exception:
        pass


# ---------------- dsh web host（工作台多轮会话/queue/steer/审批） ----------------


def _dsh_env(sid: str, sdir: Path, state: dict) -> dict:
    """web host 模式的 env 组装（与 _spawn_dsh 同源，值从 state 取）。"""
    env_file = _vulnagent_env()
    env = dict(os.environ)
    env.update({
        "PATH": str(Path.home() / ".local/bin") + ":" + env.get("PATH", ""),
        "DSH_HOME": DSH_HOME,
        "DEEPSEEK_API_KEY": env_file.get("LLM_API_KEY", ""),
        "DEEPSEEK_BASE_URL": env_file.get("LLM_BASE_URL", ""),
        "FWGRAPH_BASE_URL": env_file.get("FWGRAPH_BASE_URL", ""),
        "FWGRAPH_TOKEN": env_file.get("FWGRAPH_TOKEN", ""),
        "FWGRAPH_JOB_ID": state.get("job_id")
                          or env_file.get("FWGRAPH_JOB_ID", ""),
        "FWGRAPH_FINDINGS_DIR": str(VULNAGENT_HOME / "findings"),
        "FWGRAPH_EVENTS_FILE": str(sdir / "events.sse"),
        "FWGRAPH_SESSION_ID": sid,
        "FWGRAPH_TASK": state.get("task", ""),
        "FWGRAPH_MODE": state.get("mode", "dynamic"),
        "FWGRAPH_MAX_TURNS": str(state.get("max_turns") or 40),
        "FWGRAPH_EXTRACTED_ROOT": str(_data_dir() / "extracted"),
        # ask = 动态工具走审批面板；auto = 无人值守直接放行（fuzz/trace 才能真正跑）
        "FWGRAPH_APPROVAL": (
            "1" if str(state.get("approval_policy") or "auto") == "ask"
            else "auto"),
    })
    _inject_node_ca(env, env_file)
    return env


def _dsh_finalize(sid: str, sdir: Path, state: dict, reason: str) -> None:
    """stop/reap 收尾：归拢本 session 的 findings、写报告、落 state、
    补 session_end 事件（与 _watch 的一次性 CLI 收尾等价）。"""
    fresh = _read_state(sdir) or state
    found = _session_finding_ids(sid)
    fresh["status"] = "done"
    fresh["findings"] = found
    fresh["updated_at"] = _now()
    try:
        _write_report(sdir, fresh)
        _refresh_job_report(fresh.get("job_id") or "")
    except Exception as exc:  # noqa: BLE001 - 报告失败不能拖垮收尾
        try:
            with open(sdir / "runner.log", "a", encoding="utf-8") as fh:
                fh.write(f"[vulnagent_api] report generation failed: "
                         f"{type(exc).__name__}: {exc}\n")
        except OSError:
            pass
    try:
        (sdir / "state.json").write_text(json.dumps(fresh, indent=2),
                                         encoding="utf-8")
    except OSError:
        pass
    try:
        with open(sdir / "events.sse", "a", encoding="utf-8") as fh:
            fh.write("event: session_end\ndata: "
                     + json.dumps({"seq": 10**9, "ts": fresh["updated_at"],
                                   "summary": f"dsh web host {reason}",
                                   "findings": found}) + "\n\n")
    except OSError:
        pass


_dsh_manager: _dsh_host.DshHostManager | None = None


def _manager() -> _dsh_host.DshHostManager:
    global _dsh_manager
    if _dsh_manager is None:
        _dsh_manager = _dsh_host.DshHostManager(
            DSH_REPO, NODE_BIN, _dsh_env, _dsh_finalize,
            persist=lambda sid, sdir, state: _save_state(sdir, state))
    return _dsh_manager


def _cap_detail(turns: int, max_turns: int) -> dict:
    return {
        "code": "max_turns",
        "turns": turns,
        "max_turns": max_turns,
        "message": f"已达 {max_turns} 轮上限，确认后可继续挖掘",
    }


def _pause_for_continue(sdir: Path, state: dict) -> None:
    state["status"] = "awaiting_continue"
    _save_state(sdir, state)


def _charge_turn(sdir: Path, state: dict) -> dict:
    """session.prompt 计一轮。到 max_turns 后暂停并询问是否继续。"""
    max_turns = int(state.get("max_turns") or 80)
    turns = int(state.get("turns") or 0)
    if turns >= max_turns:
        _pause_for_continue(sdir, state)
        raise HTTPException(status_code=409, detail=_cap_detail(turns, max_turns))
    state["turns"] = turns + 1
    if state.get("status") == "awaiting_continue":
        state["status"] = "running"
    _save_state(sdir, state)
    return state


def _save_state(sdir: Path, state: dict) -> None:
    state["updated_at"] = _now()
    try:
        (sdir / "state.json").write_text(json.dumps(state, indent=2),
                                         encoding="utf-8")
    except OSError:
        pass


def _force_rmtree(path: Path) -> None:
    """Retry rmtree: host logs / pid files may still be open for a beat."""

    def _fix(func, p, _exc):
        try:
            os.chmod(p, 0o700)
            func(p)
        except OSError:
            pass

    for _ in range(12):
        if not path.exists():
            return
        try:
            shutil.rmtree(path, onexc=_fix)
        except OSError:
            pass
        if not path.exists():
            return
        time.sleep(0.12)


def _wipe_session(sid: str, sdir: Path, state: dict) -> None:
    """Kill host (and keep it from respawning) then remove the session dir."""
    try:
        _manager().stop(sid, sdir, state, reason="delete", finalize=False,
                        discard=True)
    except Exception:
        pass
    proc = _procs.pop(sid, None)
    if proc is not None and proc.poll() is None:
        try:
            proc.terminate()
        except OSError:
            pass
    pid = _read_pid(sdir)
    if pid is not None and _pid_alive(pid):
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(pid, sig)
            except OSError:
                try:
                    os.kill(pid, sig)
                except OSError:
                    break
            deadline = time.monotonic() + (1.5 if sig == signal.SIGTERM else 0.8)
            while time.monotonic() < deadline and _pid_alive(pid):
                time.sleep(0.05)
            if not _pid_alive(pid):
                break
    _unbind_hunt_session(str(state.get("job_id") or ""), sid)
    _force_rmtree(sdir)


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
        "FWGRAPH_EXTRACTED_ROOT": str(_data_dir() / "extracted"),
    })
    _inject_node_ca(env, env_file)
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
        found = _session_finding_ids(sid)
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

    def _state_reader(sid: str):
        sdir = VULNAGENT_HOME / "sessions" / sid
        if not sdir.is_dir():
            return None
        return sdir, _read_state(sdir)

    _manager().start_reaper(_state_reader)

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
        max_turns = int(payload.get("max_turns") or 80)
        if not 1 <= max_turns <= MAX_TURNS_CAP:
            raise HTTPException(status_code=400,
                                detail=f"max_turns must be 1..{MAX_TURNS_CAP}")
        if not (DSH_REPO / "apps" / "cli").is_dir():
            raise HTTPException(
                status_code=503,
                detail="未安装 DeepSeek Harness：请将仓库放到 "
                       f"{DSH_REPO} 或设置 DSH_REPO")
        running = _live_sessions()
        if len(running) >= MAX_PARALLEL:
            raise HTTPException(
                status_code=409,
                detail=f"{len(running)} sessions already running (cap {MAX_PARALLEL}): "
                       + ", ".join(running))
        sid = _new_sid()
        sdir = VULNAGENT_HOME / "sessions" / sid
        sdir.mkdir(parents=True, exist_ok=True)
        state = {
            "session_id": sid,
            "agent_id": "vuln-miner-fwgraph (dsh-web)",
            "environment_id": "fwgraph-dsh-web",
            "task": task, "status": "running", "turns": 1,
            "usage": {}, "findings": [],
            "created_at": _now(), "updated_at": _now(),
            "engine": "dsh-web",
            "mode": mode, "job_id": gate_job,
            "max_turns": max_turns, "owner": principal["username"] or "admin",
            "approval_policy": (
                "ask" if str(payload.get("approval_policy") or "auto") == "ask"
                else "auto"),
        }
        (sdir / "state.json").write_text(json.dumps(state, indent=2),
                                         encoding="utf-8")

        def _boot_and_prompt():
            if (_read_state(sdir) or state).get("status") != "running":
                return
            try:
                dsh_sid = _manager().create_session(sid, sdir, state)
                state["dsh_session_id"] = dsh_sid
                _save_state(sdir, state)
            except _dsh_host.DshHostError as exc:
                state["status"] = "error"
                state["error"] = f"{exc.code}: {exc}"
                _save_state(sdir, state)
                try:
                    _manager().stop(sid, sdir, state, reason="boot-failed",
                                    finalize=False)
                except Exception:
                    pass
                return
            fresh = _read_state(sdir) or state
            if fresh.get("status") != "running":
                try:
                    _manager().stop(sid, sdir, fresh, reason="stop")
                except Exception:
                    pass
                return
            try:
                _manager().rpc(sid, sdir, state, "session.prompt", {
                    "mode": "queue",
                    "content": [{"type": "text", "text": task}],
                })
            except Exception as exc:  # noqa: BLE001
                try:
                    with open(sdir / "runner.log", "a", encoding="utf-8") as fh:
                        fh.write(f"[vulnagent_api] first prompt failed: {exc}\n")
                except OSError:
                    pass

        threading.Thread(target=_boot_and_prompt, daemon=True,
                         name=f"dsh-boot-{sid}").start()
        accounts.audit(principal["username"], "session_start",
                       f"{sid} engine=dsh-web job={gate_job} mode={mode}")
        _bind_hunt_session(gate_job, sid)
        return {"session_id": sid, "status": "running",
                "engine": "dsh-web", "max_turns": max_turns}

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

    @app.post("/vulnagent/sessions/{sid}/rpc/{method}")
    def session_rpc(sid: str, method: str, payload: dict = Body(default=None),
                    principal: dict = Depends(require_token)):
        """harness JSON-RPC 透传（方法白名单见 dsh_host.RPC_ALLOWLIST）。
        前端经此驱动多轮 prompt/queue/steer/cancel/fork/history。"""
        sdir = _session_dir(sid)
        _require_session_access(sdir, principal)
        state = _read_state(sdir)
        if method == "session.prompt":
            if (state.get("status") or "") in ("done", "error"):
                raise HTTPException(status_code=409,
                                    detail="session already finished")
            if (state.get("status") or "") == "awaiting_continue":
                raise HTTPException(
                    status_code=409,
                    detail=_cap_detail(int(state.get("turns") or 0),
                                       int(state.get("max_turns") or 80)))
            state = _charge_turn(sdir, state)
        if method == "session.history":
            mgr = _dsh_manager
            if mgr is None or not mgr.is_live(sid):
                return _history_from_sse(sdir, payload or {})
        try:
            value = _manager().rpc(sid, sdir, state, method, payload or {})
        except _dsh_host.DshHostError as exc:
            status = {"bad-request": 400, "session-not-found": 404}.get(
                exc.code, 502)
            raise HTTPException(
                status_code=status, detail=f"{exc.code}: {exc}") from exc
        # fork 等方法会改 dsh_session_id，落盘保持 resume 能力
        if state.get("dsh_session_id"):
            _save_state(sdir, state)
        return value

    @app.get("/vulnagent/sessions/{sid}/mux")
    async def session_mux(sid: str,
                          principal: dict = Depends(require_token)):
        """harness 事件流（WS→SSE 桥）：session/event、queue 快照、审批帧。"""
        sdir = _session_dir(sid)
        _require_session_access(sdir, principal)
        state = _read_state(sdir)
        running = str(state.get("status") or "") == "running"
        mgr = _dsh_manager
        if not running and (mgr is None or not mgr.is_live(sid)):
            async def _idle():
                yield ": idle\n\n"
            return StreamingResponse(
                _idle(), media_type="text/event-stream",
                headers={"Cache-Control": "no-cache",
                         "X-Accel-Buffering": "no"})
        return StreamingResponse(_manager().mux_sse(sid, sdir, state),
                                 media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache",
                                          "X-Accel-Buffering": "no"})

    @app.post("/vulnagent/sessions/{sid}/respond")
    def session_respond(sid: str, payload: dict = Body(...),
                        principal: dict = Depends(require_token)):
        """审批/提问答复转发（harness /api/respond 宿主级端点）。"""
        sdir = _session_dir(sid)
        _require_session_access(sdir, principal)
        state = _read_state(sdir)
        try:
            return _manager().respond(sid, sdir, state, payload)
        except _dsh_host.DshHostError as exc:
            raise HTTPException(status_code=502,
                                detail=f"{exc.code}: {exc}") from exc

    @app.get("/vulnagent/sessions/{sid}/report")
    def session_report(sid: str, principal: dict = Depends(require_token)):
        sdir = _session_dir(sid)
        _require_session_access(sdir, principal)
        report = sdir / "report.md"
        state = _read_state(sdir) or {}
        try:
            _write_report(sdir, state)
        except Exception:
            pass
        if not report.is_file():
            raise HTTPException(status_code=404, detail="报告尚未生成")
        return PlainTextResponse(report.read_text(encoding="utf-8",
                                                  errors="replace"))

    @app.post("/vulnagent/sessions/{sid}/resume")
    def resume_session(sid: str, payload: dict = Body(default=None),
                       principal: dict = Depends(require_token)):
        """User follow-up after pause/stop. Does not raise max_turns.

        Composer「停止生成」不应走到 /stop；本接口兜底已经误标 done 的会话，
        让聊天框「继续」能拉活。看门狗仍走 session.prompt，对 done 继续 409。
        """
        sdir = _session_dir(sid)
        _require_session_access(sdir, principal)
        state = _read_state(sdir)
        if state.get("archived"):
            raise HTTPException(status_code=409, detail="session archived")
        status = str(state.get("status") or "")
        if status == "awaiting_continue":
            raise HTTPException(
                status_code=409,
                detail=_cap_detail(int(state.get("turns") or 0),
                                   int(state.get("max_turns") or 80)))
        msg = str((payload or {}).get("message") or "").strip()
        if not msg:
            raise HTTPException(status_code=400, detail="message required")
        if status in ("done", "error", "interrupted"):
            state["status"] = "running"
            state["error"] = ""
            _save_state(sdir, state)
            _manager().undiscard(sid)
        elif status != "running":
            raise HTTPException(status_code=409,
                                detail=f"cannot resume status={status}")
        try:
            state = _charge_turn(sdir, state)
            value = _manager().rpc(sid, sdir, state, "session.prompt", {
                "mode": "queue",
                "content": [{"type": "text", "text": msg}],
            })
        except _dsh_host.DshHostError as exc:
            raise HTTPException(status_code=502,
                                detail=f"{exc.code}: {exc}") from exc
        accounts.audit(principal["username"], "session_resume", sid)
        return {"session_id": sid, "status": "running",
                "turns": state.get("turns"),
                "max_turns": state.get("max_turns"),
                "accepted": (value or {}).get("accepted", True)}

    @app.post("/vulnagent/sessions/{sid}/continue")
    def continue_session(sid: str, payload: dict = Body(default=None),
                         principal: dict = Depends(require_token)):
        """User confirmed: raise max_turns and resume hunting."""
        sdir = _session_dir(sid)
        _require_session_access(sdir, principal)
        state = _read_state(sdir)
        extra = int((payload or {}).get("extra_turns") or 80)
        if extra < 1 or extra > 200:
            raise HTTPException(status_code=400,
                                detail="extra_turns must be 1..200")
        turns = int(state.get("turns") or 0)
        state["max_turns"] = turns + extra
        state["status"] = "running"
        state["error"] = ""
        _save_state(sdir, state)
        _manager().undiscard(sid)
        msg = str((payload or {}).get("message") or (
            "【编排】用户同意继续。轮次上限已放宽，请继续挖掘。"
            "不要重复已经入库的漏洞。record_finding 必须 call_chain+poc。"))
        try:
            state = _charge_turn(sdir, state)
            value = _manager().rpc(sid, sdir, state, "session.prompt", {
                "mode": "queue",
                "content": [{"type": "text", "text": msg}],
            })
        except _dsh_host.DshHostError as exc:
            raise HTTPException(status_code=502,
                                detail=f"{exc.code}: {exc}") from exc
        accounts.audit(principal["username"], "session_continue",
                       f"{sid} max_turns={state.get('max_turns')}")
        return {"session_id": sid, "status": "running",
                "turns": state.get("turns"),
                "max_turns": state.get("max_turns"),
                "accepted": (value or {}).get("accepted", True)}

    @app.post("/vulnagent/sessions/{sid}/stop")
    def stop_session(sid: str, principal: dict = Depends(require_token)):
        sdir = _session_dir(sid)
        _require_session_access(sdir, principal)
        state = _read_state(sdir)
        # dsh web host：杀进程 + 收割 findings/报告（finalize）
        if _manager().stop(sid, sdir, state, reason="stop", discard=True):
            accounts.audit(principal["username"], "session_stop", sid)
            return {"session_id": sid, "status": "terminating"}
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
        # still booting: host is not registered yet. Flip status so the
        # background boot thread will not prompt / will tear the host down.
        state = _read_state(sdir) or state
        if state.get("status") == "running":
            state["status"] = "done"
            _save_state(sdir, state)
            accounts.audit(principal["username"], "session_stop",
                           f"{sid} pre-boot")
            return {"session_id": sid, "status": "terminating"}
        raise HTTPException(status_code=409,
                            detail="session not running (or not managed "
                                   "by this service process)")

    @app.patch("/vulnagent/sessions/{sid}")
    def patch_session(sid: str, payload: dict = Body(...),
                      principal: dict = Depends(require_token)):
        """Archive / unarchive a session. Archiving a live hunt also stops it."""
        sdir = _session_dir(sid)
        _require_session_access(sdir, principal)
        if "archived" not in payload:
            raise HTTPException(status_code=400, detail="archived required")
        archived = bool(payload.get("archived"))
        state = _read_state(sdir)
        if archived and _effective_status(sid, state) == "running":
            try:
                _manager().stop(sid, sdir, state, reason="archive")
            except Exception:
                pass
            state = _read_state(sdir) or state
            if state.get("status") == "running":
                state["status"] = "done"
        state["archived"] = archived
        _save_state(sdir, state)
        accounts.audit(principal["username"],
                       "session_archive" if archived else "session_unarchive",
                       sid)
        return _session_summary(sdir)

    @app.post("/vulnagent/sessions/purge-archived")
    def purge_archived(principal: dict = Depends(require_token)):
        """Permanently delete every archived session the caller can access."""
        base = VULNAGENT_HOME / "sessions"
        deleted: list[str] = []
        errors: list[str] = []
        if base.is_dir():
            for d in list(base.iterdir()):
                if not d.is_dir():
                    continue
                state = _read_state(d)
                if not state.get("archived"):
                    continue
                owner = state.get("owner") or "admin"
                if not accounts.can_access(principal, owner):
                    continue
                sid = str(state.get("session_id") or d.name)
                try:
                    _wipe_session(sid, d, state)
                except Exception:
                    errors.append(sid)
                    continue
                if d.exists():
                    errors.append(sid)
                    continue
                deleted.append(sid)
                accounts.audit(principal["username"], "session_delete",
                               f"{sid} purge-archived")
        return {"deleted": deleted, "errors": errors}

    @app.delete("/vulnagent/sessions/{sid}")
    def delete_session(sid: str, principal: dict = Depends(require_token)):
        """Stop a live hunt if needed, then remove the session directory.

        Findings already recorded on the job stay in the task 漏洞报告.
        Discard the host first so a leftover mux cannot spawn it again
        while rmtree is running.
        """
        sdir = _session_dir(sid)
        _require_session_access(sdir, principal)
        state = _read_state(sdir)
        _wipe_session(sid, sdir, state)
        if sdir.exists():
            raise HTTPException(status_code=500,
                                detail="session directory not removed")
        accounts.audit(principal["username"], "session_delete", sid)
        return {"session_id": sid, "status": "deleted"}

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
        sid = str(doc.get("session_id") or "")
        if sid and _SID_RE.match(sid):
            sdir = VULNAGENT_HOME / "sessions" / sid
            st = _read_state(sdir)
            if st:
                found = list(st.get("findings") or [])
                if fid not in found:
                    found.append(fid)
                    st["findings"] = found
                    _save_state(sdir, st)
        accounts.audit(principal["username"], "finding_create",
                       f"{fid} job={doc['job_id']} severity={doc['severity']}")
        _refresh_job_report(doc.get("job_id") or "")
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
