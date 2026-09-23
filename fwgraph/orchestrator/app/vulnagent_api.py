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
        "await_note": state.get("await_note") or "",
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

        # 统计图表（2026-09-23 用户要求：报告要有各种统计图；纯文本
        # 条形图嵌 md，docx/pdf 导出原样保留——不依赖前端渲染）
        def _bar(n, total, width=26):
            filled = round(width * n / total) if total else 0
            return "█" * filled + "·" * (width - filled)

        reach_label = {"verified": "已验证", "observed": "观测到",
                       "static": "静态可达"}
        reach_counts = {}
        for f in findings:
            rk = str(f.get("reachability") or "static").lower()
            reach_counts[rk] = reach_counts.get(rk, 0) + 1
        bin_counts = {}
        for f in findings:
            bn = str(f.get("binary_path") or f.get("binary_md5") or "?")
            bn = bn.rsplit("/", 1)[-1][:20]
            bin_counts[bn] = bin_counts.get(bn, 0) + 1
        top_bins = sorted(bin_counts.items(), key=lambda kv: -kv[1])[:8]
        mx = max(counts.values()) or 1
        lines += ["", "### 危害等级分布", "", "```"]
        for k in ("critical", "high", "medium", "low", "info"):
            if k in counts:
                lines.append(f"  {sev_label[k]:　<3} │{_bar(counts[k], mx)}"
                             f"  {counts[k]}")
        lines += ["```", "", "### 可达性分布", "", "```"]
        rm = max(reach_counts.values()) or 1
        for rk, rv in reach_counts.items():
            lines.append(f"  {reach_label.get(rk, rk):　<4} │{_bar(rv, rm)}"
                         f"  {rv}")
        lines += ["```", "", "### 高频目标二进制 Top8", "", "```"]
        bm = top_bins[0][1] if top_bins else 1
        for bn, bv in top_bins:
            lines.append(f"  {bn:　<20}│{_bar(bv, bm)}  {bv}")
        lines += ["```"]
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
        ts = data.get("ts")  # 原始事件时间：前端历史回放据此显示真实时刻
        if typ == "session_start":
            task = str(data.get("task") or "").strip()
            if task:
                add("user/message",
                    {"content": task, "source": {"kind": "user"}, "ts": ts},
                    seq)
        elif typ in ("thinking", "text"):
            if data.get("stream") is True:
                continue
            text = str(data.get("text") or "")
            if not text:
                continue
            kind = "reasoning" if typ == "thinking" else "text"
            turn = int(seq or len(harness) + 1)
            add("assistant/chunk", {
                "turn": turn, "step": 0, "ts": ts,
                "chunk": {"type": "block-start", "index": 0, "blockType": kind},
            }, seq)
            delta = "reasoning-delta" if kind == "reasoning" else "text-delta"
            add("assistant/chunk", {
                "turn": turn, "step": 0, "ts": ts,
                "chunk": {"type": delta, "index": 0, "text": text},
            }, seq)
            add("assistant/chunk", {
                "turn": turn, "step": 0, "ts": ts,
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
                "ts": ts,
            }, seq)
        elif typ == "tool_result":
            add("tool/result", {
                "callId": data.get("id"),
                "name": data.get("name") or "",
                "ts": ts,
                "message": {
                    "toolCallId": data.get("id"),
                    "content": data.get("preview") or "",
                    "isError": bool(data.get("is_error")),
                },
            }, seq)
        elif typ == "session_end":
            add("turn/end", {"reason": data.get("reason") or "completed",
                             "ts": ts}, seq)
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


def _dsh_deepseek_base(url: str) -> str:
    """dsh llm-deepseek（messages 协议）自行拼 /v1/messages。

    LLM_BASE_URL 按老 builtin 引擎约定带尾部 /v1（它拼 {base}/messages），
    转发给 dsh 前剥掉，避免 /v1/v1/messages 404。
    """
    base = (url or "").rstrip("/")
    return base[:-3] if base.endswith("/v1") else base


def _dsh_env(sid: str, sdir: Path, state: dict) -> dict:
    """web host 模式的 env 组装（与 _spawn_dsh 同源，值从 state 取）。"""
    env_file = _vulnagent_env()
    from orchestrator.app import llm_settings as _llm_settings_mod
    _llm_route = _llm_settings_mod.resolve_route()
    env = dict(os.environ)
    env.update({
        "PATH": str(Path.home() / ".local/bin") + ":" + env.get("PATH", ""),
        "DSH_HOME": DSH_HOME,
        "DEEPSEEK_API_KEY": _llm_route["key"],
        "DEEPSEEK_BASE_URL": _llm_route["base"],
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
    # 顺序衔接（2026-09-23 改为询问制）：AI 已向用户询问过模拟
    # （emulation_offered）时——用户同意（replied 且未 declined）→
    # 自动发起；用户拒绝（declined）→ 不发起；AI 没问过（预算耗尽
    # 等异常收尾）→ 保持自动发起兜底。
    _offered = bool(fresh.get("emulation_offered"))
    _declined = bool(fresh.get("emulation_declined"))
    if (_declined or (_offered and not fresh.get("emulation_replied"))):
        print(f"[vulnagent_api] 跳过自动模拟衔接（offered={_offered} "
              f"declined={_declined} session={sid}）", flush=True)
    elif fresh.get("findings") and fresh.get("job_id"):
        try:
            from orchestrator.app import emulagent_api as _ea
            _fn = _ea._create_request_fn
            if _fn is None:
                print("[vulnagent_api] 自动模拟衔接失败: 请求端点未注册",
                      flush=True)
                return
            _req = _fn(
                {"job_id": fresh["job_id"], "goal": _emulation_goal(fresh),
                 "from_session": sid, "from_agent": "orchestrator"},
                {"username": "orchestrator", "role": "admin"})
            print(f"[vulnagent_api] 挖掘收尾，自动发起固件模拟: "
                  f"{_req.get('req_id')} (session={sid})", flush=True)
        except Exception as exc:  # noqa: BLE001 - 衔接失败不拖垮收尾
            print(f"[vulnagent_api] 自动模拟衔接失败: "
                  f"{type(exc).__name__}: {exc}", flush=True)


def _emulation_goal(state: dict) -> str:
    """自动衔接的模拟目标：概括已入库发现（标题/目标二进制）。"""
    titles = []
    fdir = VULNAGENT_HOME / "findings"
    for fid in (state.get("findings") or [])[:5]:
        try:
            doc = json.loads((fdir / f"{fid}.json").read_text(encoding="utf-8"))
            titles.append(f"{doc.get('title') or fid}"
                          f"（{doc.get('binary_path') or doc.get('binary_md5') or '?'}）")
        except (OSError, ValueError):
            titles.append(str(fid))
    total = len(state.get("findings") or [])
    more = f"（另有 {total - len(titles)} 项见漏洞库）" if total > len(titles) else ""
    return ("围绕本次挖掘已入库的漏洞发现搭建固件模拟环境，完成关键攻击"
            "路径的动态验证：\n" + "\n".join(f"{i+1}) {t}"
            for i, t in enumerate(titles)) + more
            + "\n目标服务与入口以发现记录为准；探活通过后 publish（编排器复探）。")


# ---------------- 挖掘会话自动驾驶（全自动流程） ----------------
# 一次任务输入后全程无人工干预（2026-09-22 决策）：
# - 瞬时错误自动恢复：重试队列注入系统恢复消息（上限 AUTOPILOT_MAX_RETRIES），
#   不可恢复错误（订阅过期/凭据类）保持 error 等待资源处理；
# - 任务批次完成自动收尾：turn completed 且之后无新轮，空闲超过
#   AUTOPILOT_IDLE_DONE 秒即 stop 收尾（finalize → 自动发起固件模拟）。
# 依赖 mux 在线的前置错误捕获（dsh_host._note_turn_error）只是快路径；
# autopilot 轮询会话历史，页面无人观察时同样生效。

AUTOPILOT_POLL = float(os.getenv("VULNAGENT_AUTOPILOT_POLL", "20"))
AUTOPILOT_IDLE_DONE = float(os.getenv("VULNAGENT_AUTOPILOT_IDLE_DONE", "120"))
AUTOPILOT_MAX_RETRIES = int(os.getenv("VULNAGENT_AUTOPILOT_MAX_RETRIES", "3"))
_TRANSIENT_MARKERS = ("malformed_response", "empty_response", "timeout",
                      "timed out", "econnreset", "econnrefused", "socket",
                      "stream ended before", "stream_closed",
                      "500", "502", "503", "bad gateway", "internal server",
                      # 2026-09-23：网关瞬断（transport failed 实测 turn
                      # error 后被误判永久、会话直接死在第 1 轮）。
                      # 注意不含 auth error——无效 key 重试无意义。
                      "transport failed", "transport error", "connection",
                      "network error", "fetch failed", "aborted")
_autopilot_threads: dict = {}
_autopilot_lock = threading.Lock()


def _error_is_transient(text: str) -> bool:
    t = str(text or "").lower()
    return any(m in t for m in _TRANSIENT_MARKERS)


def _ensure_autopilot(sid: str) -> None:
    with _autopilot_lock:
        th = _autopilot_threads.get(sid)
        if th is not None and th.is_alive():
            return
        th = threading.Thread(target=_autopilot, args=(sid,), daemon=True,
                              name=f"autopilot-{sid}")
        _autopilot_threads[sid] = th
        th.start()

def _journal_tail(sdir) -> list:
    """直读 dsh 会话 journal（zstd 全量解压，会话级体量小）。

    autopilot 用它做完成/错误检测：零 RPC、零 host 依赖——host 已死或
    ensure 重拉窗口里也能判定（2026-09-22 实测：RPC 路径在 host 死后会
    长时间挂起，导致 turn completed 迟迟无人收尾）。
    """
    import glob as _glob
    import subprocess as _sp
    _root = str(Path.home() / ".dsh" / "sessions")
    _files = _glob.glob(_root + "/*" + sdir.name
                        + "*/session-*/session.v3.jsonl.zstd")
    # 多个 session 目录（历史竞态/隔离产物）时取 mtime 最新的
    for z in sorted(_files, key=os.path.getmtime, reverse=True):
        try:
            out = _sp.run(["zstdcat", z], capture_output=True, text=True,
                          timeout=30).stdout or ""
        except Exception:  # noqa: BLE001
            continue
        evs = []
        for ln in out.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                evs.append(json.loads(ln))
            except ValueError:
                continue  # 单行坏数据不弃整个文件
        return evs
    return []


def _autopilot(sid: str) -> None:
    sdir = VULNAGENT_HOME / "sessions" / sid
    retries = 0
    rpc_failures = 0
    while True:
        time.sleep(AUTOPILOT_POLL)
        try:
            state = _read_state(sdir)
            if not state or state.get("status") != "running":
                return  # 已收尾/出错/等待确认（continue 会重新拉起 autopilot）
            events = _journal_tail(sdir)
            turn_end = next((ev for ev in reversed(events)
                             if ev.get("type") == "turn/end"), None)
            if turn_end is None:
                continue  # 首轮进行中或历史为空
            reason = (turn_end.get("data") or {}).get("reason") or {}
            err_msg = str((reason.get("error") or {}).get("message") or "")
            if reason.get("kind") == "error":
                # 引擎自愈让路：turn error 之后 journal 仍有新活动（llm/retry
                # 或新 turn）说明引擎在自行恢复，autopilot 不介入（2026-09-22
                # 实测：STREAM_CLOSED 后引擎 llm/retry 进行中被抢先置 error）。
                _ets = turn_end.get("time") or 0
                _recent = [e for e in events
                           if (e.get("time") or 0) > _ets
                           and e.get("type") in ("llm/retry", "turn/start",
                                                 "assistant/message")]
                if _recent and time.time() * 1000 - max(
                        e.get("time") or 0 for e in _recent) < 120_000:
                    continue
                if retries >= AUTOPILOT_MAX_RETRIES or not _error_is_transient(err_msg):
                    if state.get("status") == "running":
                        state["status"] = "error"
                        state["error"] = f"turn error: {err_msg[:300]}"
                        _save_state(sdir, state)
                    return
                retries += 1
                try:
                    _manager().rpc(sid, sdir, state, "session.prompt", {
                        "mode": "queue",
                        "content": [{"type": "text", "text":
                                     "【编排】上一轮因引擎瞬时错误中断（"
                                     + err_msg[:120]
                                     + "）。运行环境已自动恢复，请从中断处继续"
                                       "当前任务，不要重复已完成的分析。"}]})
                except Exception:  # noqa: BLE001 - 注入失败下轮再试
                    pass
                time.sleep(AUTOPILOT_POLL)
                continue
            if reason.get("kind") in ("completed", "interrupted"):
                ts = turn_end.get("time") or 0
                idle_s = (time.time() * 1000 - ts) / 1000 if ts else 0
                # 只认真正的新 turn；host 已死时队列消息永远不会被消费
                has_newer = any(isinstance(ev, dict)
                                and ev.get("type") == "turn/start"
                                and (ev.get("time") or 0) > ts for ev in events)
                host_alive = False
                try:
                    _pid = int((sdir / "runner.pid").read_text().strip())
                    open(f"/proc/{_pid}/cmdline").read()
                    host_alive = True
                except (OSError, ValueError):
                    pass
                # 已询问模拟的会话：turn 结束后 5s 即转等待（用户实测卡片
                # 迟到数分钟体验差）；普通收尾仍用 120s 空闲阈值。
                _idle_gate = 5 if (state.get("emulation_offered")
                                   and not state.get("emulation_replied")
                                   ) else AUTOPILOT_IDLE_DONE
                if idle_s > _idle_gate and (not has_newer
                                            or not host_alive):
                    if (state.get("emulation_offered")
                            and not state.get("emulation_replied")):
                        # 已向用户询问模拟、尚未答复：转 awaiting_continue
                        # 等待（不收尾；continue 会拉起新 turn 与 autopilot）。
                        state["status"] = "awaiting_continue"
                        state["await_note"] = ("挖掘完成，等待用户确认是否"
                                               "进行固件模拟真实测试")
                        _save_state(sdir, state)
                        try:
                            with open(sdir / "events.sse", "a",
                                      encoding="utf-8") as fh:
                                fh.write("event: session_state\ndata: "
                                         + json.dumps({
                                             "status": "awaiting_continue",
                                             "note": state["await_note"],
                                             "ts": _now()}) + "\n\n")
                        except OSError:
                            pass
                        return
                    try:
                        if not _manager().stop(sid, sdir, state,
                                               reason="auto-complete"):
                            # host 已死且未注册：stop 返回 False 不走 finalize
                            _dsh_finalize(sid, sdir, state, "auto-complete")
                    except Exception:  # noqa: BLE001
                        try:
                            _dsh_finalize(sid, sdir, state, "auto-complete")
                        except Exception:  # noqa: BLE001
                            pass
                    return
        except Exception as exc:  # noqa: BLE001 - 单轮异常绝不杀线程
            # 2026-09-23 实测：未捕获异常令线程静默死亡，offered 会话
            # 停摆 running、终局卡片消失（NOPILOT 告警 7 分钟无人接管）。
            try:
                with open(sdir / "runner.log", "a", encoding="utf-8") as fh:
                    fh.write(f"[autopilot] tick failed: {type(exc).__name__}: {exc}\n")
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
    from orchestrator.app import llm_settings as _llm_settings_mod
    _llm_route = _llm_settings_mod.resolve_route()
    env = dict(os.environ)
    env.update({
        "PATH": str(Path.home() / ".local/bin") + ":" + env.get("PATH", ""),
        "DSH_HOME": DSH_HOME,
        "DEEPSEEK_API_KEY": _llm_route["key"],
        "DEEPSEEK_BASE_URL": _llm_route["base"],
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
        # 交互纪律直接前置进任务首条消息（2026-09-23：dsh skill 机制只把
        # description 放进清单、内容靠模型按需加载——实测两轮会话模型
        # 从不加载，语言与汇报规则全部失效输出英文+全程静默。规则必须
        # 保证进上下文，不赌 skill 触发）。
        prompt_task = (
            "【交互纪律（必须遵守）】\n"
            "1. 对用户只说简体中文——包括所有中间过程消息，"
            "一条英文都不许出现。\n"
            "2. 每完成一组工具调用（最多两个），必须先用一两句中文向用户"
            "交代：刚才做了什么、结果是什么、接下来验证什么。长时间连续"
            "调用工具而一句话不说是违规。\n"
            "3. 静态判定的最后一公里用 fw_read_bytes 直读 .data 决定性"
            "字节；未进代码图的二进制用 fw_decompile_single 单独反编译。\n"
            "4. 禁止输出『建议的下一步』——所有下一步自己执行完。全部"
            "闭环后调用一次 fw_offer_emulation，然后**立刻输出最终中文"
            "总结并停止**——不要再调用任何工具、不要开始新的分析；总结"
            "末尾只需说明：模拟与否请在界面卡片选择。收尾（模拟询问由"
            "卡片呈现，不要写在报告正文里）。\n\n"
        ) + task
        if len(payload.get("task") or "") > 4000:
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
                    "content": [{"type": "text", "text": prompt_task}],
                })
            except Exception as exc:  # noqa: BLE001
                try:
                    with open(sdir / "runner.log", "a", encoding="utf-8") as fh:
                        fh.write(f"[vulnagent_api] first prompt failed: {exc}\n")
                except OSError:
                    pass
    # 编排器重启后 running 会话的自动驾驶线程随进程丢失——启动时恢复，
    # 否则完成/错误无人接管（2026-09-22 实测：重启后 turn completed 停滞
    # 9 分钟无人收尾）。
    def _startup_scan() -> None:
        try:
            for sd in (VULNAGENT_HOME / "sessions").iterdir():
                if sd.is_dir():
                    st = _read_state(sd)
                    if st and st.get("status") == "running":
                        _ensure_autopilot(str(st.get("session_id") or sd.name))
        except Exception:  # noqa: BLE001 - 恢复失败不阻塞启动
            pass

    _startup_scan()

    # 看门狗（2026-09-23）：autopilot 线程因未捕获异常静默死亡后，无人
    # 接管 running 会话（NOPILOT 告警 7 分钟实测）。线程内已有 try 兜底
    # 兜死亡，这里再加进程内周期自愈：60s 扫一次 running 会话补拉。
    def _autopilot_watchdog() -> None:
        while True:
            time.sleep(60)
            _startup_scan()

    threading.Thread(target=_autopilot_watchdog, daemon=True,
                     name="autopilot-watchdog").start()

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

    @app.get("/vulnagent/sessions/{sid}/export")
    def session_export(sid: str, principal: dict = Depends(require_token)):
        """会话完整导出（ZIP）——对齐 dsh 官方 session-log-export 的
        用户能力：报告 + journal jsonl + state + findings 全打包下载
        （2026-09-23 用户需求，从 harness 扒到工作台）。"""
        import io
        import subprocess as _sp
        import zipfile as _zf
        sdir = _session_dir(sid)
        _require_session_access(sdir, principal)
        state = _read_state(sdir) or {}
        buf = io.BytesIO()
        with _zf.ZipFile(buf, "w", _zf.ZIP_DEFLATED, compresslevel=6) as zf:
            zf.writestr(f"{sid}/state.json",
                        json.dumps(state, indent=2, ensure_ascii=False))
            rp = sdir / "report.md"
            if rp.is_file():
                zf.writestr(f"{sid}/report.md",
                            rp.read_text(encoding="utf-8",
                                         errors="replace"))
            for fid in state.get("findings") or []:
                fp = VULNAGENT_HOME / "findings" / f"{fid}.json"
                if fp.is_file():
                    try:
                        zf.writestr(f"{sid}/findings/{fid}.json",
                                    fp.read_text(encoding="utf-8"))
                    except OSError:
                        pass
            evs = sdir / "events.sse"
            if evs.is_file():
                zf.writestr(f"{sid}/events.sse",
                            evs.read_text(encoding="utf-8",
                                          errors="replace"))
            for zst in sorted((Path.home() / ".dsh" / "sessions").glob(
                    f"*{sid}*/session-*/session.v3.jsonl.zstd")):
                try:
                    out = _sp.run(["zstdcat", str(zst)],
                                  capture_output=True, text=True,
                                  timeout=60).stdout
                    if out:
                        zf.writestr(f"{sid}/session.jsonl", out)
                        break
                except Exception:  # noqa: BLE001
                    continue
        buf.seek(0)
        from fastapi.responses import StreamingResponse
        return StreamingResponse(
            buf, media_type="application/zip",
            headers={"Content-Disposition":
                     f"attachment; filename={sid}-session-log.zip"})

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
        user_text = str((payload or {}).get("message") or "").strip()
        if state.get("emulation_offered"):
            # 模拟询问后的用户答复：登记已答复；用户同意的标志是
            # findings 仍在且未 decline——收尾时 _dsh_finalize 自动发起。
            state["emulation_replied"] = True
            _save_state(sdir, state)
            low = user_text.lower()
            neg = any(k in user_text for k in ("不用", "不需要", "不要",
                                               "先不", "否", "跳过", "算了"))
            declined = neg or low.startswith(("no", "skip"))
            if declined:
                state["emulation_declined"] = True
                _save_state(sdir, state)
            msg = ("【编排】用户对固件模拟询问的答复："
                   + (user_text or "（同意）")
                   + ("。用户不同意模拟：用中文简要收尾本次任务即可，"
                      "不要发起模拟。" if declined else
                      "。用户已答复，请按答复处理：如为同意，输出最终"
                      "总结后结束本轮（编排会自动发起固件模拟）；如答复"
                      "内容另有要求，先完成再收尾。"))
        else:
            msg = user_text or (
                "【编排】用户同意继续。轮次上限已放宽，请继续挖掘。"
                "不要重复已经入库的漏洞。record_finding 必须 call_chain+poc。")
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
        _ensure_autopilot(sid)
        return {"session_id": sid, "status": "running",
                "turns": state.get("turns"),
                "max_turns": state.get("max_turns"),
                "accepted": (value or {}).get("accepted", True)}

    @app.post("/vulnagent/sessions/{sid}/emulation-offer")
    def emulation_offer(sid: str, payload: dict = Body(default=None),
                        principal: dict = Depends(require_token)):
        """挖掘 agent 终局询问前的登记（fw_offer_emulation 透传）。

        2026-09-23 决策：固件模拟改为完成后询问用户。AI 把静态+动态
        验证全部闭环后调用本端点，随后向用户输出中文询问；turn 结束
        后 autopilot 据此转入 awaiting_continue 等用户答复，而不是
        自动收尾。用户在 continue 消息里答复即可。"""
        sdir = _session_dir(sid)
        _require_session_access(sdir, principal)
        state = _read_state(sdir)
        state["emulation_offered"] = True
        state["emulation_declined"] = False
        _save_state(sdir, state)
        return {
            "session_id": sid, "emulation_offered": True,
            "instruction": "现在用中文向用户完整汇报本次挖掘结论"
            "（发现清单、PoC、验证结果）。汇报里不要写模拟询问句——"
            "选择卡片会自动出现在界面上；只在结尾加一句『是否进行"
            "固件模拟真实测试，请在下方卡片选择』。然后结束本轮输出。"
            "不要自行调用 fw_emul_request——用户在卡片上选择发起后"
            "编排会自动发起模拟。",
        }

    @app.post("/vulnagent/sessions/{sid}/emulation-decline")
    def emulation_decline(sid: str, payload: dict = Body(default=None),
                          principal: dict = Depends(require_token)):
        """用户答复不做模拟：收尾时不再自动发起模拟请求。"""
        sdir = _session_dir(sid)
        _require_session_access(sdir, principal)
        state = _read_state(sdir)
        state["emulation_declined"] = True
        _save_state(sdir, state)
        return {"session_id": sid, "emulation_declined": True}

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
            _st_now = _read_state(sdir) or state or {}
            if _st_now.get("status") in ("awaiting_continue",
                                         "awaiting_user_confirm"):
                # 暂停态会话杀完 host 无人收尾，直接 finalize
                try:
                    _dsh_finalize(sid, sdir, _st_now, "stop")
                except Exception:  # noqa: BLE001
                    pass
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
        # awaiting_continue（轮次上限/模拟询问暂停）时 host 未注册在当前
        # 服务进程（如服务重启过）：直接 finalize 收尾，而不是 409
        # （2026-09-23 用户实测"结束本轮"报错）。
        if state.get("status") in ("awaiting_continue",
                                   "awaiting_user_confirm"):
            try:
                _dsh_finalize(sid, sdir, state, "stop")
            except Exception:  # noqa: BLE001 - finalize 失败仍返回终止
                pass
            accounts.audit(principal["username"], "session_stop",
                           f"{sid} awaiting")
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
