#!/usr/bin/env python3
"""Watch a vulnagent hunt: auto-approve dynamic tools, snapshot every 60s.

Exit codes for --once:
  0 still running, 10 stuck, 11 done/error, 12 no-dynamic (stalled without
  fw_request_trace/fuzz after enough tools).
Long-running mode prints only STUCK / DONE / FAILED / NODYN to stdout.
"""
from __future__ import annotations

import json
import os
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

CTX = ssl._create_unverified_context()
HOME = Path(os.environ.get("VULNAGENT_HOME", Path.home() / "firmware-graph" / "vulnagent"))
SNAP = Path(os.environ.get("HUNT_WATCH_SNAP", "/tmp/hunt-watch.json"))
LOG = Path(os.environ.get("HUNT_WATCH_LOG", "/tmp/hunt-watch.log"))
BASE = os.environ.get("FWGRAPH_BASE_URL", "http://127.0.0.1:8000")
def _load_token() -> str:
    tok = os.environ.get("ORCH_TOKEN") or os.environ.get("FWGRAPH_TOKEN") or ""
    if tok:
        return tok
    envp = Path.home() / "firmware-graph" / "fwgraph" / ".env"
    if envp.is_file():
        for line in envp.read_text(encoding="utf-8").splitlines():
            if line.startswith("ORCH_TOKEN="):
                return line.split("=", 1)[1].strip().strip('"')
    return ""


TOKEN = _load_token()
STALL_SEC = int(os.environ.get("HUNT_STALL_SEC", "50"))
WRAP_SEC = int(os.environ.get("HUNT_WRAP_SEC", "25"))
MIN_TOOLS_FOR_DYN = int(os.environ.get("HUNT_MIN_TOOLS_FOR_DYN", "25"))
_WRAP_MARKERS = (
    "本轮状态", "本轮完成", "明确待办", "本轮进展", "环境性阻断", "剩余未扫尽",
    "后续挖掘就绪", "需要新增可调用能力",
)


def _log(msg: str) -> None:
    prev = LOG.read_text(encoding="utf-8") if LOG.is_file() else ""
    LOG.write_text(prev + msg.rstrip() + "\n", encoding="utf-8")


def _req(method: str, path: str, body=None, timeout=20, retries=3):
    data = None
    headers = {"Authorization": f"Bearer {TOKEN}"}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    last = None
    for attempt in range(max(1, retries)):
        try:
            with urllib.request.urlopen(req, context=CTX, timeout=timeout) as resp:
                raw = resp.read()
                if not raw:
                    return None
                try:
                    return json.loads(raw)
                except json.JSONDecodeError:
                    return raw.decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            if exc.code in (400, 401, 403, 404, 409, 422):
                raise
            last = exc
            time.sleep(1.2 * (attempt + 1))
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = exc
            time.sleep(1.2 * (attempt + 1))
    raise last


def parse_events(sid: str) -> dict:
    p = HOME / "sessions" / sid / "events.sse"
    out = {
        "n": 0, "tools": Counter(), "dyn": [], "errors": [],
        "last_ts": None, "last_ev": None, "texts": 0, "thinking": 0,
        "last_text": "", "last_tool": None,
    }
    if not p.is_file():
        return out
    cur = None
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("event:"):
            cur = line[6:].strip()
            continue
        if not (line.startswith("data:") and cur):
            continue
        try:
            d = json.loads(line[5:].strip())
        except json.JSONDecodeError:
            d = {}
        out["n"] += 1
        # session_start after host respawn is not agent work — don't reset idle.
        if cur != "session_start":
            out["last_ts"] = d.get("ts") or out["last_ts"]
        out["last_ev"] = cur
        if cur == "tool_call":
            name = d.get("name") or "?"
            out["tools"][name] += 1
            out["last_tool"] = name
            if str(name).startswith("fw_request_"):
                out["dyn"].append({"name": name, "input": d.get("input"), "ts": d.get("ts")})
        elif cur == "tool_result" and d.get("is_error"):
            out["errors"].append({
                "name": d.get("name"), "preview": str(d.get("preview") or "")[:240],
                "ts": d.get("ts"),
            })
        elif cur == "text":
            out["texts"] += 1
            out["last_text"] = str(d.get("text") or d.get("content") or "")
        elif cur == "thinking":
            out["thinking"] += 1
        cur = None
    return out


def age_seconds(ts: str | None) -> float | None:
    if not ts:
        return None
    # 2026-08-22T15:26:22.215Z
    try:
        from datetime import datetime, timezone
        t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - t).total_seconds()
    except Exception:
        return None


def snapshot(sid: str) -> dict:
    try:
        sess = _req("GET", f"/vulnagent/sessions/{sid}") or {}
    except Exception as exc:
        _log(f"snap-sess {exc}")
        sess = {}
    ev = parse_events(sid)
    traces, fuzz = {}, {}
    job_id = sess.get("job_id")
    if job_id:
        try:
            traces = _req("GET", f"/jobs/{job_id}/traces?limit=8", timeout=8, retries=1) or {}
        except Exception as exc:
            _log(f"snap-traces {exc}")
        try:
            fuzz = _req("GET", f"/jobs/{job_id}/fuzz", timeout=8, retries=1) or {}
        except Exception as exc:
            _log(f"snap-fuzz {exc}")
    findings = sess.get("findings") or []
    age = age_seconds(ev["last_ts"])
    tools_n = sum(ev["tools"].values())
    dyn_names = [x["name"] for x in ev["dyn"]]
    status = sess.get("status") or "unknown"
    wrap_up = any(m in (ev.get("last_text") or "") for m in _WRAP_MARKERS)
    in_flight = ev.get("last_ev") == "tool_call" or ev.get("last_tool") in (
        "fw_get_trace", "fw_get_fuzz_run", "fw_get_qemu_exec",
        "fw_request_trace", "fw_request_fuzz", "fw_request_frida", "fw_qemu_exec",
    )
    polling = in_flight or "轮询" in (ev.get("last_text") or "")
    # A live trace/fuzz start can stay quiet for several minutes (TRACE_LOCK).
    if polling and age is not None and age < 600:
        stuck = False
    else:
        stuck = (
            status == "running"
            and age is not None
            and (age > STALL_SEC or (wrap_up and age > WRAP_SEC))
        )
    no_dyn = (
        status == "running"
        and tools_n >= MIN_TOOLS_FOR_DYN
        and not dyn_names
        and age is not None
        and age > 60
    )
    snap = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sid": sid,
        "status": status,
        "approval_policy": sess.get("approval_policy"),
        "dsh_session_id": sess.get("dsh_session_id"),
        "events": ev["n"],
        "last_ev": ev["last_ev"],
        "last_ts": ev["last_ts"],
        "idle_sec": round(age, 1) if age is not None else None,
        "tools": dict(ev["tools"]),
        "tools_n": tools_n,
        "dyn_calls": ev["dyn"][-8:],
        "errors": ev["errors"][-8:],
        "texts": ev["texts"],
        "thinking": ev["thinking"],
        "traces_total": (traces or {}).get("total"),
        "fuzz_runs": len((fuzz or {}).get("runs") or []),
        "findings": findings,
        "stuck": stuck,
        "no_dynamic": no_dyn,
        "error": sess.get("error") or "",
        "turns": int(sess.get("turns") or 0),
        "max_turns": int(sess.get("max_turns") or 80),
    }
    SNAP.write_text(json.dumps(snap, ensure_ascii=False, indent=2), encoding="utf-8")
    return snap


def auto_approve_loop(sid: str, stop: threading.Event):
    """Stay on mux and answer approval/requested so fuzz/trace can run."""
    while not stop.is_set():
        try:
            req = urllib.request.Request(
                BASE + f"/vulnagent/sessions/{sid}/mux",
                headers={"Authorization": f"Bearer {TOKEN}", "Accept": "text/event-stream"},
            )
            with urllib.request.urlopen(req, context=CTX, timeout=120) as resp:
                buf = ""
                while not stop.is_set():
                    chunk = resp.read(256)
                    if not chunk:
                        break
                    buf += chunk.decode("utf-8", "replace")
                    while "\n\n" in buf:
                        block, buf = buf.split("\n\n", 1)
                        data_lines = []
                        for line in block.split("\n"):
                            if line.startswith("data:"):
                                data_lines.append(line[5:].lstrip())
                        if not data_lines:
                            continue
                        raw = "\n".join(data_lines)
                        try:
                            frame = json.loads(raw)
                        except json.JSONDecodeError:
                            continue
                        method = frame.get("method") or (frame.get("payload") or {}).get("type")
                        payload = frame.get("payload") if isinstance(frame.get("payload"), dict) else frame
                        rpc_id = frame.get("rpcId")
                        if method == "approval/requested" and rpc_id:
                            try:
                                rec = _req("POST", f"/vulnagent/sessions/{sid}/respond", {
                                    "type": "client-response",
                                    "rpcId": rpc_id,
                                    "result": {
                                        "ok": True,
                                        "value": {
                                            "sessionId": payload.get("sessionId"),
                                            "approvalId": payload.get("approvalId"),
                                            "outcome": "allowed-once",
                                        },
                                    },
                                })
                                LOG.write_text(
                                    (LOG.read_text() if LOG.is_file() else "")
                                    + f"approved {payload.get('toolName')} {rec}\n",
                                    encoding="utf-8")
                            except Exception as exc:
                                LOG.write_text(
                                    (LOG.read_text() if LOG.is_file() else "")
                                    + f"approve-fail {exc}\n",
                                    encoding="utf-8")
        except Exception as exc:
            if stop.is_set():
                return
            LOG.write_text(
                (LOG.read_text() if LOG.is_file() else "") + f"mux {exc}\n",
                encoding="utf-8")
            time.sleep(2)


NUDGE = (
    "【编排】不要停，不要等预算重置。日配额 384，会话 192。"
    "空差分不是结束：解析器改 via=stdin 或 input_path=/tmp/x，不要只打端口。"
    "换入口 httpd/minidlna/athadhoc/uclited。"
    "fw_qemu_exec 仅 signal 11/6 算崩溃。record_finding 必须 call_chain+poc。"
)


def finish_session(sid: str, reason: str) -> None:
    try:
        rec = _req("POST", f"/vulnagent/sessions/{sid}/stop", {})
        _log(f"finish {reason} {rec}")
    except Exception as exc:
        _log(f"finish-fail {reason} {exc}")


def unstick(sid: str) -> None:
    """Cancel a finished-but-idle turn and queue a hidden continue prompt."""
    try:
        _req("POST", f"/vulnagent/sessions/{sid}/rpc/session.cancel", {})
    except Exception as exc:
        LOG.write_text((LOG.read_text() if LOG.is_file() else "")
                       + f"unstick-cancel {exc}\n", encoding="utf-8")
    time.sleep(1.5)
    try:
        rec = _req("POST", f"/vulnagent/sessions/{sid}/rpc/session.prompt", {
            "mode": "queue",
            "content": [{"type": "text", "text": NUDGE}],
        })
        LOG.write_text((LOG.read_text() if LOG.is_file() else "")
                       + f"unstick-prompt {rec}\n", encoding="utf-8")
    except urllib.error.HTTPError as exc:
        raw = ""
        try:
            raw = exc.read().decode("utf-8", "replace")[:400]
        except Exception:
            raw = str(exc)
        _log(f"unstick-prompt-fail {exc} {raw}")
        if exc.code == 409 and "max_turns" in raw:
            _log("awaiting_continue max_turns")
    except Exception as exc:
        LOG.write_text((LOG.read_text() if LOG.is_file() else "")
                       + f"unstick-prompt-fail {exc}\n", encoding="utf-8")


def classify(snap: dict) -> int:
    if snap["status"] in ("done", "error", "interrupted"):
        return 11
    if snap["stuck"]:
        return 10
    if snap["no_dynamic"]:
        return 12
    return 0


def main():
    if not TOKEN:
        print("FAILED missing ORCH_TOKEN", flush=True)
        return 1
    args = sys.argv[1:]
    once = "--once" in args
    sid = None
    for i, a in enumerate(args):
        if a == "--sid" and i + 1 < len(args):
            sid = args[i + 1]
    sid = sid or os.environ.get("HUNT_SID")
    if not sid:
        print("FAILED missing sid", flush=True)
        return 1
    if once:
        snap = snapshot(sid)
        code = classify(snap)
        if snap["status"] == "awaiting_continue":
            print("WAIT", flush=True)
            return 0
        if code == 10:
            print("STUCK", flush=True)
        elif code == 11:
            print("DONE" if snap["status"] == "done" else "FAILED", flush=True)
        elif code == 12:
            print("NODYN", flush=True)
        return code

    stop = threading.Event()
    t = threading.Thread(target=auto_approve_loop, args=(sid, stop), daemon=True)
    t.start()
    last_nudge = 0.0
    try:
        while True:
            try:
                snap = snapshot(sid)
                code = classify(snap)
                if snap["status"] == "awaiting_continue":
                    now = time.time()
                    if now - last_nudge > 90:
                        print("WAIT", flush=True)
                        last_nudge = now
                elif code == 10:
                    now = time.time()
                    if now - last_nudge > 50:
                        unstick(sid)
                        last_nudge = now
                        # wrap-up idle (~50–80s) is expected; only surface a
                        # long stall that unstick did not recover
                        if (snap.get("idle_sec") or 0) >= 300:
                            print("STUCK", flush=True)
                    elif (snap.get("idle_sec") or 0) >= 300:
                        print("STUCK", flush=True)
                elif code == 11:
                    print("DONE" if snap["status"] == "done" else "FAILED", flush=True)
                    return 0 if snap["status"] == "done" else 1
                elif code == 12:
                    print("NODYN", flush=True)
            except Exception as exc:
                _log(f"watch-loop {exc}")
            time.sleep(60)
    finally:
        stop.set()


if __name__ == "__main__":
    raise SystemExit(main() or 0)
