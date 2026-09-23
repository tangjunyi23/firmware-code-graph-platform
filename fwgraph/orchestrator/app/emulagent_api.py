"""固件模拟 agent（fwgraph-emul）的编排端点。

三组路由：
- /emulagent/sessions*   模拟 agent 的 dsh web 会话（复用 DshHostManager，
                         profile=fwgraph-emul-web / preset=fwgraph-emul，
                         与漏洞挖掘的 /vulnagent 物理隔离：目录、并发配额、
                         工具面互不相通）
- /emul/envs*            模拟环境（进程簇）的生命周期：build/boot/probe/
                         patch/reset/stop/publish/send。publish 是真实性闸门：
                         编排器亲自复探，AI 说了不算。
- /emul/requests*        挖掘 agent → 模拟 agent 的跨 agent 请求总线。
                         挖掘 agent 在静态+组件 fuzz 结论成型后调
                         fw_emul_request 发起；编排器把结构化目标投递给
                         （新建或已在跑的）模拟会话，环境就绪后请求置 ready。
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Body
from fastapi.responses import StreamingResponse

from orchestrator.app import accounts
from orchestrator.app import dsh_host as _dsh_host
from orchestrator.app import vulnagent_api

from pipeline.emul import runner as emul_runner
from pipeline.emul import janitor as emul_janitor
from pipeline.emul import store as emul_store

FWGRAPH_ROOT = vulnagent_api.FWGRAPH_ROOT
NODE_BIN = vulnagent_api.NODE_BIN
DSH_REPO = vulnagent_api.DSH_REPO
VULNAGENT_HOME = vulnagent_api.VULNAGENT_HOME
EMUL_SESSIONS_HOME = VULNAGENT_HOME / "emul-sessions"
EMUL_PROFILE_WEB = os.getenv("EMUL_PROFILE_WEB", "fwgraph-emul-web")
EMUL_PRESET = os.getenv("EMUL_AGENT_PRESET", "fwgraph-emul")
EMUL_MAX_PARALLEL = int(os.getenv("EMUL_MAX_PARALLEL", "2"))
EMUL_MAX_TURNS = int(os.getenv("EMUL_MAX_TURNS", "120"))

_SID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _data_dir() -> Path:
    return vulnagent_api._data_dir()


# ---------------- 会话状态 ----------------

def _sdir(sid: str) -> Path:
    if not _SID_RE.match(str(sid or "")):
        raise HTTPException(status_code=404, detail="session not found")
    d = EMUL_SESSIONS_HOME / sid
    if not d.is_dir():
        raise HTTPException(status_code=404, detail="session not found")
    return d


def _read_state(sdir: Path) -> dict:
    try:
        return json.loads((sdir / "state.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_state(sdir: Path, state: dict) -> None:
    state["updated_at"] = _now()
    sdir.mkdir(parents=True, exist_ok=True)
    (sdir / "state.json").write_text(json.dumps(state, indent=2),
                                     encoding="utf-8")


def _live_sessions() -> list:
    out = []
    if not EMUL_SESSIONS_HOME.is_dir():
        return out
    for d in EMUL_SESSIONS_HOME.iterdir():
        if not d.is_dir():
            continue
        st = _read_state(d)
        if st.get("status") == "running":
            out.append(d.name)
    return out


def _pid_alive(sdir: Path) -> bool:
    """runner.pid 指向的宿主进程是否还活着（编排器重启/进程崩溃后为假）。"""
    try:
        pid = int((sdir / "runner.pid").read_text().strip())
    except (OSError, ValueError):
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _host_alive(sid: str, sdir: Path) -> bool:
    mgr = _manager_cache
    if mgr is not None and mgr.is_live(sid):
        return True
    return _pid_alive(sdir)


def _summary(d: Path) -> dict:
    st = _read_state(d)
    return {
        "session_id": d.name,
        "task": st.get("task", ""),
        "status": st.get("status", "unknown"),
        "job_id": st.get("job_id", ""),
        "engine": st.get("engine", "dsh-web"),
        "turns": st.get("turns", 0),
        "max_turns": st.get("max_turns", EMUL_MAX_TURNS),
        "owner": st.get("owner", "admin"),
        "created_at": st.get("created_at", ""),
        "updated_at": st.get("updated_at", ""),
        # running 但宿主已死 = 失联（观察台据此提示并可停止，不占并发额度迷惑人）
        "host_alive": _host_alive(d.name, d)
        if st.get("status") == "running" else True,
    }


def _require_access(sdir: Path, principal: dict) -> None:
    st = _read_state(sdir)
    owner = st.get("owner") or "admin"
    if not accounts.can_access(principal, owner):
        raise HTTPException(status_code=403, detail="not your session")


# ---------------- dsh 引擎环境 ----------------

def _emul_env(sid: str, sdir: Path, state: dict) -> dict:
    """模拟会话的 dsh host 环境注入（在挖掘 _dsh_env 基础上加 EMUL 标记）。"""
    env_file = vulnagent_api._vulnagent_env()
    from orchestrator.app import llm_settings as _llm_settings_mod
    _llm_route = _llm_settings_mod.resolve_route()
    env = dict(os.environ)
    env.update({
        "PATH": str(Path.home() / ".local/bin") + ":" + env.get("PATH", ""),
        "DSH_HOME": vulnagent_api.DSH_HOME,
        "DEEPSEEK_API_KEY": _llm_route["key"],
        "DEEPSEEK_BASE_URL": _llm_route["base"],
        "FWGRAPH_BASE_URL": env_file.get("FWGRAPH_BASE_URL", ""),
        "FWGRAPH_TOKEN": env_file.get("FWGRAPH_TOKEN", ""),
        "FWGRAPH_JOB_ID": state.get("job_id")
                          or env_file.get("FWGRAPH_JOB_ID", ""),
        "FWGRAPH_SESSION_ID": sid,
        "FWGRAPH_EVENTS_FILE": str(sdir / "events.sse"),
        "FWGRAPH_TASK": state.get("task", ""),
        "FWGRAPH_EMUL": "1",
        "DSH_TOOLS_MODE": "native",
    })
    vulnagent_api._inject_node_ca(env, env_file)
    return env


def _write_report(sdir: Path, state: dict) -> None:
    lines = [
        f"# 固件模拟会话 {state.get('session_id', '')}",
        "",
        f"- 任务：{state.get('task', '')}",
        f"- 固件任务：{state.get('job_id', '')}",
        f"- 状态：{state.get('status', '')}",
        "",
    ]
    envs = emul_store.list_envs(_data_dir())
    mine = [e for e in envs if e.get("session_id") == state.get("session_id")]
    for e in mine:
        lines += [
            f"## 环境 {e['env_id']}（{e['status']}）",
            f"- 服务：{json.dumps(e.get('services', []), ensure_ascii=False)[:800]}",
            f"- 复探端点：{json.dumps(e.get('verified_endpoints', []), ensure_ascii=False)[:400]}",
            "",
        ]
    (sdir / "report.md").write_text("\n".join(lines), encoding="utf-8")


def _finalize(sid: str, sdir: Path, state: dict, reason: str) -> None:
    try:
        envs = emul_store.list_envs(_data_dir())
        for e in envs:
            if e.get("session_id") == sid and e.get("status") in (
                    "booting", "degraded"):
                # 环境保留（挖掘侧还要消费），但收敛状态并记原因
                e["status"] = "stopped" if reason != "idle-reap" else e["status"]
                emul_store.env_note(e, f"模拟会话结束（{reason}），环境保留")
                emul_store.save_env(_data_dir(), e)
        for req in emul_store.list_requests(_data_dir()):
            if req.get("emul_session") == sid and req.get("status") in (
                    "pending", "working"):
                latest = [e for e in envs if e.get("request_id") == req["req_id"]]
                ready = [e for e in latest if e.get("status") == "ready"]
                if ready:
                    req["status"] = "ready"
                    req["env_id"] = ready[0]["env_id"]
                else:
                    req["status"] = "failed"
                    req["error"] = f"模拟会话结束（{reason}）时环境未就绪"
                emul_store.save_request(_data_dir(), req)
        _write_report(sdir, state)
    except Exception:
        pass


_manager_cache: _dsh_host.DshHostManager | None = None
_manager_lock = threading.Lock()


def _manager() -> _dsh_host.DshHostManager:
    global _manager_cache
    with _manager_lock:
        if _manager_cache is None:
            _manager_cache = _dsh_host.DshHostManager(
                DSH_REPO, NODE_BIN, _emul_env, _finalize,
                web_profile=EMUL_PROFILE_WEB, agent_preset=EMUL_PRESET)
            _manager_cache.start_reaper(
                lambda sid: (lambda d: (d, _read_state(d)) if d.is_dir()
                             else None)(EMUL_SESSIONS_HOME / sid))
        return _manager_cache

# register() 执行时登记请求创建闭包；挖掘收尾的自动模拟衔接
# （vulnagent_api._dsh_finalize）经此复用端点的门禁/复用/拉起逻辑。
_create_request_fn = None

# ---------------- 模拟会话自动驾驶 ----------------
# 与挖掘会话自动驾驶同构（vulnagent_api._autopilot）：turn completed 且
# 空闲超过阈值、该会话所有请求均已终态 → stop 收尾（_finalize 收敛环境
# 与请求并写报告）；瞬时错误自动恢复。页面无人观察时同样生效
# （2026-09-22 实测：turn completed 后停滞 25 分钟无人收尾）。
EMUL_AUTOPILOT_POLL = float(os.getenv("EMUL_AUTOPILOT_POLL", "20"))
EMUL_AUTOPILOT_IDLE_DONE = float(os.getenv("EMUL_AUTOPILOT_IDLE_DONE", "120"))
EMUL_AUTOPILOT_MAX_RETRIES = int(os.getenv("EMUL_AUTOPILOT_MAX_RETRIES", "2"))
_emul_autopilot_threads: dict = {}
_emul_autopilot_lock = threading.Lock()


def _emul_ensure_autopilot(sid: str) -> None:
    with _emul_autopilot_lock:
        th = _emul_autopilot_threads.get(sid)
        if th is not None and th.is_alive():
            return
        th = threading.Thread(target=_emul_autopilot, args=(sid,),
                              daemon=True, name=f"emul-autopilot-{sid}")
        _emul_autopilot_threads[sid] = th
        th.start()


def _emul_autopilot(sid: str) -> None:
    sdir = EMUL_SESSIONS_HOME / sid
    retries = 0
    rpc_failures = 0
    while True:
        time.sleep(EMUL_AUTOPILOT_POLL)
        state = _read_state(sdir)
        if not state or state.get("status") != "running":
            return
        # 直读 journal（零 RPC/零 host 依赖；RPC 路径在 host 死后会长时间
        # 挂起，见 vulnagent_api._journal_tail 注释）
        from orchestrator.app.vulnagent_api import _journal_tail
        events = _journal_tail(sdir)
        turn_end = next((ev for ev in reversed(events)
                         if ev.get("type") == "turn/end"), None)
        if turn_end is None:
            continue
        reason = (turn_end.get("data") or {}).get("reason") or {}
        err_msg = str((reason.get("error") or {}).get("message") or "")
        if reason.get("kind") == "error":
            # 引擎自愈让路（同 vulnagent autopilot）：error 后 journal 仍有
            # llm/retry 或新 turn 活动则不介入
            _ets = turn_end.get("time") or 0
            _recent = [e for e in events
                       if (e.get("time") or 0) > _ets
                       and e.get("type") in ("llm/retry", "turn/start",
                                             "assistant/message")]
            if _recent and time.time() * 1000 - max(
                    e.get("time") or 0 for e in _recent) < 120_000:
                continue
            if retries >= EMUL_AUTOPILOT_MAX_RETRIES:
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
                                 + err_msg[:120] + "）。请继续当前任务。"}]})
            except Exception:  # noqa: BLE001
                pass
            time.sleep(EMUL_AUTOPILOT_POLL)
            continue
        if reason.get("kind") in ("completed", "interrupted"):
            ts = turn_end.get("time") or 0
            idle_s = (time.time() * 1000 - ts) / 1000 if ts else 0
            # 只认真正的新 turn：队列里未消费的消息（user/message）说明
            # host 已死无法开工，不能据此无限等待（实测死区）。
            has_newer = any(ev.get("type") == "turn/start"
                            and (ev.get("time") or 0) > ts for ev in events)
            host_alive = False
            try:
                _pid = int((sdir / "runner.pid").read_text().strip())
                open(f"/proc/{_pid}/cmdline").read()
                host_alive = True
            except (OSError, ValueError):
                pass
            if idle_s > EMUL_AUTOPILOT_IDLE_DONE and (not has_newer
                                                      or not host_alive):
                # 无条件收尾：AI 已停（完成/被打断/宿主已死），残留的
                # working 请求由 _finalize 自动终态化（failed/ready）。
                try:
                    if not _manager().stop(sid, sdir, state,
                                           reason="auto-complete"):
                        # host 已死且未注册：stop 直接返回 False 不走
                        # finalize 回调——手动收尾，否则 state 永远 running
                        _finalize(sid, sdir, state, "auto-complete")
                        state["status"] = "done"
                        _save_state(sdir, state)
                except Exception:  # noqa: BLE001
                    try:
                        _finalize(sid, sdir, state, "auto-complete")
                        state["status"] = "done"
                        _save_state(sdir, state)
                    except Exception:  # noqa: BLE001
                        pass
                return


# ---------------- setup ----------------

def setup(app: FastAPI, require_token) -> None:
    """Register emulation routes. Call BEFORE webui.setup(app)."""
    auth = [Depends(require_token)]
    emul_janitor.start(_data_dir())

    # ---- 模拟会话 ----

    @app.post("/emulagent/sessions", status_code=202)
    def create_session(payload: dict = Body(...),
                       principal: dict = Depends(require_token)):
        raw_task = str(payload.get("task") or "").strip()
        if not raw_task:
            raise HTTPException(status_code=400, detail="缺少 task")
        # 前置指引（skill 按需加载不可靠——与挖掘侧同因同修）：中文纪律
        # + csman/MTD/SIGBUS 诊断配方入口（2026-09-23 R15A1 HNAP 链实战）
        task = (
            "【模拟纪律（必须遵守）】对用户只说简体中文；每完成一组操作"
            "用一两句中文汇报进展与证据。\n"
            "D-Link/csman 机型必读流程：先跑 rc40/rc50 语义（解 www.tgz"
            " 到 /tmp/www3、cp pre4.dat pre7.dat reset.dat 到 /tmp/csman）"
            "再起 csmanuds/httpd；MTD 报错先判存活再考虑等长路径 patch"
            "或交叉编译 LD_PRELOAD 垫片；qemu signal 10 (Bus error) 用"
            " qemu -g + gdb-multiarch 或 strace 定位；HNAP 501/404/SIGBUS"
            "语义与 /var/config UBIFS 补齐方法见 fwgraph-firmware-emul "
            "技能的诊断配方节。\n\n"
        ) + raw_task
        if not job_id:
            raise HTTPException(status_code=400,
                                detail="缺少 job_id：模拟必须绑定固件任务")
        mf = _data_dir() / "extracted" / job_id / "manifest.json"
        if not mf.is_file():
            raise HTTPException(status_code=404,
                                detail=f"任务 {job_id} 未解包，无法模拟")
        if not (DSH_REPO / "apps" / "cli").is_dir():
            raise HTTPException(status_code=503, detail="未安装 DeepSeek Harness")
        running = _live_sessions()
        if len(running) >= EMUL_MAX_PARALLEL:
            raise HTTPException(
                status_code=409,
                detail=f"{len(running)} 个模拟会话已在运行（上限 "
                       f"{EMUL_MAX_PARALLEL}）: " + ", ".join(running))
        max_turns = max(1, min(int(payload.get("max_turns") or EMUL_MAX_TURNS),
                               EMUL_MAX_TURNS))
        sid = f"e-{secrets.token_hex(4)}-{secrets.token_hex(4)}"
        sdir = EMUL_SESSIONS_HOME / sid
        sdir.mkdir(parents=True, exist_ok=True)
        (sdir / "workspace").mkdir(exist_ok=True)
        state = {
            "session_id": sid, "agent_id": "fw-emul (dsh-web)",
            "environment_id": "fwgraph-emul-dsh-web",
            "task": raw_task, "status": "running", "turns": 1,
            "usage": {}, "created_at": _now(), "updated_at": _now(),
            "engine": "dsh-web", "job_id": job_id,
            "max_turns": max_turns,
            "owner": principal["username"] or "admin",
            "approval_policy": "auto",
        }
        _save_state(sdir, state)

        def _boot_and_prompt():
            try:
                dsh_sid = _manager().create_session(sid, sdir, state)
                state["dsh_session_id"] = dsh_sid
                _save_state(sdir, state)
            except _dsh_host.DshHostError as exc:
                state["status"] = "error"
                state["error"] = f"{exc.code}: {exc}"
                _save_state(sdir, state)
                return
            try:
                _manager().rpc(sid, sdir, state, "session.prompt", {
                    "mode": "queue",
                    "content": [{"type": "text", "text": task}],
                })
            except Exception as exc:  # noqa: BLE001
                try:
                    with open(sdir / "runner.log", "a", encoding="utf-8") as fh:
                        fh.write(f"[emulagent_api] first prompt failed: {exc}\n")
                except OSError:
                    pass

        threading.Thread(target=_boot_and_prompt, daemon=True,
                         name=f"emul-boot-{sid}").start()
        _emul_ensure_autopilot(sid)
        return {"session_id": sid, "status": "running", "engine": "dsh-web",
                "max_turns": max_turns}

    @app.get("/emulagent/sessions")
    def list_sessions(principal: dict = Depends(require_token)):
        if not EMUL_SESSIONS_HOME.is_dir():
            return []
        out = [_summary(d) for d in EMUL_SESSIONS_HOME.iterdir() if d.is_dir()]
        out = [s for s in out
               if accounts.can_access(principal, s["owner"])]
        out.sort(key=lambda s: s.get("created_at") or "", reverse=True)
        return out

    @app.get("/emulagent/sessions/{sid}")
    def get_session(sid: str, principal: dict = Depends(require_token)):
        sdir = _sdir(sid)
        _require_access(sdir, principal)
        out = _summary(sdir)
        out["envs"] = [e for e in emul_store.list_envs(_data_dir())
                       if e.get("session_id") == sid]
        return out

    @app.post("/emulagent/sessions/{sid}/rpc/{method}")
    def session_rpc(sid: str, method: str, payload: dict = Body(default=None),
                    principal: dict = Depends(require_token)):
        sdir = _sdir(sid)
        _require_access(sdir, principal)
        state = _read_state(sdir)
        if method == "session.prompt" and state.get("status") in (
                "done", "error"):
            raise HTTPException(status_code=409, detail="session already finished")
        if method == "session.history":
            # 宿主不在就离线回放 events.sse，绝不为看历史冷启 Node 宿主
            # （与 vulnagent_api 同语义；模拟会话事件格式与其完全一致）。
            mgr = _manager_cache
            if mgr is None or not mgr.is_live(sid):
                return vulnagent_api._history_from_sse(sdir, payload or {})
        try:
            value = _manager().rpc(sid, sdir, state, method, payload or {})
        except _dsh_host.DshHostError as exc:
            status = {"bad-request": 400, "session-not-found": 404}.get(
                exc.code, 502)
            raise HTTPException(status_code=status,
                                detail=f"{exc.code}: {exc}") from exc
        if method == "session.prompt":
            state = _read_state(sdir)
            state["turns"] = int(state.get("turns") or 0) + 1
            _save_state(sdir, state)
        if state.get("dsh_session_id"):
            _save_state(sdir, state)
        return value

    @app.get("/emulagent/sessions/{sid}/mux")
    async def session_mux(sid: str,
                          principal: dict = Depends(require_token)):
        sdir = _sdir(sid)
        _require_access(sdir, principal)
        state = _read_state(sdir)

        async def _idle():
            yield ": idle\n\n"

        if str(state.get("status") or "") != "running":
            return StreamingResponse(_idle(), media_type="text/event-stream",
                                     headers={"Cache-Control": "no-cache",
                                              "X-Accel-Buffering": "no"})
        if not _host_alive(sid, sdir) and (sdir / "runner.pid").is_file():
            # 失联会话（宿主进程已死）：只读观察不负责复活它，
            # 否则每次有人打开本页都会冷启一个 Node 宿主。
            return StreamingResponse(_idle(), media_type="text/event-stream",
                                     headers={"Cache-Control": "no-cache",
                                              "X-Accel-Buffering": "no"})
        return StreamingResponse(_manager().mux_sse(sid, sdir, state),
                                 media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache",
                                          "X-Accel-Buffering": "no"})

    @app.post("/emulagent/sessions/{sid}/respond")
    def session_respond(sid: str, payload: dict = Body(...),
                        principal: dict = Depends(require_token)):
        sdir = _sdir(sid)
        _require_access(sdir, principal)
        state = _read_state(sdir)
        try:
            return _manager().respond(sid, sdir, state, payload)
        except _dsh_host.DshHostError as exc:
            raise HTTPException(status_code=502,
                                detail=f"{exc.code}: {exc}") from exc

    @app.post("/emulagent/sessions/{sid}/stop")
    def stop_session(sid: str, principal: dict = Depends(require_token)):
        sdir = _sdir(sid)
        _require_access(sdir, principal)
        state = _read_state(sdir)
        killed = _manager().stop(sid, sdir, state, reason="stop")
        state["status"] = "done"
        _save_state(sdir, state)
        return {"session_id": sid, "status": "done", "stopped_host": killed}

    @app.delete("/emulagent/sessions/{sid}")
    def delete_session(sid: str, principal: dict = Depends(require_token)):
        sdir = _sdir(sid)
        _require_access(sdir, principal)
        state = _read_state(sdir)
        if state.get("status") == "running":
            _manager().stop(sid, sdir, state, reason="delete")
        import shutil
        shutil.rmtree(sdir, ignore_errors=True)
        return {"deleted": sid}

    # ---- 模拟环境生命周期 ----

    def _env_or_404(env_id: str) -> dict:
        env = emul_store.load_env(_data_dir(), env_id)
        if env is None:
            raise HTTPException(status_code=404, detail="环境不存在")
        return emul_runner.reconcile_env(_data_dir(), env)

    @app.post("/emul/build")
    def emul_build(payload: dict = Body(...),
                   principal: dict = Depends(require_token)):
        job_id = str(payload.get("job_id") or "").strip()
        session_id = str(payload.get("session_id") or "").strip()
        if not job_id or not session_id:
            raise HTTPException(status_code=400,
                                detail="需要 job_id 与 session_id（模拟会话）")
        sdir = EMUL_SESSIONS_HOME / session_id
        if not sdir.is_dir():
            raise HTTPException(status_code=404, detail="模拟会话不存在")
        env_id = emul_store.new_env_id(job_id)
        try:
            env = emul_runner.build_env(
                _data_dir(), job_id, session_id, EMUL_SESSIONS_HOME, env_id,
                budget_gb=payload.get("budget_gb"),
                request_id=str(payload.get("request_id") or ""),
                owner=principal["username"] or "admin")
        except emul_runner.EmulError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return env

    @app.get("/emul/envs")
    def emul_list_envs(job_id: str | None = None,
                       status: str | None = None,
                       principal: dict = Depends(require_token)):
        return emul_store.list_envs(_data_dir(), job_id=job_id,
                                    status=status)

    @app.get("/emul/envs/{env_id}")
    def emul_get_env(env_id: str, principal: dict = Depends(require_token)):
        return _env_or_404(env_id)

    @app.post("/emul/envs/{env_id}/boot")
    def emul_boot(env_id: str, payload: dict = Body(...),
                  principal: dict = Depends(require_token)):
        env = _env_or_404(env_id)
        try:
            svc = emul_runner.boot_service(
                _data_dir(), env,
                str(payload.get("binary_md5") or ""),
                list(payload.get("argv") or []),
                int(payload.get("port") or 0),
                argv0=payload.get("argv0"),
                name=payload.get("name"),
                ready_timeout=payload.get("ready_timeout"),
                binary_path=payload.get("binary_path"))
        except (emul_runner.EmulError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return svc

    @app.post("/emul/envs/{env_id}/console")
    def emul_console(env_id: str, payload: dict = Body(default=None),
                     principal: dict = Depends(require_token)):
        env = _env_or_404(env_id)
        p = payload or {}
        try:
            return emul_runner.console(env, service=p.get("service"),
                                       tail=int(p.get("tail") or 120))
        except emul_runner.EmulError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/emul/envs/{env_id}/probe")
    def emul_probe(env_id: str, payload: dict = Body(...),
                   principal: dict = Depends(require_token)):
        env = _env_or_404(env_id)
        try:
            return emul_runner.probe(
                _data_dir(), env, payload.get("port"),
                proto=str(payload.get("proto") or "tcp"),
                http_path=payload.get("http_path"),
                payload_hex=payload.get("payload_hex"),
                http_method=payload.get("http_method"),
                path=payload.get("path"))
        except (emul_runner.EmulError, ValueError, TypeError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/emul/envs/{env_id}/send")
    def emul_send(env_id: str, payload: dict = Body(...),
                  principal: dict = Depends(require_token)):
        """挖掘 agent 的消费通道：向模拟设备发真实报文。"""
        env = _env_or_404(env_id)
        try:
            return emul_runner.send(
                _data_dir(), env, payload.get("port"),
                proto=str(payload.get("proto") or "tcp"),
                payload_hex=payload.get("payload_hex"),
                payload_text=payload.get("payload"),
                http_method=payload.get("http_method"),
                http_path=str(payload.get("http_path") or "/"),
                headers=payload.get("headers"))
        except (emul_runner.EmulError, ValueError, TypeError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/emul/envs/{env_id}/patch")
    def emul_patch(env_id: str, payload: dict = Body(...),
                   principal: dict = Depends(require_token)):
        env = _env_or_404(env_id)
        try:
            return emul_runner.patch_file(
                _data_dir(), env, str(payload.get("op") or "write"),
                str(payload.get("path") or ""),
                content_b64=payload.get("content_b64"),
                mode=payload.get("mode"),
                content_text=payload.get("content"))
        except (emul_runner.EmulError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/emul/envs/{env_id}/read")
    def emul_read(env_id: str, payload: dict = Body(...),
                  principal: dict = Depends(require_token)):
        env = _env_or_404(env_id)
        try:
            return emul_runner.read_file(env, str(payload.get("path") or ""))
        except emul_runner.EmulError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/emul/envs/{env_id}/reset")
    def emul_reset(env_id: str, principal: dict = Depends(require_token)):
        env = _env_or_404(env_id)
        try:
            return emul_runner.reset_env(_data_dir(), env)
        except emul_runner.EmulError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/emul/envs/{env_id}/stop")
    def emul_stop(env_id: str, principal: dict = Depends(require_token)):
        env = _env_or_404(env_id)
        return emul_runner.stop_env(_data_dir(), env, reason="api")

    @app.post("/emul/envs/{env_id}/publish")
    def emul_publish(env_id: str, payload: dict = Body(...),
                     principal: dict = Depends(require_token)):
        env = _env_or_404(env_id)
        try:
            out = emul_runner.publish_env(
                _data_dir(), env, list(payload.get("endpoints") or []),
                note=str(payload.get("note") or ""))
        except emul_runner.EmulError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if out.get("published") and env.get("request_id"):
            req = emul_store.load_request(_data_dir(), env["request_id"])
            if req and req.get("status") not in ("ready", "cancelled"):
                req["status"] = "ready"
                req["env_id"] = env["env_id"]
                emul_store.save_request(_data_dir(), req)
            # 环境就绪的权威信号：把可用性 queue 回发起请求的挖掘会话
            if req and not req.get("miner_notified"):
                ok = _notify_miner(
                    req.get("from_session") or "",
                    "[模拟环境就绪] 请求 " + req["req_id"] + "（目标："
                    + (req.get("goal") or "") + "）的环境已构建并通过编排器"
                    "复探：env_id=" + env["env_id"] + "，端点："
                    + _fmt_endpoints(env) + "。可用 fw_emul_env 查看服务与"
                    "端口映射、fw_emul_send 对端点发真实请求做动态验证。")
                if ok:
                    req["miner_notified"] = True
                    emul_store.save_request(_data_dir(), req)
        return out

    # ---- 挖掘 → 模拟 请求总线 ----

    @app.post("/emul/requests", status_code=202)
    def create_request(payload: dict = Body(...),
                       principal: dict = Depends(require_token)):
        """挖掘 agent 发起模拟请求；自动拉起/复用该 job 的模拟会话。"""
        job_id = str(payload.get("job_id") or "").strip()
        goal = str(payload.get("goal") or "").strip()
        if not job_id or not goal:
            raise HTTPException(status_code=400, detail="需要 job_id 与 goal")
        # 顺序门禁：固件模拟在漏洞挖掘之后。job 存在未收尾的挖掘会话
        # 时拒绝（挖掘 agent 的 fw_emul_request 同样收到此提示，引导其
        # 专注静态/图谱分析并在结论中列出待动态验证的目标）。
        # awaiting_continue 豁免（2026-09-23 询问制）：挖掘完成转
        # "等待用户确认是否模拟" 的会话不挡模拟发起。
        unfinished = []
        from orchestrator.app import vulnagent_api as _va
        _sess_root = _va.VULNAGENT_HOME / "sessions"
        if _sess_root.is_dir():
            for _sd in _sess_root.iterdir():
                if not _sd.is_dir():
                    continue
                _st = _va._read_state(_sd) or {}
                if _st.get("job_id") == job_id and _st.get("status") in (
                        "running", "interrupted", "error"):
                    unfinished.append(f"{_sd.name}:{_st.get('status')}")
        if unfinished:
            raise HTTPException(
                status_code=409,
                detail="固件模拟在漏洞挖掘结束后进行；该固件存在未收尾的"
                       f"挖掘会话（{', '.join(unfinished[:3])}）。请先完成或"
                       "停止挖掘（挖掘正常收尾后编排会自动发起模拟）。")
        req_id = emul_store.new_request_id(job_id)
        req = emul_store.new_request_record(
            req_id, job_id, goal, dict(payload.get("targets") or {}),
            str(payload.get("from_session") or ""),
            from_agent=str(payload.get("from_agent") or "vuln-miner"),
            owner=principal["username"] or "admin")
        emul_store.save_request(_data_dir(), req)

        # 复用同 job 的运行中模拟会话；没有就拉一个（新会话创建时即投递任务）
        sid = None
        reused = False
        for s in _live_sessions():
            if _read_state(EMUL_SESSIONS_HOME / s).get("job_id") == job_id:
                sid = s
                reused = True
                break
        if sid is None:
            sub = {"task": _synthesize_task(req), "job_id": job_id,
                   "max_turns": EMUL_MAX_TURNS}
            inner = create_session(sub, principal)
            sid = inner["session_id"]
        req["emul_session"] = sid
        req["status"] = "working"
        emul_store.save_request(_data_dir(), req)
        if reused:
            # 已在跑的会话补一条队列消息（不抢占当前轮）
            try:
                sdir = EMUL_SESSIONS_HOME / sid
                _manager().rpc(sid, sdir, _read_state(sdir),
                               "session.prompt", {
                                   "mode": "queue",
                                   "content": [{"type": "text",
                                                "text": _synthesize_task(req)}]})
            except Exception:  # noqa: BLE001 - 排队失败不致命，前端可看请求
                pass
        return {"req_id": req_id, "status": "working",
                "emul_session": sid}
    global _create_request_fn
    _create_request_fn = create_request

    @app.post("/emul/report", status_code=202)
    def emul_report(payload: dict = Body(...),
                    principal: dict = Depends(require_token)):
        """模拟 agent 主动向挖掘 agent 上报进展（跨 agent 通信入口）。

        kind=ready/blocked/progress；text 中文。定位关联请求：优先
        env_id→request_id，其次本任务最新非终态请求。落请求 updates，
        并在挖掘会话活着时 queue 一条通知。
        """
        kind = str(payload.get("kind") or "progress")
        if kind not in ("progress", "ready", "blocked"):
            raise HTTPException(status_code=400, detail="kind 需为 progress/ready/blocked")
        text = str(payload.get("text") or "").strip()[:1200]
        if not text:
            raise HTTPException(status_code=400, detail="text 不能为空")
        env_id = str(payload.get("env_id") or "")
        req = None
        env = None
        if env_id:
            env = next((e for e in emul_store.list_envs(_data_dir())
                        if e.get("env_id") == env_id), None)
            if env and env.get("request_id"):
                req = emul_store.load_request(_data_dir(), env["request_id"])
        if req is None:
            cands = [r for r in emul_store.list_requests(_data_dir())
                     if r.get("status") in ("pending", "working")]
            cands.sort(key=lambda r: str(r.get("updated_at") or ""), reverse=True)
            req = cands[0] if cands else None
        if req is None:
            return {"delivered": False, "reason": "没有关联的模拟请求"}
        req.setdefault("updates", []).append(
            {"at": emul_store._now(), "kind": kind, "text": text})
        prefix = {"ready": "[模拟环境就绪]", "blocked": "[模拟受阻]",
                  "progress": "[模拟进度]"}[kind]
        delivered = _notify_miner(
            req.get("from_session") or "",
            prefix + " 请求 " + req["req_id"] + "：" + text)
        if kind == "ready" and env and env.get("status") == "ready"                 and req.get("status") not in ("ready", "cancelled"):
            req["status"] = "ready"
            req["env_id"] = env["env_id"]
        if kind == "blocked" and req.get("status") == "working":
            req["status"] = "failed"
            req["error"] = text[:4000]
        emul_store.save_request(_data_dir(), req)
        return {"delivered": delivered, "req_id": req["req_id"],
                "miner_session": req.get("from_session") or ""}

    @app.post("/emul/janitor/run")
    def janitor_run(principal: dict = Depends(require_token)):
        """手动触发一轮自动清理（管理员）；后台线程每 30 分钟自动跑。"""
        if principal.get("role") != "admin":
            raise HTTPException(status_code=403, detail="仅管理员")
        return emul_janitor.reap_once(_data_dir())

    @app.get("/emul/requests")
    def list_requests(job_id: str | None = None,
                      principal: dict = Depends(require_token)):
        return emul_store.list_requests(_data_dir(), job_id=job_id)

    @app.get("/emul/requests/{req_id}")
    def get_request(req_id: str, principal: dict = Depends(require_token)):
        req = emul_store.load_request(_data_dir(), req_id)
        if req is None:
            raise HTTPException(status_code=404, detail="请求不存在")
        return req

    # 编排器重启后 running 模拟会话的自动驾驶线程随进程丢失——启动恢复
    try:
        for sd in EMUL_SESSIONS_HOME.iterdir():
            if sd.is_dir():
                st = _read_state(sd)
                if st and st.get("status") == "running":
                    _emul_ensure_autopilot(str(st.get("session_id")
                                                or sd.name))
    except Exception:  # noqa: BLE001 - 恢复失败不阻塞启动
        pass


def _miner_alive(session_id: str) -> bool:
    sdir = VULNAGENT_HOME / "sessions" / str(session_id or "")
    try:
        state = json.loads((sdir / "state.json").read_text(encoding="utf-8"))
        return state.get("status") == "running"
    except (OSError, ValueError):
        return False


def _notify_miner(session_id: str, text: str) -> bool:
    """把模拟侧动态 queue 进挖掘会话（A2A 反向通道）。

    挖掘会话活着才投递；非 running 只落请求记录（updates），挖掘侧
    之后可在会话历史里看到。投递失败不影响模拟流程。
    """
    if not session_id or not _miner_alive(session_id):
        return False
    sdir = VULNAGENT_HOME / "sessions" / session_id
    try:
        state = json.loads((sdir / "state.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    try:
        from orchestrator.app import vulnagent_api
        vulnagent_api._manager().rpc(
            session_id, sdir, state, "session.prompt",
            {"mode": "queue",
             "content": [{"type": "text", "text": text}]})
        return True
    except Exception:  # noqa: BLE001 - 通知失败不阻塞模拟
        return False


def _fmt_endpoints(env: dict) -> str:
    parts = []
    for ep in env.get("verified_endpoints") or []:
        if ep.get("path"):
            parts.append(f"unix:{ep['path']}")
        elif ep.get("port"):
            parts.append(f"{ep.get('proto') or 'tcp'}:{ep['port']}")
    for svc in env.get("services") or []:
        if svc.get("status") == "ok" and svc.get("host_port"):
            parts.append(f"{svc['name']}(容器{svc['guest_port']}→宿主{svc['host_port']})")
    return "、".join(parts[:6]) or "（见 fw_emul_env）"


def _synthesize_task(req: dict) -> str:
    targets = req.get("targets") or {}
    lines = [
        f"[模拟请求 {req['req_id']}]（来自漏洞挖掘 agent，请围绕它的结论搭建环境）",
        f"目标：{req.get('goal', '')}",
    ]
    if targets:
        lines.append("结构化上下文：" + json.dumps(targets, ensure_ascii=False))
    lines += [
        "要求：",
        "0. 全程使用简体中文（含思考过程与最终汇报），禁止整段英文。",
        "1. fw_emul_build 建环境时带 request_id=" + req["req_id"] + "。",
        "2. 只把上下文里点名的服务和端口拉起来；起不来按 console 诊断-"
        "patch-reset 迭代，最多 6 轮。",
        "3. 全部端点 fw_emul_probe 实测通过后 fw_emul_publish（编排器会复探）。",
        "4. 禁止自建任何 web 页面/仪表盘冒充设备；环境只由真实固件进程构成。",
    ]
    return "\n".join(lines)
