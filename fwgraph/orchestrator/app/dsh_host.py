"""dsh web host 进程管理器：每个 vulnagent session 一个 harness web host。

背景：工作台复刻 harness Web UI 后，多轮对话 / queue / steer / 审批 / fork
等交互都走 harness 原生 JSON-RPC（POST /api/<method> 信封协议）；事件流在
web host 上是 WebSocket-only（GET 返回 426 upgrade required），本模块把它
桥成 SSE 供前端消费。harness 的 tools 插件仍把 vulnagent 格式 events.sse
落盘（plugin-events），所以既有 /events 端点与报告收割链不受影响。

生命周期：POST /vulnagent/sessions 创建 host + dsh session（agent preset
= fwgraph）；host 进程死掉后按 state.json 的 dsh_session_id 重启并 resume
（session.create 传已有 sessionId，harness 从磁盘日志恢复）；空闲超过
DSH_HOST_IDLE_SECONDS 被 reaper 回收（显式 stop 或回收时触发 finalize 回调
生成报告）。

鉴权（dsh 0.1.1+）：web host 启用浏览器会话鉴权——boot 日志打印
``dsh web: http://127.0.0.1:<port>/?token=<launch-token>``（官方就绪信号），
本模块 GET 该 URL 换取 authority 绑定的签名 cookie（存 ~/.dsh 凭据库的
密钥签名，30 天有效），此后所有 /api RPC、/api/respond 与事件 WS 都带该
cookie。host 每次重启换端口（新 authority），cookie 每次随 boot 重新铸造。
对前端的鉴权由 vulnagent_api 的 Bearer + owner 校验负责。
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import socket
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Callable

import httpx

DSH_WEB_PROFILE = os.getenv("DSH_WEB_PROFILE", "fwgraph-web")
DSH_AGENT_PRESET = os.getenv("DSH_AGENT_PRESET", "fwgraph")
BOOT_TIMEOUT = float(os.getenv("DSH_HOST_BOOT_TIMEOUT", "90"))
IDLE_SECONDS = float(os.getenv("DSH_HOST_IDLE_SECONDS", "1800"))
RPC_TIMEOUT = float(os.getenv("DSH_HOST_RPC_TIMEOUT", "30"))

# 前端允许透传的 harness RPC 方法（其余如 workspace.*/settings.* 不开放）
RPC_ALLOWLIST = frozenset({
    "host.describe",
    "session.list", "session.history", "session.prompt", "session.cancel",
    "session.updateQueue", "session.fork", "session.rename",
    "session.models", "session.selectModel",
    "agentPreset.list",
})

# ---------------- dsh 0.1.1+ 线协议适配 ----------------
# 上游 0.1.1 把 wire 协议换成了 Typert Gateway：端点 <ns>/<method>（斜杠）、
# payload 必须是 {"args": {<参数名>: ...}}（单 request 参数按 TS 参数名）；
# 事件 WS 从 /api/events.mux（自动推流）换成 /api/remote.mux（显式 open 流）；
# 审批应答从 /api/respond 换成 POST /api/$events/result。前端与编排器仍说
# 0.1.0 协议（点分方法 + 平铺 payload），下面的映射表 + 翻译器双向翻译。

# 旧方法名 → (新端点, request 参数名；None = 无参)
RPC_METHOD_MAP = {
    "host.describe": ("session/list", "_request"),   # 仅作 boot 就绪探测
    "session.list": ("session/list", "_request"),
    "session.create": ("session/create", "request"),
    "session.history": ("session/page", "request"),
    "session.prompt": ("session/prompt", "request"),
    "session.cancel": ("session/cancel", "request"),
    "session.fork": ("session/fork", "request"),
    "session.rename": ("session/rename", "request"),
    "session.updateQueue": ("session/updateQueue", "request"),
    "session.models": ("session/modelCatalog", None),
    "session.selectModel": ("session/selectModel", "request"),
    "agentPreset.list": ("agentPresets/list", None),
}


def _mint_request_id() -> str:
    return uuid.uuid4().hex


def _translate_request(method: str, arg_key: str | None, payload: dict,
                       dsh_sid: str) -> dict:
    """旧平铺 payload → 新 {"args": ...}。session.* 注入 sessionId。"""
    payload = dict(payload or {})
    if method == "session.list" or method == "host.describe":
        return {"_request": {}}
    if arg_key is None:
        return {}
    if method == "session.history":
        page = {"address": {"kind": "session", "sessionId": dsh_sid},
                "throughSeq": -1}
        if payload.get("maxMessages") is not None:
            page["maxMessages"] = int(payload["maxMessages"])
        if payload.get("beforeSeq") is not None:
            page["beforeSeq"] = int(payload["beforeSeq"])
        return {"request": page}
    if method == "session.prompt":
        req = dict(payload)
        req["sessionId"] = dsh_sid
        req.setdefault("requestId", _mint_request_id())
        req.setdefault("mode", "queue")
        return {"request": req}
    if method == "session.updateQueue":
        action = payload.get("action") if isinstance(
            payload.get("action"), dict) else {
            k: v for k, v in payload.items()
            if k not in ("sessionId", "itemId", "id")}
        return {"request": {
            "sessionId": dsh_sid,
            "itemId": payload.get("itemId") or payload.get("id") or "",
            "action": action,
        }}
    req = dict(payload)
    if method.startswith("session.") and method != "session.list":
        if dsh_sid:
            req.setdefault("sessionId", dsh_sid)
    return {"request": req}


def _translate_response(method: str, value: dict) -> dict:
    """新响应 → 旧形状（session.history 的 records → events 等）。"""
    value = dict(value or {})
    if method == "session.history":
        value = {"events": value.get("records") or [],
                 "hasMore": bool(value.get("hasMore"))}
    elif method == "agentPreset.list":
        value.setdefault("items", value.get("presets") or [])
    return value


def _old_frame(rpc_id: str, method: str, payload: dict) -> dict:
    """包一个 0.1.0 语义的 server-request 帧（前端 dshClient 的入口形状）。"""
    return {"type": "server-request", "rpcId": rpc_id,
            "method": method, "payload": payload}


def _translate_mux_frame(msg: dict, dsh_sid: str, host: "_Host",
                         attempt_ctx: dict) -> list:
    """remote.mux 帧批 → 旧 0.1.0 事件帧列表。

    msg 形状（stream-server.ts）：{type:'item', streamId, value} |
    {type:'end'|'error', streamId[, error]}。ready 帧的 clientId 落到
    host.events_client_id 供 respond() 使用。
    """
    out: list = []
    mtype = msg.get("type")
    if mtype == "error":
        err = msg.get("error") or {}
        out.append(_old_frame("stream", "stream/error",
                              {"error": {"message": str(
                                  err.get("message") or err.get("code")
                                  or "stream error")}}))
        return out
    if mtype != "item":
        return out
    value = msg.get("value") or {}
    stream = msg.get("streamId")

    if stream == "follow":
        vtype = value.get("type")
        if vtype == "snapshot":
            for i, rec in enumerate(value.get("records") or []):
                out.append(_old_frame(f"snap-{i}", "session/event",
                                      {"event": rec.get("event"),
                                       "view": rec.get("view")}))
        elif vtype == "event":
            out.append(_old_frame("live", "session/event",
                                  {"event": value.get("event"),
                                   "view": value.get("view")}))
        elif vtype == "assistant-stream":
            frame = value.get("frame") or {}
            ftype = frame.get("type")
            if ftype == "start":
                attempt_ctx[str(frame.get("attemptId"))] = {
                    "turn": frame.get("turn") or 0,
                    "step": frame.get("step") or 0}
            elif ftype == "chunk":
                ctx = attempt_ctx.get(str(frame.get("attemptId")), {})
                # 合成旧 assistant/chunk 事件（无 seq，前端按块折叠不落水位）
                out.append(_old_frame("stream", "session/event", {"event": {
                    "type": "assistant/chunk",
                    "data": {"chunk": frame.get("chunk"),
                             "turn": ctx.get("turn", 0),
                             "step": ctx.get("step", 0)}}}))

    elif stream == "control":
        vtype = value.get("type")
        if vtype == "baseline":
            base = value.get("value") or {}
            items = (base.get("queues") or {}).get(dsh_sid)
            if items is not None:
                out.append(_old_frame("ctl", "session/queue",
                                      {"items": items}))
            jobs = (base.get("jobs") or {}).get(dsh_sid)
            if jobs is not None:
                out.append(_old_frame("ctl", "session/jobs", {"jobs": jobs}))
        elif vtype == "queue" and value.get("sessionId") == dsh_sid:
            out.append(_old_frame("ctl", "session/queue",
                                  {"items": value.get("items") or []}))
        elif vtype == "jobs" and value.get("sessionId") == dsh_sid:
            out.append(_old_frame("ctl", "session/jobs",
                                  {"jobs": value.get("jobs") or []}))
        elif vtype == "projection" and value.get("sessionId") == dsh_sid:
            out.append(_old_frame("ctl", "session/projection", {
                "key": value.get("key"), "value": value.get("value"),
                "seq": value.get("seq")}))

    elif stream == "events":
        vtype = value.get("type")
        if vtype == "ready":
            host.events_client_id = str(value.get("clientId") or "")
        elif vtype == "waterfall":
            event = str(value.get("event") or "")
            request = value.get("request") or {}
            rpc_id = str(value.get("eventId") or "")
            if event == "approval/request":
                out.append(_old_frame(rpc_id, "approval/requested", {
                    "approvalId": rpc_id, "sessionId": dsh_sid,
                    "toolName": request.get("toolName") or "",
                    "callId": request.get("callId"),
                    "reason": request.get("reason") or ""}))
            elif event == "user-questions/request":
                out.append(_old_frame(rpc_id, "question/requested", {
                    "questions": request.get("questions") or []}))
        elif vtype == "emit":
            args = value.get("args") or []
            payload = args[0] if args and isinstance(args[0], dict) else {}
            out.append(_old_frame("evt", str(value.get("event") or ""),
                                  payload))
        elif vtype == "cancel":
            out.append(_old_frame(str(value.get("eventId") or ""),
                                  "approval/resolved", {}))
    return out


class DshHostError(Exception):
    """Boot/RPC failure. `code` 沿用 harness 错误码或 boot 自有码。"""

    def __init__(self, message: str, code: str = "internal"):
        super().__init__(message)
        self.code = code


def _session_gone(exc: DshHostError) -> bool:
    return exc.code in ("session-not-found", "bad-request")


def _session_corrupt(exc: DshHostError) -> bool:
    """磁盘日志校验失败：空 callId 的 tool/result 会让 history/resume 永久 502。"""
    text = f"{exc.code}: {exc}"
    return any(needle in text for needle in (
        "SessionPersistenceCorruptionError",
        "failed validation",
        "history unavailable",
        "must have tool source",
    ))


def _quarantine_dsh_session(dsh_sid: str) -> None:
    """Move a corrupt harness session out of ~/.dsh/sessions.

    Leaving a `.corrupt` sibling inside `sessions/` still breaks host boot:
    workspace listArtifacts scans every artifact and rejects renamed dirs
    whose header id no longer matches the path.
    """
    sid = str(dsh_sid or "").strip()
    if not sid or "/" in sid or sid in {".", ".."}:
        return
    home = Path(os.environ.get("DSH_HOME") or Path.home() / ".dsh")
    root = home / "sessions"
    if not root.is_dir():
        return
    try:
        matches = [
            p for p in root.rglob("*")
            if p.is_dir() and (p.name == sid or p.name.startswith(sid + ".corrupt"))
        ]
    except OSError:
        return
    dest_root = home / "quarantine"
    try:
        dest_root.mkdir(parents=True, exist_ok=True)
    except OSError:
        return
    for path in matches:
        dest = dest_root / f"{path.name}-{uuid.uuid4().hex[:8]}"
        try:
            path.rename(dest)
        except OSError:
            pass


def _alloc_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _Host:
    __slots__ = ("proc", "port", "dsh_session_id", "last_activity", "cookie",
                 "events_client_id")

    def __init__(self, proc: subprocess.Popen, port: int, dsh_session_id: str):
        self.proc = proc
        self.port = port
        self.dsh_session_id = dsh_session_id
        self.last_activity = time.monotonic()
        # dsh 0.1.1+ 浏览器会话鉴权铸造出的 "name=value" cookie 对（无属性）
        self.cookie = ""
        # $events 流 ready 帧下发的 clientId（respond 回填用；每次 mux 连接更新）
        self.events_client_id = ""


class DshHostManager:
    """线程安全的 sid → dsh web host 注册表。

    env_factory(sid, sdir, state) -> dict：由调用方（vulnagent_api）组装
    FWGRAPH_*/DEEPSEEK_* 环境；finalize(sid, sdir, state, reason) 在 stop/
    reap 时回调（写报告、落 state）；persist(sid, sdir, state) 在
    dsh_session_id 变更时落盘，避免 mux/history 并发只改内存。
    """

    def __init__(self, dsh_repo: Path, node_bin: str,
                 env_factory: Callable[[str, Path, dict], dict[str, str]],
                 finalize: Callable[[str, Path, dict, str], None] | None = None,
                 spawner: Callable[..., subprocess.Popen] | None = None,
                 persist: Callable[[str, Path, dict], None] | None = None,
                 web_profile: str = DSH_WEB_PROFILE,
                 agent_preset: str = DSH_AGENT_PRESET):
        self._repo = Path(dsh_repo)
        self._node = node_bin
        self._env_factory = env_factory
        self._finalize = finalize or (lambda *_: None)
        self._persist = persist
        self._spawn = spawner or subprocess.Popen
        self._web_profile = web_profile
        self._agent_preset = agent_preset
        self._hosts: dict[str, _Host] = {}
        self._sid_locks: dict[str, threading.Lock] = {}
        self._discarded: set[str] = set()
        self._lock = threading.Lock()
        self._reaper_stop = threading.Event()
        self._reaper: threading.Thread | None = None

    def undiscard(self, sid: str) -> None:
        with self._lock:
            self._discarded.discard(sid)

    def _lock_for(self, sid: str) -> threading.Lock:
        with self._lock:
            lock = self._sid_locks.get(sid)
            if lock is None:
                lock = threading.Lock()
                self._sid_locks[sid] = lock
            return lock

    def _persist_state(self, sid: str, sdir: Path, state: dict) -> None:
        if self._persist is not None:
            self._persist(sid, sdir, state)

    def _mint_session(self, host: _Host, sid: str, sdir: Path, state: dict) -> str:
        """Abandon a dead/corrupt harness session and create a fresh one."""
        old = host.dsh_session_id or str(state.get("dsh_session_id") or "")
        if old:
            _quarantine_dsh_session(old)
        value = self._rpc(host, "session/create", {
            "request": {"cwd": _session_cwd(sdir, state),
                        "agentPreset": self._agent_preset}})
        new_id = str(value.get("sessionId") or "")
        if not new_id:
            raise DshHostError("session.create returned no sessionId")
        host.dsh_session_id = new_id
        state["dsh_session_id"] = new_id
        self._persist_state(sid, sdir, state)
        return new_id

    # ---------------- 进程生命周期 ----------------

    def _kill_stale_pid(self, sdir: Path) -> bool:
        """编排器重启后旧 host 仍占 runner.pid：先清掉再 spawn，避免双开。"""
        try:
            pid = int((sdir / "runner.pid").read_text().strip())
        except (OSError, ValueError):
            return False
        if pid <= 1:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except OSError:
            return False
        try:
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
        except OSError:
            cmdline = b""
        if cmdline and b"fwgraph-web" not in cmdline \
                and b"apps/cli/lib/bin.js" not in cmdline \
                and b"apps/cli/src/bin.ts" not in cmdline:
            return False
        self._signal_pid(pid)
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return True

    def _wait_launch_token(self, host: _Host, sdir: Path) -> str:
        """等 boot 日志出现官方就绪行并取 launch token。

        web-app 在 Loader 落定后才打印 ``dsh web: http://127.0.0.1:<port>/
        ?token=...``（同一行可能尾随 LAN URL），supervisor 见到该行即可 RPC。
        """
        rx = re.compile(
            rf"dsh web: http://127\.0\.0\.1:{host.port}/\?token=([A-Za-z0-9_=-]+)")
        deadline = time.monotonic() + BOOT_TIMEOUT
        while time.monotonic() < deadline:
            if host.proc.poll() is not None:
                tail = ""
                try:
                    tail = (sdir / "runner.log").read_text(
                        encoding="utf-8", errors="replace")[-500:]
                except OSError:
                    pass
                raise DshHostError(
                    f"dsh web host exited rc={host.proc.returncode}: {tail}",
                    code="boot-failed")
            try:
                text = (sdir / "runner.log").read_text(
                    encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            m = rx.search(text)
            if m:
                return m.group(1)
            time.sleep(1.0)
        raise DshHostError(f"dsh web host boot timeout ({BOOT_TIMEOUT}s)",
                           code="boot-timeout")

    def _mint_cookie(self, host: _Host, sdir: Path) -> None:
        """launch token → 签名 cookie；后续 RPC/WS 全带它。"""
        token = self._wait_launch_token(host, sdir)
        url = f"http://127.0.0.1:{host.port}/"
        try:
            resp = httpx.get(url, params={"token": token},
                             follow_redirects=False, timeout=RPC_TIMEOUT)
        except httpx.HTTPError as exc:
            raise DshHostError(f"dsh cookie mint transport: {exc}",
                               code="upstream") from exc
        set_cookie = resp.headers.get("set-cookie", "")
        pair = set_cookie.split(";", 1)[0].strip()
        if resp.status_code != 303 or "=" not in pair:
            raise DshHostError(
                f"dsh cookie mint HTTP {resp.status_code}: {resp.text[:120]}",
                code="upstream")
        host.cookie = pair

    def _spawn_host(self, sid: str, sdir: Path, state: dict) -> _Host:
        self._kill_stale_pid(sdir)
        port = _alloc_port()
        env = self._env_factory(sid, sdir, state)
        env["DSH_TOOLS_MODE"] = env.get("DSH_TOOLS_MODE") or "native"
        # 入口用编译产物（全链从 lib 解析，单一模块图）。tsx 直跑 src 时
        # 部分插件链加载 src、包名导入走 lib，@deepseek-ai/dsh-tools 出现
        # src/lib 双副本，TOOL_RUNTIME_SCHEDULER symbol 不相等 → agent-loop
        # 取 undefined.prepare → 所有工具调用 turn 即错（2026-09-22 实测）。
        cli_entry = "apps/cli/lib/bin.js"
        if not (self._repo / cli_entry).is_file():
            cli_entry = "apps/cli/src/bin.ts"
        cmd = [self._node]
        if cli_entry.endswith(".ts"):
            cmd += ["--import", "tsx/esm"]
        cmd += [cli_entry, "--profile", self._web_profile,
                "--port", str(port), "--no-open"]
        log_file = open(sdir / "runner.log", "ab")
        try:
            proc = self._spawn(cmd, cwd=str(self._repo), env=env,
                               stdout=log_file, stderr=subprocess.STDOUT,
                               start_new_session=True)
        finally:
            log_file.close()
        try:
            (sdir / "runner.pid").write_text(str(proc.pid), encoding="utf-8")
        except OSError:
            pass
        host = _Host(proc, port, str(state.get("dsh_session_id") or ""))
        # 0.1.1+：先等就绪行 + 铸 cookie，再轮询 host.describe
        self._mint_cookie(host, sdir)
        deadline = time.monotonic() + BOOT_TIMEOUT
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                tail = ""
                try:
                    tail = (sdir / "runner.log").read_text(
                        encoding="utf-8", errors="replace")[-500:]
                except OSError:
                    pass
                raise DshHostError(
                    f"dsh web host exited rc={proc.returncode}: {tail}",
                    code="boot-failed")
            try:
                self._rpc(host, "session/list", {"_request": {}})
                return host
            except DshHostError:
                time.sleep(1.0)
        self._kill(host)
        raise DshHostError(f"dsh web host boot timeout ({BOOT_TIMEOUT}s)",
                           code="boot-timeout")

    def _signal_pid(self, pid: int) -> None:
        if not pid or pid <= 1:
            return

        def alive() -> bool:
            try:
                os.kill(pid, 0)
                return True
            except OSError:
                return False

        if not alive():
            return
        for sig, grace in ((signal.SIGTERM, 5.0), (signal.SIGKILL, 1.0)):
            try:
                os.killpg(pid, sig)
            except OSError:
                try:
                    os.kill(pid, sig)
                except OSError:
                    return
            deadline = time.monotonic() + grace
            while time.monotonic() < deadline:
                if not alive():
                    return
                time.sleep(0.1)

    def _kill(self, host: _Host) -> None:
        pid = getattr(host.proc, "pid", None)
        if pid:
            self._signal_pid(pid)
        try:
            if host.proc.poll() is None:
                host.proc.kill()
                host.proc.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass

    def ensure(self, sid: str, sdir: Path, state: dict,
               finished_ok: bool = False) -> _Host:
        """拿到 live host；进程死了按 dsh_session_id 重启并 resume。

        mux 与 session.history 会同时打进来：同一 sid 串行 boot，禁止双开
        host（否则一边 resume 成功、另一边空 session，history 缺 sessionId）。
        finished_ok：done/error 会话默认拒绝（prompt 等写操作走这条），
        但历史回放（mux / session.history）需要拉起只读宿主 resume——
        宿主随 orchestrator 重启死亡后，已结束会话的执行流仍可回看。
        """
        if str(state.get("status") or "") in ("done", "error") \
                and not finished_ok:
            raise DshHostError("session finished", code="session-not-found")
        with self._lock_for(sid):
            return self._ensure_locked(sid, sdir, state)

    def _ensure_locked(self, sid: str, sdir: Path, state: dict) -> _Host:
        # done/error 的 gate 在 ensure()（finished_ok 控制读路径放行）；
        # 这里只负责锁内复用/重启 host
        with self._lock:
            if sid in self._discarded:
                raise DshHostError("session discarded",
                                   code="session-not-found")
            host = self._hosts.get(sid)
            if host is not None and host.proc.poll() is None:
                host.last_activity = time.monotonic()
                return host
            stale = self._hosts.pop(sid, None)
            stale_sid = (
                (stale.dsh_session_id if stale else "")
                or str(state.get("dsh_session_id") or "")
            )
        # sid 锁内启动：同会话的 mux/history 等这次 boot 结束
        host = self._spawn_host(sid, sdir, state)
        if not host.dsh_session_id:
            host.dsh_session_id = stale_sid
        with self._lock:
            old = self._hosts.get(sid)
            if old is not None and old is not host:
                self._kill(old)
            self._hosts[sid] = host
        if host.dsh_session_id:
            # resume：create 传已有 sessionId，harness 从磁盘日志恢复
            try:
                self._rpc(host, "session/create", {
                    "request": {"cwd": _session_cwd(sdir, state),
                                "agentPreset": self._agent_preset,
                                "sessionId": host.dsh_session_id}})
            except DshHostError as exc:
                if _session_gone(exc) or _session_corrupt(exc):
                    self._mint_session(host, sid, sdir, state)
                else:
                    raise
        return host

    def create_session(self, sid: str, sdir: Path, state: dict) -> str:
        """新会话：ensure host + session.create + 返回 dsh_session_id。"""
        state.pop("dsh_session_id", None)
        host = self.ensure(sid, sdir, state)
        value = self._rpc(host, "session/create", {
            "request": {"cwd": _session_cwd(sdir, state),
                        "agentPreset": self._agent_preset}})
        dsh_sid = str(value.get("sessionId") or "")
        if not dsh_sid:
            raise DshHostError("session.create returned no sessionId")
        host.dsh_session_id = dsh_sid
        state["dsh_session_id"] = dsh_sid
        self._persist_state(sid, sdir, state)
        return dsh_sid

    def stop(self, sid: str, sdir: Path, state: dict, reason: str = "stop",
             finalize: bool = True, discard: bool = False) -> bool:
        with self._lock_for(sid):
            if discard:
                with self._lock:
                    self._discarded.add(sid)
            with self._lock:
                host = self._hosts.get(sid)
            if host is not None and host.proc.poll() is None \
                    and host.dsh_session_id:
                try:
                    self._rpc(host, "session/cancel", {
                        "request": {"sessionId": host.dsh_session_id}})
                except DshHostError:
                    pass
            with self._lock:
                host = self._hosts.pop(sid, None)
            killed = False
            if host is not None:
                self._kill(host)
                killed = True
            if self._kill_stale_pid(sdir):
                killed = True
            if finalize and killed:
                self._finalize(sid, sdir, state, reason)
            return killed

    def is_live(self, sid: str) -> bool:
        with self._lock:
            host = self._hosts.get(sid)
            return host is not None and host.proc.poll() is None

    def live_sids(self) -> list[str]:
        with self._lock:
            return [sid for sid, h in self._hosts.items()
                    if h.proc.poll() is None]

    def _reap_pass(self, state_reader: Callable[[str], tuple[Path, dict] | None]) -> list[str]:
        """单趟回收：进程已死或空闲超 IDLE_SECONDS 的 host。返回回收的 sid。"""
        with self._lock:
            victims = [(sid, h) for sid, h in self._hosts.items()
                       if h.proc.poll() is not None
                       or time.monotonic() - h.last_activity > IDLE_SECONDS]
        reaped = []
        for sid, host in victims:
            got = state_reader(sid)
            if got is not None and str((got[1] or {}).get("status") or "") \
                    == "awaiting_continue":
                host.last_activity = time.monotonic()
                continue
            with self._lock:
                self._hosts.pop(sid, None)
            self._kill(host)
            if got is not None:
                self._finalize(sid, got[0], got[1], "idle-reap")
            reaped.append(sid)
        return reaped

    def start_reaper(self, state_reader: Callable[[str], tuple[Path, dict] | None]) -> None:
        """后台线程：回收空闲 host。state_reader(sid) -> (sdir, state)。"""
        if self._reaper is not None:
            return

        def _loop() -> None:
            while not self._reaper_stop.wait(60):
                self._reap_pass(state_reader)

        self._reaper = threading.Thread(target=_loop, daemon=True,
                                        name="dsh-host-reaper")
        self._reaper.start()

    def shutdown(self) -> None:
        self._reaper_stop.set()
        with self._lock:
            hosts = list(self._hosts.items())
            self._hosts.clear()
        for _sid, host in hosts:
            self._kill(host)

    # ---------------- RPC / 事件流 ----------------

    def _rpc(self, host: _Host, method: str, payload: dict) -> dict:
        """0.1.1+ wire：POST /api/<ns>/<method>，payload={"args":...}。"""
        host.last_activity = time.monotonic()
        url = f"http://127.0.0.1:{host.port}/api/{method}"
        envelope = {"type": "client-request", "rpcId": uuid.uuid4().hex,
                    "method": method, "payload": {"args": payload or {}}}
        headers = {"Cookie": host.cookie} if host.cookie else None
        try:
            resp = httpx.post(url, json=envelope, headers=headers,
                              timeout=RPC_TIMEOUT)
        except httpx.HTTPError as exc:
            raise DshHostError(f"dsh rpc {method} transport: {exc}",
                               code="upstream") from exc
        try:
            body = resp.json()
        except ValueError as exc:
            raise DshHostError(
                f"dsh rpc {method} HTTP {resp.status_code}: {resp.text[:200]}",
                code="upstream") from exc
        result = body.get("result") or {}
        if result.get("ok"):
            return result.get("value") or {}
        error = result.get("error") or {}
        raise DshHostError(error.get("message") or f"dsh rpc {method} failed",
                           code=error.get("code") or "internal")

    def _rpc_history(self, host: _Host, dsh_sid: str,
                     payload: dict) -> dict:
        """session.history 兼容：0.1.1+ 的 page 需要 throughSeq 水位线。

        老协议 history 无水位线概念；先用超大 throughSeq 探测，host 会在
        "past cursor N" 错误里报出当前水位线，再按 N 重读（新会话 N=-1 →
        空页，等价老协议的空 history）。
        """
        page_req = {"address": {"kind": "session", "sessionId": dsh_sid},
                    "throughSeq": 10 ** 9,
                    "maxMessages": int(payload.get("maxMessages") or 200)}
        if payload.get("beforeSeq") is not None:
            page_req["beforeSeq"] = int(payload["beforeSeq"])
        try:
            res = self._rpc(host, "session/page", {"request": page_req})
        except DshHostError as exc:
            m = re.search(r"past cursor (-?\d+)", str(exc))
            if not m:
                raise
            page_req["throughSeq"] = int(m.group(1))
            res = self._rpc(host, "session/page", {"request": page_req})
        return {"events": res.get("records") or [],
                "hasMore": bool(res.get("hasMore"))}

    def rpc(self, sid: str, sdir: Path, state: dict, method: str,
            payload: dict) -> dict:
        """前端入口：旧协议方法名/负载 → 0.1.1+ wire，响应翻译回旧形状。"""
        if method not in RPC_ALLOWLIST:
            raise DshHostError(f"method not allowed: {method}",
                               code="bad-request")
        mapped = RPC_METHOD_MAP.get(method)
        if mapped is None:
            raise DshHostError(f"method not mapped: {method}",
                               code="bad-request")
        endpoint, arg_key = mapped
        # session.history 是纯读：已结束会话也要能回放（拉起只读宿主）
        host = self.ensure(sid, sdir, state,
                           finished_ok=(method == "session.history"))
        dsh_sid = str(state.get("dsh_session_id")
                      or host.dsh_session_id or "")
        if method.startswith("session.") and method != "session.list" \
                and method != "session.create" and not dsh_sid:
            dsh_sid = self._mint_session(host, sid, sdir, state)
        if method == "session.history":
            try:
                return self._rpc_history(host, dsh_sid, payload)
            except DshHostError as exc:
                if _session_corrupt(exc) or exc.code == "session-not-found":
                    self._mint_session(host, sid, sdir, state)
                    return {"events": [], "hasMore": False}
                raise
        args = _translate_request(method, arg_key, payload, dsh_sid)
        try:
            value = self._rpc(host, endpoint, args)
        except DshHostError as exc:
            retryable = method.startswith("session.") and method != "session.list"
            if retryable and (_session_corrupt(exc) or exc.code == "session-not-found"):
                new_id = self._mint_session(host, sid, sdir, state)
                args = _translate_request(method, arg_key, payload, new_id)
                if method == "session.history":
                    return {"events": [], "hasMore": False}
                value = self._rpc(host, endpoint, args)
            else:
                raise
        # fork 改换当前会话分支：跟随新 dsh session
        if method == "session.fork" and value.get("sessionId"):
            host.dsh_session_id = str(value["sessionId"])
            state["dsh_session_id"] = host.dsh_session_id
            self._persist_state(sid, sdir, state)
        return _translate_response(method, value)

    async def mux_sse(self, sid: str, sdir: Path, state: dict):
        """WS→SSE 桥：remote.mux 三条流 → 旧 0.1.0 事件帧。

        0.1.1+ 的事件 WS（/api/remote.mux）需要显式 open 流：
        - session/follow：durable 事件 + assistant 流（→ session/event）
        - session/control：queue/jobs/projection 实况（按 sessionId 过滤）
        - $events：审批/提问 waterfall（→ approval|question/requested，
          ready 帧的 clientId 存到 host 供 respond() 回填）
        """
        import json as _json
        import websockets  # 延迟导入：uvicorn[standard] 自带

        # mux 只读（follow/回放）：已结束会话拉起只读宿主，idle 不跑新轮
        host = await asyncio.to_thread(
            self.ensure, sid, sdir, state, True)
        url = f"ws://127.0.0.1:{host.port}/api/remote.mux"
        # 0.1.1+ 浏览器会话鉴权：WS upgrade 与 /api 同一道 requestRejection 围栏
        headers = {"Cookie": host.cookie} if host.cookie else None
        async with websockets.connect(url, max_size=16 * 1024 * 1024,
                                      additional_headers=headers) as ws:
            dsh_sid = host.dsh_session_id or str(
                state.get("dsh_session_id") or "")
            if not dsh_sid:
                # boot 竞态：前端在会话创建瞬间连 mux，此时 _boot_and_prompt
                # 的 create 可能尚未写回 dsh_session_id——直接 mint 会造出
                # 第二个没有任务的死会话，mux 绑死后前端永远零帧
                # （2026-09-23 实测）。先等 boot 写回，超时才兜底 mint。
                for _ in range(60):
                    await asyncio.sleep(0.5)
                    try:
                        _fresh = json.loads(
                            (sdir / "state.json").read_text(encoding="utf-8"))
                        dsh_sid = str(_fresh.get("dsh_session_id") or "")
                    except (OSError, ValueError):
                        dsh_sid = ""
                    if dsh_sid:
                        state["dsh_session_id"] = dsh_sid
                        break
            if not dsh_sid:
                dsh_sid = await asyncio.to_thread(
                    self._mint_session, host, sid, sdir, state)

            async def _open(stream_id: str, endpoint: str, args: dict):
                await ws.send(_json.dumps({
                    "type": "open", "streamId": stream_id,
                    "endpoint": endpoint, "payload": {"args": args}}))

            await _open("follow", "session/follow", {"request": {
                "address": {"kind": "session", "sessionId": dsh_sid},
                "assistantStream": True}})
            await _open("control", "session/control", {})
            await _open("events", "$events", {})
            yield (f'data: {_json.dumps({"type": "server-request", "rpcId": "mux-open", "method": "session/subscribed", "payload": {}})}\n\n')

            attempt_ctx: dict = {}   # assistant-stream start 帧的 turn/step
            while True:
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=15)
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
                    continue
                except websockets.exceptions.ConnectionClosed:
                    return
                host.last_activity = time.monotonic()
                try:
                    msg = _json.loads(raw)
                except ValueError:
                    continue
                for frame in _translate_mux_frame(msg, dsh_sid, host,
                                                  attempt_ctx):
                    yield f"data: {_json.dumps(frame)}\n\n"
                    self._note_turn_error(frame, sid, sdir, state)

    def _note_turn_error(self, frame: dict, sid: str, sdir: Path,
                         state: dict) -> None:
        """turn/end 的 error reason → 会话置 error（mux 消费者在场即生效）。

        agent-loop 的 turn 级错误（工具管线崩溃等）不会自行浮出到
        state.json；没有这层，编排与前端永远显示"思考中"。
        """
        try:
            # 只处理实时帧：mux 打开时 follow 快照会回放全部历史事件，
            # 旧 turn 的 error 帧会把 continue 后的 state 再打回 error
            # （2026-09-22 实测：resume 后 state 被旧错误覆盖）。
            if str(frame.get("rpcId") or "") != "live":
                return
            if frame.get("method") != "session/event":
                return
            event = (frame.get("payload") or {}).get("event") or {}
            if not isinstance(event, dict) or event.get("type") != "turn/end":
                return
            data = event.get("data") or {}
            reason = data.get("reason") or {}
            if not isinstance(reason, dict) or reason.get("kind") != "error":
                return
            err = reason.get("error") or {}
            message = str(err.get("message") or "turn error")[:300]
            if state.get("status") != "running":
                return
            state["status"] = "error"
            state["error"] = f"turn {data.get('turn')} error: {message}"
            state["updated_at"] = time.strftime(
                "%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
            self._persist_state(sid, sdir, state)
            with open(sdir / "events.sse", "a", encoding="utf-8") as fh:
                fh.write("event: error\ndata: " + json.dumps({
                    "ts": state["updated_at"], "session_id": sid,
                    "error": state["error"]}) + "\n\n")
        except Exception:  # noqa: BLE001 - 观察器绝不打断 mux 流
            pass

    def respond(self, sid: str, sdir: Path, state: dict, payload: dict) -> dict:
        """审批/提问答复（0.1.1+：POST /api/$events/result 携带 outcome）。

        入参仍是旧形状 {type:'client-response', rpcId, result:{ok,value}}；
        rpcId 即 $events waterfall 的 eventId。审批 value={sessionId,
        approvalId, outcome}，提问 value={answers:[...]}。返回旧形状
        {accepted, reason?} 供前端判定 not-pending。
        """
        host = self.ensure(sid, sdir, state)
        payload = dict(payload or {})
        rpc_id = str(payload.get("rpcId") or "")
        result = payload.get("result")
        ok = isinstance(result, dict) and result.get("ok") is True
        value = (result or {}).get("value") if ok else None
        if isinstance(value, dict) and "outcome" in value:
            outcome_value = value.get("outcome")
        else:
            outcome_value = value
        outcome = ({"kind": "result", "value": outcome_value}
                   if ok else
                   {"kind": "rejected",
                    "error": {"name": "client", "message": "rejected"}})
        args = {"clientId": host.events_client_id, "eventId": rpc_id,
                "outcome": outcome}
        envelope = {"type": "client-request", "rpcId": uuid.uuid4().hex,
                    "method": "$events/result", "payload": {"args": args}}
        url = f"http://127.0.0.1:{host.port}/api/$events/result"
        headers = {"Cookie": host.cookie} if host.cookie else None
        try:
            resp = httpx.post(url, json=envelope, headers=headers,
                              timeout=RPC_TIMEOUT)
        except httpx.HTTPError as exc:
            raise DshHostError(f"dsh respond transport: {exc}",
                               code="upstream") from exc
        try:
            body = resp.json()
        except ValueError as exc:
            raise DshHostError(
                f"dsh respond HTTP {resp.status_code}: {resp.text[:200]}",
                code="upstream") from exc
        result_envelope = body.get("result") or {}
        if result_envelope.get("ok"):
            return {"accepted": True}
        error = result_envelope.get("error") or {}
        return {"accepted": False,
                "reason": error.get("code") or "not-pending"}


def _session_cwd(sdir: Path, state: dict) -> str:
    """Writable sandbox for bash/fs tools. Firmware files stay read-only
    via fw_browse_firmware (extracted/<job>/); never point cwd there."""
    ws = sdir / "workspace"
    ws.mkdir(parents=True, exist_ok=True)
    readme = ws / "README.txt"
    if not readme.is_file():
        try:
            readme.write_text(
                "Writable sandbox for this hunt.\n"
                "Firmware files: fw_browse_firmware (read-only).\n"
                "Run firmware dynamically: fw_request_trace / fw_request_fuzz.\n"
                "You may write PoC files here and execute them with bash.\n",
                encoding="utf-8")
        except OSError:
            pass
    return str(ws)
