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
生成报告）。harness host 无鉴权（只绑 127.0.0.1 + Host/Origin 围栏），
本模块的服务端调用不带 Origin、Host 为 127.0.0.1，天然过信任围栏；对前端
的鉴权由 vulnagent_api 的 Bearer + owner 校验负责。
"""

from __future__ import annotations

import asyncio
import os
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


class DshHostError(Exception):
    """Boot/RPC failure. `code` 沿用 harness 错误码或 boot 自有码。"""

    def __init__(self, message: str, code: str = "internal"):
        super().__init__(message)
        self.code = code


def _alloc_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _Host:
    __slots__ = ("proc", "port", "dsh_session_id", "last_activity")

    def __init__(self, proc: subprocess.Popen, port: int, dsh_session_id: str):
        self.proc = proc
        self.port = port
        self.dsh_session_id = dsh_session_id
        self.last_activity = time.monotonic()


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
                 persist: Callable[[str, Path, dict], None] | None = None):
        self._repo = Path(dsh_repo)
        self._node = node_bin
        self._env_factory = env_factory
        self._finalize = finalize or (lambda *_: None)
        self._persist = persist
        self._spawn = spawner or subprocess.Popen
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
                and b"apps/cli/src/bin.ts" not in cmdline:
            return False
        self._signal_pid(pid)
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return True

    def _spawn_host(self, sid: str, sdir: Path, state: dict) -> _Host:
        self._kill_stale_pid(sdir)
        port = _alloc_port()
        env = self._env_factory(sid, sdir, state)
        env["DSH_TOOLS_MODE"] = env.get("DSH_TOOLS_MODE") or "native"
        cmd = [self._node, "--import", "tsx/esm", "apps/cli/src/bin.ts",
               "--profile", DSH_WEB_PROFILE, "--port", str(port)]
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
                self._rpc(host, "host.describe", {})
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

    def ensure(self, sid: str, sdir: Path, state: dict) -> _Host:
        """拿到 live host；进程死了按 dsh_session_id 重启并 resume。

        mux 与 session.history 会同时打进来：同一 sid 串行 boot，禁止双开
        host（否则一边 resume 成功、另一边空 session，history 缺 sessionId）。
        """
        if str(state.get("status") or "") in ("done", "error"):
            raise DshHostError("session finished", code="session-not-found")
        with self._lock_for(sid):
            return self._ensure_locked(sid, sdir, state)

    def _ensure_locked(self, sid: str, sdir: Path, state: dict) -> _Host:
        if str(state.get("status") or "") in ("done", "error"):
            raise DshHostError("session finished", code="session-not-found")
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
                self._rpc(host, "session.create", {
                    "cwd": _session_cwd(sdir, state),
                    "agentPreset": DSH_AGENT_PRESET,
                    "sessionId": host.dsh_session_id,
                })
            except DshHostError as exc:
                if exc.code in ("session-not-found", "bad-request"):
                    value = self._rpc(host, "session.create", {
                        "cwd": _session_cwd(sdir, state),
                        "agentPreset": DSH_AGENT_PRESET,
                    })
                    host.dsh_session_id = str(value.get("sessionId") or "")
                    if host.dsh_session_id:
                        state["dsh_session_id"] = host.dsh_session_id
                        self._persist_state(sid, sdir, state)
                else:
                    raise
        return host

    def create_session(self, sid: str, sdir: Path, state: dict) -> str:
        """新会话：ensure host + session.create + 返回 dsh_session_id。"""
        state.pop("dsh_session_id", None)
        host = self.ensure(sid, sdir, state)
        value = self._rpc(host, "session.create", {
            "cwd": _session_cwd(sdir, state),
            "agentPreset": DSH_AGENT_PRESET,
        })
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
                    self._rpc(host, "session.cancel", {
                        "sessionId": host.dsh_session_id,
                    })
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
        host.last_activity = time.monotonic()
        url = f"http://127.0.0.1:{host.port}/api/{method}"
        envelope = {"type": "client-request", "rpcId": uuid.uuid4().hex,
                    "method": method, "payload": payload}
        try:
            resp = httpx.post(url, json=envelope, timeout=RPC_TIMEOUT)
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

    def rpc(self, sid: str, sdir: Path, state: dict, method: str,
            payload: dict) -> dict:
        if method not in RPC_ALLOWLIST:
            raise DshHostError(f"method not allowed: {method}",
                               code="bad-request")
        host = self.ensure(sid, sdir, state)
        payload = dict(payload or {})
        raw_sid = payload.get("sessionId")
        dsh_sid = raw_sid if isinstance(raw_sid, str) and raw_sid.strip() else (
            host.dsh_session_id or str(state.get("dsh_session_id") or "")
        )
        if method.startswith("session.") and method != "session.list":
            if not dsh_sid:
                raise DshHostError(
                    "missing sessionId for " + method, code="bad-request")
            payload["sessionId"] = dsh_sid
            host.dsh_session_id = dsh_sid
        value = self._rpc(host, method, payload)
        # fork 改换当前会话分支：跟随新 dsh session
        if method == "session.fork" and value.get("sessionId"):
            host.dsh_session_id = str(value["sessionId"])
            state["dsh_session_id"] = host.dsh_session_id
            self._persist_state(sid, sdir, state)
        return value

    async def mux_sse(self, sid: str, sdir: Path, state: dict):
        """WS→SSE 桥：把 host 的 /api/events.mux 转成 text/event-stream 帧。"""
        import websockets  # 延迟导入：uvicorn[standard] 自带

        host = await asyncio.to_thread(self.ensure, sid, sdir, state)
        url = f"ws://127.0.0.1:{host.port}/api/events.mux"
        async with websockets.connect(url, max_size=16 * 1024 * 1024) as ws:
            while True:
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=15)
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
                    continue
                except websockets.exceptions.ConnectionClosed:
                    return
                host.last_activity = time.monotonic()
                text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
                # 与 SSE 格式对齐：单帧单行 JSON
                yield f"data: {text.strip()}\n\n"

    def respond(self, sid: str, sdir: Path, state: dict, payload: dict) -> dict:
        """转发审批/提问答复（/api/respond 是宿主级端点，不走 RPC 信封路由）。"""
        host = self.ensure(sid, sdir, state)
        url = f"http://127.0.0.1:{host.port}/api/respond"
        try:
            resp = httpx.post(url, json=payload, timeout=RPC_TIMEOUT)
        except httpx.HTTPError as exc:
            raise DshHostError(f"dsh respond transport: {exc}",
                               code="upstream") from exc
        try:
            return resp.json()
        except ValueError as exc:
            raise DshHostError(
                f"dsh respond HTTP {resp.status_code}: {resp.text[:200]}",
                code="upstream") from exc


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
