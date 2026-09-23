"""dsh web host 管理器（dsh_host.py）与 /vulnagent/sessions 代理端点测试。

假 host：FastAPI + uvicorn 跑在 127.0.0.1 临时端口，实现 harness 的
JSON-RPC 信封（/api/<method>）、/api/respond 与 WS /api/events.mux；
spawner 注入把 manager 的 node 子进程换成这个桩（端口从 cmd --port 解析）。
"""

import asyncio
import json
import threading
import time
from pathlib import Path

import pytest
import uvicorn
from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.testclient import TestClient

from orchestrator.app import accounts, main, vulnagent_api
from orchestrator.app import dsh_host

LEGACY = "orch-test-token"
JOB = "abcdef012345"


# ---------------- 假 dsh web host ----------------

class _StubHost:
    """ harness web host 桩：记录 RPC 信封，WS 回放预置帧。"""

    def __init__(self):
        self.calls = []          # (method, payload)
        self.responds = []       # POST /api/respond 原文
        self.mux_frames = []     # 连接后依次发出的 JSON 字符串
        self.session_counter = 0
        # dsh 0.1.1+ 浏览器会话鉴权：launch token → GET / 换 cookie → RPC 带 cookie
        self.token = "stub-launch-token-01"
        self.cookie_pair = "dsh-auth-stub=signed"
        self.app = FastAPI()
        self.server: uvicorn.Server | None = None
        self.thread: threading.Thread | None = None

        stub = self

        @self.app.get("/")
        async def index(token: str = ""):
            if token != stub.token:
                return Response(status_code=401, content="unauthorized")
            resp = Response(status_code=303)
            resp.headers["location"] = "/"
            resp.headers["set-cookie"] = (
                f"{stub.cookie_pair}; Path=/; HttpOnly; SameSite=Lax")
            return resp

        @self.app.post("/api/$events/result")
        async def events_result(body: dict, request: Request):
            if stub.cookie_pair not in (request.headers.get("cookie") or ""):
                return Response(status_code=401, content="unauthorized")
            args = (body.get("payload") or {}).get("args") or {}
            stub.responds.append(args)
            return {"type": "server-response", "rpcId": body.get("rpcId"),
                    "result": {"ok": True, "value": {"accepted": True}}}

        @self.app.post("/api/respond")
        async def respond(body: dict, request: Request):
            if stub.cookie_pair not in (request.headers.get("cookie") or ""):
                return Response(status_code=401, content="unauthorized")
            stub.responds.append(body)
            return {"accepted": True}

        @self.app.post("/api/{ns}/{method}")
        async def rpc(ns: str, method: str, body: dict, request: Request):
            if stub.cookie_pair not in (request.headers.get("cookie") or ""):
                return Response(status_code=401, content="unauthorized")
            endpoint = f"{ns}/{method}"
            if endpoint == "respond":
                stub.responds.append(body)
                return {"accepted": True}
            args = (body.get("payload") or {}).get("args") or {}
            req = args.get("request")
            if not isinstance(req, dict):
                req = args.get("_request") or {}
            stub.calls.append((endpoint, req))
            if endpoint == "session/list":
                value = {"items": []}
            elif endpoint == "session/create":
                # resume：payload 带 sessionId 时原样返回；session-dead* 模拟丢失
                sid = req.get("sessionId")
                if sid and str(sid).startswith("session-dead"):
                    return {
                        "type": "server-response",
                        "rpcId": body.get("rpcId"),
                        "result": {"ok": False, "error": {
                            "code": "session-not-found",
                            "message": "gone",
                        }},
                    }
                if sid and str(sid).startswith("session-corrupt"):
                    return {
                        "type": "server-response",
                        "rpcId": body.get("rpcId"),
                        "result": {"ok": False, "error": {
                            "code": "internal",
                            "message": (
                                'history unavailable for session '
                                f'"{sid}": SessionPersistenceCorruptionError: '
                                'stored session failed validation: Error: '
                                'session event at seq 58 message must have '
                                'tool source'
                            ),
                        }},
                    }
                if not sid:
                    stub.session_counter += 1
                    sid = f"session-stub-{stub.session_counter}"
                value = {"sessionId": sid,
                         "agentPreset": req.get("agentPreset")}
            elif endpoint == "session/page":
                sid = (req.get("address") or {}).get("sessionId")
                if sid and str(sid).startswith("session-badhist"):
                    return {
                        "type": "server-response",
                        "rpcId": body.get("rpcId"),
                        "result": {"ok": False, "error": {
                            "code": "internal",
                            "message": (
                                f'history unavailable for session "{sid}": '
                                "SessionPersistenceCorruptionError: stored "
                                "session failed validation"
                            ),
                        }},
                    }
                value = {}
            elif endpoint == "session/prompt":
                value = {"accepted": True}
            elif endpoint == "session/fork":
                stub.session_counter += 1
                value = {"sessionId": f"session-fork-{stub.session_counter}"}
            else:
                value = {}
            return {"type": "server-response", "rpcId": body.get("rpcId"),
                    "result": {"ok": True, "value": value}}

        @self.app.websocket("/api/remote.mux")
        async def mux(ws: WebSocket):
            await ws.accept()
            # remote.mux 协议：先收 open 再推 item；$events 流回 ready 帧。
            # 三条流都 open 过之后回放预置帧并主动关闭（桥在 ConnectionClosed
            # 时返回，TestClient 需要 ASGI 任务完结才能交付流式响应）。
            try:
                while True:
                    raw = await ws.receive_text()
                    try:
                        msg = json.loads(raw)
                    except ValueError:
                        continue
                    if msg.get("type") == "open":
                        sid_open = msg.get("streamId")
                        if sid_open == "events":
                            await ws.send_text(json.dumps({
                                "type": "item", "streamId": "events",
                                "value": {"type": "ready",
                                          "clientId": "stub-client-1"}}))
                        if sid_open == "follow":
                            for frame in stub.mux_frames:
                                await ws.send_text(frame)
                        if sid_open == "events":
                            await ws.close()
                            return
            except (WebSocketDisconnect, RuntimeError):
                return

    def start(self, port: int):
        config = uvicorn.Config(self.app, host="127.0.0.1", port=port,
                                log_level="error")
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        deadline = time.time() + 10
        while not self.server.started and time.time() < deadline:
            time.sleep(0.05)

    def stop(self):
        if self.server is not None:
            self.server.should_exit = True
        if self.thread is not None:
            self.thread.join(timeout=5)


class _FakeProc:
    """Popen stand-in：terminate 时停掉桩服务器。"""

    def __init__(self, stub: _StubHost):
        self.stub = stub
        self.pid = 999999
        self._dead = False

    def poll(self):
        return 0 if self._dead else None

    def terminate(self):
        self._dead = True
        self.stub.stop()

    def wait(self, timeout=None):
        self._dead = True
        return 0

    def kill(self):
        self._dead = True
        self.stub.stop()


class _FakeSpawner:
    """替换 subprocess.Popen：从 cmd 解析 --port，在该端口起桩 host。"""

    def __init__(self):
        self.stubs: list[_StubHost] = []
        self.cmds: list[list[str]] = []

    def __call__(self, cmd, cwd=None, env=None, stdout=None, stderr=None,
                 start_new_session=False):
        self.cmds.append(list(cmd))
        port = int(cmd[cmd.index("--port") + 1])
        stub = _StubHost()
        stub.start(port)
        self.stubs.append(stub)
        # 模拟 web-app boot 后打印官方就绪行（manager 靠它取 launch token）
        if stdout is not None:
            stdout.write(
                f"dsh web: http://127.0.0.1:{port}/?token={stub.token}\n"
                .encode())
            stdout.flush()
        return _FakeProc(stub)


def _make_manager(tmp_path, spawner, persist=None):
    finals = []

    def env_factory(sid, sdir, state):
        return dict(__import__("os").environ)

    def finalize(sid, sdir, state, reason):
        finals.append((sid, reason))

    mgr = dsh_host.DshHostManager(tmp_path, "node", env_factory,
                                  finalize, spawner=spawner, persist=persist)
    mgr._finals = finals  # 测试观察口
    return mgr


# ---------------- 管理器单测 ----------------

class TestManager:
    def test_session_cwd_is_sandbox_workspace(self, tmp_path):
        sdir = tmp_path / "s-ws-0001"
        sdir.mkdir()
        cwd = Path(dsh_host._session_cwd(sdir, {"job_id": JOB}))
        assert cwd == sdir / "workspace"
        assert cwd.is_dir()
        assert cwd.name == "workspace"

    def test_boot_create_prompt(self, tmp_path):
        spawner = _FakeSpawner()
        mgr = _make_manager(tmp_path, spawner)
        sdir = tmp_path / "s-test-0001"
        sdir.mkdir()
        state = {"job_id": JOB}
        dsh_sid = mgr.create_session("s-test-0001", sdir, state)
        assert dsh_sid == "session-stub-1"
        # create 后 prompt：sessionId 被自动注入
        value = mgr.rpc("s-test-0001", sdir, state, "session.prompt",
                        {"mode": "queue",
                         "content": [{"type": "text", "text": "挖"}]})
        assert value == {"accepted": True}
        methods = [m for m, _ in spawner.stubs[0].calls]
        assert methods[0] == "session/list"             # 就绪探测（host.describe 的替身）
        assert "session/create" in methods
        prompt = [p for m, p in spawner.stubs[0].calls
                  if m == "session/prompt"][0]
        assert prompt["sessionId"] == "session-stub-1"
        mgr.rpc("s-test-0001", sdir, {"job_id": JOB, "dsh_session_id": dsh_sid},
                "session.history", {"maxMessages": 200})
        hist = [p for m, p in spawner.stubs[0].calls if m == "session/page"]
        assert hist and hist[0]["address"]["sessionId"] == "session-stub-1"
        assert hist[0]["maxMessages"] == 200
        # fwgraph preset + profile 到达命令行
        cmd = spawner.cmds[0]
        assert "fwgraph-web" in cmd

    def test_history_mints_when_dsh_session_id_missing(self, tmp_path):
        persisted = []

        def persist(sid, sdir, state):
            persisted.append(state.get("dsh_session_id"))

        spawner = _FakeSpawner()
        mgr = _make_manager(tmp_path, spawner, persist=persist)
        sdir = tmp_path / "s-test-emptyid"
        sdir.mkdir()
        state = {"job_id": JOB, "dsh_session_id": ""}
        hist = mgr.rpc("s-test-emptyid", sdir, state, "session.history",
                       {"maxMessages": 10})
        assert hist == {"events": [], "hasMore": False}
        assert state["dsh_session_id"].startswith("session-stub-")
        assert persisted and persisted[-1] == state["dsh_session_id"]

    def test_history_fills_session_id_from_state(self, tmp_path):
        spawner = _FakeSpawner()
        mgr = _make_manager(tmp_path, spawner)
        sdir = tmp_path / "s-test-hist"
        sdir.mkdir()
        state = {"job_id": JOB}
        dsh_sid = mgr.create_session("s-test-hist", sdir, state)
        state["dsh_session_id"] = dsh_sid
        mgr._hosts["s-test-hist"].dsh_session_id = ""
        mgr.rpc("s-test-hist", sdir, state, "session.history",
                {"maxMessages": 10, "sessionId": None})
        hist = [p for m, p in spawner.stubs[0].calls if m == "session/page"]
        assert hist[-1]["address"]["sessionId"] == dsh_sid

    def test_rpc_allowlist(self, tmp_path):
        spawner = _FakeSpawner()
        mgr = _make_manager(tmp_path, spawner)
        sdir = tmp_path / "s-test-0002"
        sdir.mkdir()
        with pytest.raises(dsh_host.DshHostError) as ei:
            mgr.rpc("s-test-0002", sdir, {}, "workspace.delete", {})
        assert ei.value.code == "bad-request"

    def test_fork_follows_new_session(self, tmp_path):
        spawner = _FakeSpawner()
        mgr = _make_manager(tmp_path, spawner)
        sdir = tmp_path / "s-test-0003"
        sdir.mkdir()
        state = {"job_id": JOB}
        mgr.create_session("s-test-0003", sdir, state)
        value = mgr.rpc("s-test-0003", sdir, state, "session.fork",
                        {"atSeq": 3})
        assert value["sessionId"].startswith("session-fork-")
        assert state["dsh_session_id"] == value["sessionId"]

    def test_resume_after_crash(self, tmp_path):
        spawner = _FakeSpawner()
        mgr = _make_manager(tmp_path, spawner)
        sdir = tmp_path / "s-test-0004"
        sdir.mkdir()
        state = {"job_id": JOB}
        dsh_sid = mgr.create_session("s-test-0004", sdir, state)
        state["dsh_session_id"] = dsh_sid
        # 崩溃：杀 host 但不从注册表移除（模拟进程死亡）
        host = mgr._hosts["s-test-0004"]
        host.proc.terminate()
        # ensure 重启并 resume：第二个 stub 收到带 sessionId 的 create
        mgr.ensure("s-test-0004", sdir, state)
        assert len(spawner.stubs) == 2
        creates = [p for m, p in spawner.stubs[1].calls
                   if m == "session/create"]
        assert creates and creates[0]["sessionId"] == dsh_sid

    def test_resume_missing_creates_and_persists(self, tmp_path):
        persisted = []

        def persist(sid, sdir, state):
            persisted.append(state.get("dsh_session_id"))

        spawner = _FakeSpawner()
        mgr = _make_manager(tmp_path, spawner, persist=persist)
        sdir = tmp_path / "s-test-gone"
        sdir.mkdir()
        state = {"job_id": JOB, "dsh_session_id": "session-dead-old"}
        host = mgr.ensure("s-test-gone", sdir, state)
        assert host.dsh_session_id.startswith("session-stub-")
        assert state["dsh_session_id"].startswith("session-stub-")
        assert persisted and persisted[-1] == state["dsh_session_id"]
        hist = mgr.rpc("s-test-gone", sdir, state, "session.history",
                       {"maxMessages": 10})
        assert hist == {"events": [], "hasMore": False}
        payloads = [p for m, p in spawner.stubs[0].calls
                    if m == "session/page"]
        assert payloads and payloads[0]["address"]["sessionId"] == host.dsh_session_id

    def test_resume_corrupt_mints_new_session(self, tmp_path):
        persisted = []

        def persist(sid, sdir, state):
            persisted.append(state.get("dsh_session_id"))

        spawner = _FakeSpawner()
        mgr = _make_manager(tmp_path, spawner, persist=persist)
        sdir = tmp_path / "s-test-corrupt"
        sdir.mkdir()
        state = {"job_id": JOB, "dsh_session_id": "session-corrupt-old"}
        host = mgr.ensure("s-test-corrupt", sdir, state)
        assert host.dsh_session_id.startswith("session-stub-")
        assert state["dsh_session_id"].startswith("session-stub-")
        assert persisted and persisted[-1] == state["dsh_session_id"]

    def test_history_corrupt_returns_empty_and_mints(self, tmp_path):
        persisted = []

        def persist(sid, sdir, state):
            persisted.append(state.get("dsh_session_id"))

        spawner = _FakeSpawner()
        mgr = _make_manager(tmp_path, spawner, persist=persist)
        sdir = tmp_path / "s-test-badhist"
        sdir.mkdir()
        state = {"job_id": JOB}
        mgr.create_session("s-test-badhist", sdir, state)
        mgr._hosts["s-test-badhist"].dsh_session_id = "session-badhist-old"
        state["dsh_session_id"] = "session-badhist-old"
        hist = mgr.rpc("s-test-badhist", sdir, state, "session.history",
                       {"maxMessages": 10})
        assert hist == {"events": [], "hasMore": False}
        assert state["dsh_session_id"].startswith("session-stub-")
        assert state["dsh_session_id"] != "session-badhist-old"
        assert persisted and persisted[-1] == state["dsh_session_id"]

    def test_concurrent_ensure_single_spawn(self, tmp_path):
        spawner = _FakeSpawner()
        mgr = _make_manager(tmp_path, spawner)
        sdir = tmp_path / "s-test-conc"
        sdir.mkdir()
        state = {"job_id": JOB}
        dsh_sid = mgr.create_session("s-test-conc", sdir, state)
        assert state.get("dsh_session_id") == dsh_sid
        mgr._hosts["s-test-conc"].proc.terminate()
        errors = []

        def go():
            try:
                mgr.rpc("s-test-conc", sdir, state, "session.history",
                        {"maxMessages": 1})
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=go) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        # create + 一次重启，不能因 mux/history 并发再开第三个 host
        assert len(spawner.stubs) == 2

    def test_stop_finalize_and_reap(self, tmp_path):
        spawner = _FakeSpawner()
        mgr = _make_manager(tmp_path, spawner)
        sdir = tmp_path / "s-test-0005"
        sdir.mkdir()
        state = {"job_id": JOB}
        mgr.create_session("s-test-0005", sdir, state)
        assert mgr.stop("s-test-0005", sdir, state, reason="stop") is True
        assert ("s-test-0005", "stop") in mgr._finals
        assert mgr.stop("s-test-0005", sdir, state) is False  # 幂等
        # reap：再造一个，把它人为变老
        mgr.create_session("s-test-0005", sdir, state)
        mgr._hosts["s-test-0005"].last_activity = time.monotonic() - 10**9
        reaped = mgr._reap_pass(lambda sid: (sdir, state))
        assert reaped == ["s-test-0005"]
        assert ("s-test-0005", "idle-reap") in mgr._finals

    def test_mux_sse_bridge(self, tmp_path):
        spawner = _FakeSpawner()
        mgr = _make_manager(tmp_path, spawner)
        sdir = tmp_path / "s-test-0006"
        sdir.mkdir()
        state = {"job_id": JOB}
        mgr.create_session("s-test-0006", sdir, state)
        # remote.mux item 帧（follow/control 流）→ 桥翻成旧 0.1.0 method 帧
        spawner.stubs[0].mux_frames = [
            json.dumps({"type": "item", "streamId": "follow", "value": {
                "type": "event",
                "event": {"seq": 1, "type": "user/message",
                          "data": {"text": "hi"}}}}),
            json.dumps({"type": "item", "streamId": "control", "value": {
                "type": "queue", "sessionId": "session-stub-1", "items": []}}),
        ]

        async def collect():
            out = []
            async for chunk in mgr.mux_sse("s-test-0006", sdir, state):
                out.append(chunk)
                if len(out) >= 3:
                    break
            return out

        got = asyncio.run(asyncio.wait_for(collect(), timeout=10))
        first = json.loads(got[0][len("data: "):].strip())
        assert first["method"] == "session/subscribed"
        second = json.loads(got[1][len("data: "):].strip())
        assert second["method"] == "session/event"
        assert second["payload"]["event"]["type"] == "user/message"
        third = json.loads(got[2][len("data: "):].strip())
        assert third["method"] == "session/queue"
        assert third["payload"]["items"] == []

    def test_discard_blocks_ensure(self, tmp_path):
        spawner = _FakeSpawner()
        mgr = _make_manager(tmp_path, spawner)
        sdir = tmp_path / "s-test-gone"
        sdir.mkdir()
        state = {"job_id": JOB}
        mgr.create_session("s-test-gone", sdir, state)
        assert mgr.stop("s-test-gone", sdir, state, reason="delete",
                        finalize=False, discard=True) is True
        with pytest.raises(dsh_host.DshHostError) as ei:
            mgr.ensure("s-test-gone", sdir, state)
        assert ei.value.code == "session-not-found"


# ---------------- 端点级 ----------------

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
    monkeypatch.setenv("ORCH_TOKEN", LEGACY)
    vulnagent_home = tmp_path / "vulnagent"
    (vulnagent_home / "sessions").mkdir(parents=True)
    (vulnagent_home / "findings").mkdir(parents=True)
    monkeypatch.setattr(vulnagent_api, "VULNAGENT_HOME", vulnagent_home)
    accounts.create_user("admin", "admin-pass-1", role="admin")
    accounts.create_user("bob", "bob-pass-123", role="user")
    # job 满足图谱+攻击面门禁
    ext = tmp_path / "cbm" / JOB
    ext.mkdir(parents=True, exist_ok=True)
    (ext / "graph_done.json").write_text("{}", encoding="utf-8")
    atk = tmp_path / "attack" / JOB
    atk.mkdir(parents=True, exist_ok=True)
    (atk / "attack_done.json").write_text("{}", encoding="utf-8")
    spawner = _FakeSpawner()
    mgr = dsh_host.DshHostManager(tmp_path, "node", vulnagent_api._dsh_env,
                                  vulnagent_api._dsh_finalize,
                                  spawner=spawner)
    mgr._spawner = spawner  # 测试观察口
    monkeypatch.setattr(vulnagent_api, "_dsh_manager", mgr)
    yield TestClient(main.app)
    for stub in spawner.stubs:
        stub.stop()


def _legacy():
    return {"Authorization": f"Bearer {LEGACY}"}


def _wait_host(sid, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        mgr = vulnagent_api._dsh_manager
        if mgr is not None:
            host = mgr._hosts.get(sid)
            if host is not None and host.dsh_session_id:
                return host
        time.sleep(0.02)
    raise AssertionError(f"host {sid} did not boot")


def _start(http, headers=None, **kw):
    payload = {"task": kw.pop("task", "挖"), "job_id": kw.pop("job_id", JOB),
               **kw}
    resp = http.post("/vulnagent/sessions", headers=headers or _legacy(),
                     json=payload)
    assert resp.status_code == 202, resp.text
    sid = resp.json()["session_id"]
    _wait_host(sid)
    return sid


def _bob(http):
    resp = http.post("/auth/login",
                     json={"username": "bob", "password": "bob-pass-123"})
    return {"Authorization": f"Bearer {resp.json()['token']}"}


class TestSessionEndpoints:
    def test_dsh_env_injects_tls_ca(self, tmp_path, monkeypatch):
        cert = tmp_path / "tls" / "cert.pem"
        cert.parent.mkdir()
        cert.write_text("dummy-cert", encoding="utf-8")
        monkeypatch.setattr(vulnagent_api, "_data_dir", lambda: tmp_path)
        monkeypatch.setattr(vulnagent_api, "_vulnagent_env", lambda: {})
        env = vulnagent_api._dsh_env("s-ca-test", tmp_path, {"job_id": JOB})
        assert env["NODE_EXTRA_CA_CERTS"] == str(cert)
        assert env["FWGRAPH_EXTRACTED_ROOT"] == str(tmp_path / "extracted")
        assert env["FWGRAPH_APPROVAL"] == "auto"
        env_ask = vulnagent_api._dsh_env(
            "s-ca-test", tmp_path, {"job_id": JOB, "approval_policy": "ask"})
        assert env_ask["FWGRAPH_APPROVAL"] == "1"

    def test_create_202_and_shape(self, client):
        resp = client.post("/vulnagent/sessions", headers=_legacy(),
                           json={"task": "挖 verified 路径", "job_id": JOB,
                                 "mode": "dynamic", "max_turns": 20})
        assert resp.status_code == 202
        body = resp.json()
        assert body["engine"] == "dsh-web"
        assert "session_id" in body
        sid = body["session_id"]
        host = _wait_host(sid)
        assert host.dsh_session_id == "session-stub-1"
        state = json.loads(
            (vulnagent_api.VULNAGENT_HOME / "sessions" / sid
             / "state.json").read_text())
        assert state["engine"] == "dsh-web"
        assert state["dsh_session_id"] == "session-stub-1"
        assert state.get("approval_policy") == "auto"
        assert state["turns"] == 1
        assert state["max_turns"] == 20

    def test_rpc_endpoint_passthrough_and_auth(self, client):
        sid = _start(client)
        # 无 token 401
        assert client.post(f"/vulnagent/sessions/{sid}/rpc/session.list",
                           json={}).status_code == 401
        # 白名单外 400
        resp = client.post(f"/vulnagent/sessions/{sid}/rpc/workspace.delete",
                           headers=_legacy(), json={})
        assert resp.status_code == 400
        # 正常透传
        resp = client.post(f"/vulnagent/sessions/{sid}/rpc/session.history",
                           headers=_legacy(), json={"maxMessages": 10})
        assert resp.status_code == 200

    def test_history_from_sse_when_host_idle(self, client):
        sid = "s-diskhist-0001"
        sdir = vulnagent_api.VULNAGENT_HOME / "sessions" / sid
        sdir.mkdir(parents=True)
        (sdir / "state.json").write_text(json.dumps({
            "session_id": sid, "status": "done", "owner": "admin",
            "job_id": JOB, "turns": 2, "max_turns": 80,
            "findings": [], "created_at": "t0", "updated_at": "t1",
        }), encoding="utf-8")
        (sdir / "events.sse").write_text(
            "event: session_start\n"
            "data: {\"seq\":0,\"task\":\"挖洞任务\"}\n\n"
            "event: thinking\n"
            "data: {\"seq\":1,\"text\":\"hmm\",\"stream\":true,\"block\":0}\n\n"
            "event: text\n"
            "data: {\"seq\":2,\"text\":\"你好\",\"stream\":false,\"block\":0}\n\n"
            "event: tool_call\n"
            "data: {\"seq\":3,\"id\":\"c1\",\"name\":\"fw_search\","
            "\"input\":{\"pattern\":\"x\"}}\n\n"
            "event: tool_result\n"
            "data: {\"seq\":4,\"id\":\"c1\",\"name\":\"fw_search\","
            "\"is_error\":false,\"preview\":\"{}\"}\n\n",
            encoding="utf-8")
        resp = client.post(
            f"/vulnagent/sessions/{sid}/rpc/session.history",
            headers=_legacy(), json={"maxMessages": 50})
        assert resp.status_code == 200
        body = resp.json()
        assert body.get("source") == "sse"
        types = [e["event"]["type"] for e in body["events"]]
        assert "user/message" in types
        assert "assistant/chunk" in types
        assert "tool/call" in types
        assert "tool/result" in types
        texts = [
            ((e["event"].get("data") or {}).get("chunk") or {}).get("text")
            for e in body["events"]
        ]
        assert "你好" in texts
        assert "hmm" not in texts
        assert sid not in vulnagent_api._dsh_manager._hosts

    def test_mux_idle_when_session_done(self, client):
        sid = "s-diskhist-0002"
        sdir = vulnagent_api.VULNAGENT_HOME / "sessions" / sid
        sdir.mkdir(parents=True)
        (sdir / "state.json").write_text(json.dumps({
            "session_id": sid, "status": "done", "owner": "admin",
            "job_id": JOB, "turns": 1, "max_turns": 80,
            "findings": [], "created_at": "t0", "updated_at": "t1",
        }), encoding="utf-8")
        with client.stream("GET", f"/vulnagent/sessions/{sid}/mux",
                           headers=_legacy()) as resp:
            assert resp.status_code == 200
            text = "".join(resp.iter_text())
        assert "idle" in text
        assert sid not in vulnagent_api._dsh_manager._hosts

    def test_rpc_404_for_others(self, client):
        sid = _start(client)
        bob = _bob(client)
        assert client.post(f"/vulnagent/sessions/{sid}/rpc/session.history",
                           headers=bob, json={}).status_code == 404
        assert client.get(f"/vulnagent/sessions/{sid}/mux",
                          headers=bob).status_code == 404

    def test_mux_streams_sse(self, client):
        sid = _start(client)
        mgr = vulnagent_api._dsh_manager
        # 0.1.1+ remote.mux item 帧 → 桥翻成旧 session/event method 帧
        frame = json.dumps({"type": "item", "streamId": "follow", "value": {
            "type": "event",
            "event": {"seq": 1, "type": "user/message",
                      "data": {"text": "hi"}}}})
        mgr._hosts[sid]  # host 已注册
        # 找到该 sid 的 stub 并预置帧
        for stub in mgr._spawner.stubs:
            stub.mux_frames = [frame]
        with client.stream("GET", f"/vulnagent/sessions/{sid}/mux",
                           headers=_legacy()) as resp:
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith(
                "text/event-stream")
            for line in resp.iter_lines():
                if line.startswith("data: "):
                    parsed = json.loads(line[6:])
                    if parsed["method"] == "session/subscribed":
                        continue
                    assert parsed["method"] == "session/event"
                    assert parsed["payload"]["event"]["type"] == \
                        "user/message"
                    break

    def test_prompt_charges_turns_then_409_at_cap(self, client):
        sid = _start(client, max_turns=2)
        sdir = vulnagent_api.VULNAGENT_HOME / "sessions" / sid
        state = json.loads((sdir / "state.json").read_text())
        assert state["turns"] == 1
        body = {"mode": "queue",
                "content": [{"type": "text", "text": "续"}]}
        ok = client.post(f"/vulnagent/sessions/{sid}/rpc/session.prompt",
                         headers=_legacy(), json=body)
        assert ok.status_code == 200, ok.text
        state = json.loads((sdir / "state.json").read_text())
        assert state["turns"] == 2
        capped = client.post(f"/vulnagent/sessions/{sid}/rpc/session.prompt",
                             headers=_legacy(), json=body)
        assert capped.status_code == 409
        detail = capped.json()["detail"]
        assert "max_turns" in detail
        state = json.loads((sdir / "state.json").read_text())
        assert state["status"] == "awaiting_continue"
        cont = client.post(f"/vulnagent/sessions/{sid}/continue",
                           headers=_legacy(), json={"extra_turns": 2})
        assert cont.status_code == 200, cont.text
        body = cont.json()
        assert body["status"] == "running"
        assert body["max_turns"] == 4
        state = json.loads((sdir / "state.json").read_text())
        assert state["status"] == "running"
        assert state["turns"] == 3

    def test_prompt_on_done_409_resume_revives(self, client):
        sid = _start(client)
        assert client.post(f"/vulnagent/sessions/{sid}/stop",
                           headers=_legacy()).status_code == 200
        body = {"mode": "queue",
                "content": [{"type": "text", "text": "继续"}]}
        blocked = client.post(f"/vulnagent/sessions/{sid}/rpc/session.prompt",
                              headers=_legacy(), json=body)
        assert blocked.status_code == 409
        assert "finished" in blocked.text
        rec = client.post(f"/vulnagent/sessions/{sid}/resume",
                          headers=_legacy(), json={"message": "继续"})
        assert rec.status_code == 200, rec.text
        assert rec.json()["status"] == "running"
        sdir = vulnagent_api.VULNAGENT_HOME / "sessions" / sid
        state = json.loads((sdir / "state.json").read_text())
        assert state["status"] == "running"
        assert client.post(f"/vulnagent/sessions/{sid}/rpc/session.prompt",
                           headers=_legacy(), json=body).status_code == 200

    def test_stop_blocks_ensure_when_done(self, client):
        sid = _start(client)
        assert client.post(f"/vulnagent/sessions/{sid}/stop",
                           headers=_legacy()).status_code == 200
        sdir = vulnagent_api.VULNAGENT_HOME / "sessions" / sid
        state = json.loads((sdir / "state.json").read_text())
        with pytest.raises(dsh_host.DshHostError) as ei:
            vulnagent_api._dsh_manager.ensure(sid, sdir, state)
        assert ei.value.code == "session-not-found"

    def test_stop_finalize(self, client):
        sid = _start(client)
        resp = client.post(f"/vulnagent/sessions/{sid}/stop",
                           headers=_legacy())
        assert resp.status_code == 200
        sdir = vulnagent_api.VULNAGENT_HOME / "sessions" / sid
        state = json.loads((sdir / "state.json").read_text())
        assert state["status"] == "done"
        events = (sdir / "events.sse").read_text(encoding="utf-8")
        assert "event: session_end" in events
        # 再 stop：host 已死 → 落旧路径 → 409
        assert client.post(f"/vulnagent/sessions/{sid}/stop",
                           headers=_legacy()).status_code == 409

    def test_delete_session(self, client):
        sid = _start(client)
        sdir = vulnagent_api.VULNAGENT_HOME / "sessions" / sid
        assert sdir.is_dir()
        resp = client.delete(f"/vulnagent/sessions/{sid}", headers=_legacy())
        assert resp.status_code == 200
        assert resp.json()["status"] == "deleted"
        assert not sdir.exists()
        assert client.get(f"/vulnagent/sessions/{sid}",
                          headers=_legacy()).status_code == 404
        assert client.delete(f"/vulnagent/sessions/{sid}",
                             headers=_legacy()).status_code == 404
        # mux/history 不得把已删会话的 host 再拉起来
        with pytest.raises(Exception):
            vulnagent_api._dsh_manager.ensure(sid, sdir, {})

    def test_archive_and_purge(self, client):
        sid = _start(client)
        listed = client.get("/vulnagent/sessions", headers=_legacy()).json()
        row = next(s for s in listed if s["session_id"] == sid)
        assert row["archived"] is False
        resp = client.patch(f"/vulnagent/sessions/{sid}", headers=_legacy(),
                            json={"archived": True})
        assert resp.status_code == 200, resp.text
        assert resp.json()["archived"] is True
        listed = client.get("/vulnagent/sessions", headers=_legacy()).json()
        row = next(s for s in listed if s["session_id"] == sid)
        assert row["archived"] is True
        sdir = vulnagent_api.VULNAGENT_HOME / "sessions" / sid
        assert sdir.is_dir()
        purged = client.post("/vulnagent/sessions/purge-archived",
                             headers=_legacy())
        assert purged.status_code == 200, purged.text
        assert sid in purged.json()["deleted"]
        assert not sdir.exists()

    def test_respond_forwards_approval_payload(self, client):
        sid = _start(client)
        body = {
            "type": "client-response",
            "rpcId": "rpc-approval-1",
            "result": {
                "ok": True,
                "value": {
                    "sessionId": "session-stub-1",
                    "approvalId": "ap-1",
                    "outcome": "allowed-once",
                },
            },
        }
        resp = client.post(f"/vulnagent/sessions/{sid}/respond",
                           headers=_legacy(), json=body)
        assert resp.status_code == 200, resp.text
        assert resp.json().get("accepted") is True
        stub = vulnagent_api._dsh_manager._spawner.stubs[-1]
        assert stub.responds
        # 0.1.1+：转发到 /api/$events/result，args 携带 outcome
        got = stub.responds[-1]
        assert got["eventId"] == "rpc-approval-1"
        assert got["outcome"]["kind"] == "result"
        assert got["outcome"]["value"] == "allowed-once"
