"""emulagent_api 会话端点测试：离线 history 回放 / host_alive / mux 防冷启。

模拟会话的 events.sse 与挖掘会话同构（plugin-events 写入），宿主不在时
rpc/session.history 必须离线回放，绝不为看历史冷启 Node 宿主。
"""

import json
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from orchestrator.app import accounts, emulagent_api, main
from orchestrator.app import vulnagent_api

LEGACY = "orch-test-token"
JOB = "abcdef012345"

_EVENTS_SSE = """event: session_start
data: {"seq":1,"ts":"2026-09-18T01:00:00Z","task":"拉起 httpd","agent_id":"fw-emul (dsh-web)"}

event: tool_call
data: {"seq":2,"ts":"2026-09-18T01:00:05Z","id":"call_1","name":"fw_emul_build","input":{"budget_gb":20}}

event: tool_result
data: {"seq":3,"ts":"2026-09-18T01:00:09Z","id":"call_1","name":"fw_emul_build","preview":"{\\"env_id\\":\\"emul-x\\"}","is_error":false}

event: session_end
data: {"seq":4,"ts":"2026-09-18T01:00:10Z","reason":"completed"}

"""


def _dead_pid() -> int:
    p = subprocess.Popen(["true"])
    p.wait()
    return p.pid


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
    monkeypatch.setenv("ORCH_TOKEN", LEGACY)
    vulnagent_home = tmp_path / "vulnagent"
    emul_sessions = vulnagent_home / "emul-sessions"
    emul_sessions.mkdir(parents=True)
    monkeypatch.setattr(vulnagent_api, "VULNAGENT_HOME", vulnagent_home)
    monkeypatch.setattr(emulagent_api, "EMUL_SESSIONS_HOME", emul_sessions)
    monkeypatch.setattr(emulagent_api, "_manager_cache", None)
    accounts.create_user("admin", "admin-pass-1", role="admin")
    yield TestClient(main.app)


def _legacy():
    return {"Authorization": f"Bearer {LEGACY}"}


def _session(emul_sessions: Path, sid: str, state: dict,
             events: str | None = None, pid: int | None = None) -> Path:
    d = emul_sessions / sid
    d.mkdir(parents=True, exist_ok=True)
    (d / "state.json").write_text(json.dumps(state), encoding="utf-8")
    if events is not None:
        (d / "events.sse").write_text(events, encoding="utf-8")
    if pid is not None:
        (d / "runner.pid").write_text(str(pid), encoding="utf-8")
    return d


class TestOfflineHistory:
    def test_history_replays_sse_without_host(self, client, tmp_path):
        sid = "e-aaaaaaaa-bbbbcccc"
        _session(emulagent_api.EMUL_SESSIONS_HOME, sid,
                 {"session_id": sid, "status": "done", "owner": "admin",
                  "job_id": JOB, "task": "拉起 httpd"},
                 events=_EVENTS_SSE)
        resp = client.post(f"/emulagent/sessions/{sid}/rpc/session.history",
                           headers=_legacy(), json={"maxMessages": 200})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["source"] == "sse"
        types = [e["event"]["type"] for e in body["events"]]
        assert types[0] == "user/message"
        assert "tool/call" in types and "tool/result" in types
        assert types[-1] == "turn/end"
        # 原始事件时间透传给前端
        first = body["events"][0]["event"]["data"]
        assert first["ts"] == "2026-09-18T01:00:00Z"
        call = next(e["event"]["data"] for e in body["events"]
                    if e["event"]["type"] == "tool/call")
        assert call["callId"] == "call_1"
        assert call["name"] == "fw_emul_build"
        assert call["ts"] == "2026-09-18T01:00:05Z"

    def test_history_running_without_host_replays_too(self, client):
        """失联会话（running 但宿主死）看历史同样不拉宿主。"""
        sid = "e-zombie-0000-deadbeef"
        _session(emulagent_api.EMUL_SESSIONS_HOME, sid,
                 {"session_id": sid, "status": "running", "owner": "admin",
                  "job_id": JOB},
                 events=_EVENTS_SSE, pid=_dead_pid())
        resp = client.post(f"/emulagent/sessions/{sid}/rpc/session.history",
                           headers=_legacy(), json={})
        assert resp.status_code == 200
        assert resp.json()["source"] == "sse"


class TestHostAlive:
    def test_summary_flags_zombie(self, client):
        sid = "e-zombie-1111-11112222"
        _session(emulagent_api.EMUL_SESSIONS_HOME, sid,
                 {"session_id": sid, "status": "running", "owner": "admin"},
                 pid=_dead_pid())
        resp = client.get(f"/emulagent/sessions/{sid}", headers=_legacy())
        assert resp.status_code == 200
        assert resp.json()["host_alive"] is False

    def test_summary_live_host(self, client, monkeypatch):
        sid = "e-live-2222-33334444"
        _session(emulagent_api.EMUL_SESSIONS_HOME, sid,
                 {"session_id": sid, "status": "running", "owner": "admin"},
                 pid=_dead_pid())

        class _StubMgr:
            def is_live(self, s):
                return s == sid

        monkeypatch.setattr(emulagent_api, "_manager_cache", _StubMgr())
        resp = client.get(f"/emulagent/sessions/{sid}", headers=_legacy())
        assert resp.json()["host_alive"] is True

    def test_done_session_defaults_alive(self, client):
        sid = "e-done-3333-55556666"
        _session(emulagent_api.EMUL_SESSIONS_HOME, sid,
                 {"session_id": sid, "status": "done", "owner": "admin"})
        resp = client.get(f"/emulagent/sessions/{sid}", headers=_legacy())
        assert resp.json()["host_alive"] is True


class TestMux:
    def test_mux_idle_for_zombie_without_spawning(self, client, monkeypatch):
        """失联会话的 mux 必须直接回空闲流，禁止借 ensure 冷启宿主。"""
        sid = "e-zombie-4444-77778888"
        _session(emulagent_api.EMUL_SESSIONS_HOME, sid,
                 {"session_id": sid, "status": "running", "owner": "admin"},
                 pid=_dead_pid())

        class _NoSpawn:
            def __init__(self, *a, **k):
                raise AssertionError("mux 不应为失联会话构造 DshHostManager")

        monkeypatch.setattr(
            "orchestrator.app.dsh_host.DshHostManager", _NoSpawn)
        with client.stream("GET", f"/emulagent/sessions/{sid}/mux",
                           headers=_legacy()) as resp:
            assert resp.status_code == 200
            body = b"".join(resp.iter_bytes()).decode()
        assert "idle" in body

    def test_mux_idle_for_done_session(self, client):
        sid = "e-done-5555-9999aaaa"
        _session(emulagent_api.EMUL_SESSIONS_HOME, sid,
                 {"session_id": sid, "status": "done", "owner": "admin"})
        with client.stream("GET", f"/emulagent/sessions/{sid}/mux",
                           headers=_legacy()) as resp:
            body = b"".join(resp.iter_bytes()).decode()
        assert "idle" in body


class TestStopZombie:
    def test_stop_marks_done_without_host(self, client):
        sid = "e-zombie-6666-bbbbcccc"
        _session(emulagent_api.EMUL_SESSIONS_HOME, sid,
                 {"session_id": sid, "status": "running", "owner": "admin",
                  "job_id": JOB, "task": "t"},
                 pid=_dead_pid())
        resp = client.post(f"/emulagent/sessions/{sid}/stop",
                           headers=_legacy())
        assert resp.status_code == 200, resp.text
        state = json.loads(
            (emulagent_api.EMUL_SESSIONS_HOME / sid
             / "state.json").read_text())
        assert state["status"] == "done"
