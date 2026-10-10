import json
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi import HTTPException
from orchestrator.app import vulnagent_api as va, dsh_host
from orchestrator.tests.test_vulnagent_dsh_host import client, _legacy, _start, _wait_host, _bob, JOB


def test_session_list_scans_findings_once_and_keeps_owner_filter(client, monkeypatch):
    for sid, owner in [("s-readonce-0001", "admin"), ("s-readonce-0002", "bob")]:
        directory = va.VULNAGENT_HOME / "sessions" / sid
        directory.mkdir()
        (directory / "state.json").write_text(json.dumps({"session_id": sid, "owner": owner, "status": "done"}))
        (va.VULNAGENT_HOME / "findings" / f"F-{sid}.json").write_text(json.dumps({"id": f"F-{sid}", "session_id": sid}))
    counts = Counter()
    original = Path.read_text
    def read(path, *args, **kwargs):
        if path.parent.name == "findings": counts[path.name] += 1
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "read_text", read)
    response = client.get("/vulnagent/sessions", headers=_bob(client))
    assert response.status_code == 200
    rows = response.json()
    assert [r["session_id"] for r in rows] == ["s-readonce-0002"]
    assert rows[0]["findings"] == ["F-s-readonce-0002"]
    assert counts == {"F-s-readonce-0001.json": 1, "F-s-readonce-0002.json": 1}


def test_parallel_starts_cannot_overbook_last_slot(client, monkeypatch):
    monkeypatch.setattr(va, "MAX_PARALLEL", 1)
    monkeypatch.setattr(va, "_ensure_autopilot", lambda sid: None)
    original = va._new_sid
    def slow_sid():
        time.sleep(.05)
        return original()
    monkeypatch.setattr(va, "_new_sid", slow_sid)
    def start():
        return client.post("/vulnagent/sessions", headers=_legacy(), json={"task": "concurrency test", "job_id": JOB})
    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda _: start(), range(2)))
    assert sorted(r.status_code for r in responses) == [202, 409]
    _wait_host(next(r.json()["session_id"] for r in responses if r.status_code == 202))


def test_failed_first_prompt_does_not_leave_session_running(client, monkeypatch):
    monkeypatch.setattr(va, "_ensure_autopilot", lambda sid: None)
    manager = va._manager()
    original = manager.rpc
    def rpc(sid, directory, state, method, payload):
        if method == "session.prompt": raise dsh_host.DshHostError("test prompt failed", code="internal")
        return original(sid, directory, state, method, payload)
    monkeypatch.setattr(manager, "rpc", rpc)
    response = client.post("/vulnagent/sessions", headers=_legacy(), json={"task": "failure test", "job_id": JOB})
    assert response.status_code == 202
    sid = response.json()["session_id"]
    deadline = time.monotonic() + 5
    directory = va.VULNAGENT_HOME / "sessions" / sid
    while time.monotonic() < deadline:
        state = va._read_state(directory)
        if state.get("status") == "error": break
        time.sleep(.02)
    assert state["status"] == "error"
    assert "test prompt failed" in state["error"]


def test_resume_restarts_autopilot_and_respects_parallel_cap(client, monkeypatch):
    monkeypatch.setattr(va, "_ensure_autopilot", lambda sid: None)
    sid = _start(client)
    _wait_host(sid)
    directory = va.VULNAGENT_HOME / "sessions" / sid
    state = va._read_state(directory)
    state["status"] = "done"
    va._save_state(directory, state)
    monkeypatch.setattr(va, "MAX_PARALLEL", 1)
    monkeypatch.setattr(va, "_live_sessions", lambda: ["s-other-0001"])
    response = client.post(f"/vulnagent/sessions/{sid}/resume", headers=_legacy(), json={"message": "continue"})
    assert response.status_code == 409
    assert va._read_state(directory)["status"] == "done"
    monkeypatch.setattr(va, "_live_sessions", lambda: [])
    restarted = []
    monkeypatch.setattr(va, "_ensure_autopilot", restarted.append)
    response = client.post(f"/vulnagent/sessions/{sid}/resume", headers=_legacy(), json={"message": "continue"})
    assert response.status_code == 200
    assert restarted == [sid]
