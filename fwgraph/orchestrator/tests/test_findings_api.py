"""Tests for the server-validated findings API (POST/PATCH /vulnagent/
findings), findings/session/report owner filtering, and the session-start
gate.

Isolation: temp FWGRAPH_DATA + VULNAGENT_HOME, ORCH_TOKEN legacy admin plus
session-token users bob/carol. The seeded job owns a manifest
(data/extracted), a symbols.json (data/pseudocode) and one trace
(data/traces) so every validation branch can be exercised.
"""

import json
import time

import pytest
from fastapi.testclient import TestClient

from orchestrator.app import accounts, main, vulnagent_api

LEGACY = "orch-test-token"
JOB = "abcdef012345"
MD5 = "03c6e3b4312c0a8c855cb9298c90dc32"
TRACE = "0123456789ab"
ADDR = "0x108d8"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
    monkeypatch.setenv("ORCH_TOKEN", LEGACY)
    vulnagent_home = tmp_path / "vulnagent"
    (vulnagent_home / "sessions").mkdir(parents=True)
    (vulnagent_home / "findings").mkdir(parents=True)
    monkeypatch.setenv("VULNAGENT_HOME", str(vulnagent_home))
    monkeypatch.setattr(vulnagent_api, "VULNAGENT_HOME", vulnagent_home)
    accounts.create_user("admin", "admin-pass-1", role="admin")
    accounts.create_user("bob", "bob-pass-123", role="user")
    accounts.create_user("carol", "carol-pass-1", role="user")
    _seed_job(tmp_path, owner="bob")
    yield TestClient(main.app)
    with main._jobs_lock:
        main._jobs.pop(JOB, None)


def _seed_job(tmp_path, owner="bob"):
    job = {"job_id": JOB, "firmware": "mx12.bin", "status": "routed",
           "error": None, "created_at": "t0", "updated_at": "t0",
           "size_bytes": 1, "owner": owner}
    with main._jobs_lock:
        main._jobs[JOB] = job
    job_dir = tmp_path / "firmware" / JOB
    job_dir.mkdir(parents=True, exist_ok=True)
    (job_dir / "job.json").write_text(json.dumps(job), encoding="utf-8")
    ext = tmp_path / "extracted" / JOB
    ext.mkdir(parents=True, exist_ok=True)
    (ext / "manifest.json").write_text(json.dumps({
        "job_id": JOB, "firmware": "mx12.bin",
        "binaries": [{"path": "/bin/httpd", "md5": MD5, "arch": "arm"}],
        "stats": {}}), encoding="utf-8")
    pseudo = tmp_path / "pseudocode" / JOB
    pseudo.mkdir(parents=True, exist_ok=True)
    (pseudo / "symbols.json").write_text(json.dumps({
        "job_id": JOB,
        "binaries": {MD5: {"path": "/bin/httpd", "arch": "arm",
                           "functions": [{"addr": ADDR, "name": "main"},
                                         {"addr": "0x10900",
                                          "name": "handle_req"}]}}}),
        encoding="utf-8")
    tdir = tmp_path / "traces" / JOB / TRACE
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / "trace.json").write_text(json.dumps({"trace_id": TRACE,
                                                 "status": "ok"}),
                                     encoding="utf-8")


def _legacy():
    return {"Authorization": f"Bearer {LEGACY}"}


def _session(http, username, password):
    resp = http.post("/auth/login",
                     json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['token']}"}


def _bob(http):
    return _session(http, "bob", "bob-pass-123")


def _carol(http):
    return _session(http, "carol", "carol-pass-1")


def _payload(**over):
    base = {
        "job_id": JOB,
        "title": "httpd 栈溢出",
        "severity": "high",
        "confidence": 0.5,
        "vuln_class": "栈溢出",
        "cwe": "CWE-120",
        "binary_md5": MD5,
        "binary_path": "/bin/httpd",
        "reachability": "static",
        "summary": "handle_req 中 strcpy 未检查长度",
        "evidence": ["0x108d8 strcpy(dst, src)", "attack path P3"],
        "call_chain": "main@0x108d8 → handle_req@0x10900 → strcpy",
        "poc": "POST /goform/setMac HTTP/1.1\n\nmac=" + "A" * 40,
    }
    base.update(over)
    return base


def _post(http, headers, **over):
    return http.post("/vulnagent/findings", headers=headers, json=_payload(**over))


class TestFindingCreate:
    def test_create_requires_call_chain_and_poc(self, client):
        resp = _post(client, _legacy(), call_chain="", poc="")
        assert resp.status_code == 422
        assert "call_chain" in resp.json()["detail"]
        resp = _post(client, _legacy(), poc="")
        assert resp.status_code == 422
        assert "poc" in resp.json()["detail"]

    def test_create_ok(self, client, tmp_path):
        resp = _post(client, _legacy())
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["id"].startswith("F-")
        assert body["status"] == "draft"
        assert body["owner"] == "token-admin"
        assert body["recorded_at"]
        assert "confidence_reported" not in body
        # persisted: file + index line
        fdir = tmp_path / "vulnagent" / "findings"
        assert (fdir / f"{body['id']}.json").is_file()
        lines = (fdir / "index.jsonl").read_text(encoding="utf-8").splitlines()
        assert json.loads(lines[-1])["id"] == body["id"]
        # audit trail
        audit = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
        assert "finding_create" in audit

    def test_create_requires_auth(self, client):
        assert client.post("/vulnagent/findings",
                           json=_payload()).status_code == 401

    def test_plain_user_can_create(self, client):
        resp = _post(client, _bob(client))
        assert resp.status_code == 201
        assert resp.json()["owner"] == "bob"

    def test_job_must_exist(self, client):
        resp = _post(client, _legacy(), job_id="000000000000")
        assert resp.status_code == 422
        assert "job_id" in resp.json()["detail"]

    def test_job_id_traversal_rejected(self, client):
        resp = _post(client, _legacy(), job_id="../etc")
        assert resp.status_code == 422

    def test_md5_must_be_in_manifest(self, client):
        resp = _post(client, _legacy(), binary_md5="f" * 32)
        assert resp.status_code == 422
        assert "binary_md5" in resp.json()["detail"]

    def test_manifest_missing_422(self, client, tmp_path):
        (tmp_path / "extracted" / JOB / "manifest.json").unlink()
        resp = _post(client, _legacy())
        assert resp.status_code == 422
        assert "binary_md5" in resp.json()["detail"]

    def test_function_addr_checked_against_symbols(self, client):
        resp = _post(client, _legacy(), function_addr="0xdeadbeef")
        assert resp.status_code == 422
        assert "function_addr" in resp.json()["detail"]
        resp = _post(client, _legacy(), function_addr=ADDR)
        assert resp.status_code == 201
        assert resp.json()["function_addr"] == ADDR

    def test_function_addr_symbols_missing_422(self, client, tmp_path):
        (tmp_path / "pseudocode" / JOB / "symbols.json").unlink()
        resp = _post(client, _legacy(), function_addr=ADDR)
        assert resp.status_code == 422
        assert "function_addr" in resp.json()["detail"]

    def test_severity_enum(self, client):
        resp = _post(client, _legacy(), severity="fatal")
        assert resp.status_code == 422
        assert "severity" in resp.json()["detail"]
        for ok in ("critical", "high", "medium", "low", "info"):
            assert _post(client, _legacy(), severity=ok).status_code == 201

    def test_reachability_enum(self, client):
        resp = _post(client, _legacy(), reachability="maybe")
        assert resp.status_code == 422
        assert "reachability" in resp.json()["detail"]

    def test_cwe_strict(self, client):
        for bad in ("CWE-89a", "CWE-89; CWE-787", "cwe-120", "CWE-", "120"):
            resp = _post(client, _legacy(), cwe=bad)
            assert resp.status_code == 422, bad
            assert "cwe" in resp.json()["detail"]
        assert _post(client, _legacy(), cwe="CWE-787").status_code == 201

    def test_vuln_class_no_mixed(self, client):
        for bad in ("栈溢出/命令注入", "栈溢出,命令注入", "栈溢出、命令注入"):
            resp = _post(client, _legacy(), vuln_class=bad)
            assert resp.status_code == 422, bad
            assert "vuln_class" in resp.json()["detail"]

    def test_evidence_non_empty_string_list(self, client):
        for bad in ([], "not-a-list", ["", "x"], ["ok", 3]):
            resp = _post(client, _legacy(), evidence=bad)
            assert resp.status_code == 422, repr(bad)
            assert "evidence" in resp.json()["detail"]

    def test_confidence_range_and_type(self, client):
        for bad in (-0.1, 1.5, "0.5", True):
            resp = _post(client, _legacy(), confidence=bad)
            assert resp.status_code == 422, repr(bad)
            assert "confidence" in resp.json()["detail"]
        assert _post(client, _legacy(), confidence=0).status_code == 201
        assert _post(client, _legacy(), confidence=1).status_code == 201

    def test_static_confidence_capped(self, client):
        resp = _post(client, _legacy(), reachability="static",
                     confidence=0.95)
        assert resp.status_code == 201
        body = resp.json()
        assert body["confidence"] == 0.7
        assert body["confidence_reported"] == 0.95

    def test_static_under_cap_untouched(self, client):
        resp = _post(client, _legacy(), reachability="static",
                     confidence=0.6)
        body = resp.json()
        assert body["confidence"] == 0.6
        assert "confidence_reported" not in body

    def test_observed_requires_trace_id(self, client):
        resp = _post(client, _legacy(), reachability="observed",
                     confidence=0.9)
        assert resp.status_code == 422
        assert "trace_id" in resp.json()["detail"]

    def test_verified_trace_must_exist(self, client):
        resp = _post(client, _legacy(), reachability="verified",
                     confidence=0.9, trace_id="ffffffffffff")
        assert resp.status_code == 422
        assert "trace_id" in resp.json()["detail"]

    def test_observed_with_real_trace_ok(self, client):
        resp = _post(client, _legacy(), reachability="observed",
                     confidence=0.9, trace_id=TRACE)
        assert resp.status_code == 201
        body = resp.json()
        assert body["confidence"] == 0.9  # no cap on dynamic evidence
        assert body["trace_id"] == TRACE

    def test_required_fields(self, client):
        for field in ("title", "summary", "binary_path", "vuln_class"):
            resp = _post(client, _legacy(), **{field: ""})
            assert resp.status_code == 422, field
            assert field in resp.json()["detail"]


class TestFindingPatch:
    def _create(self, client):
        resp = _post(client, _legacy())
        assert resp.status_code == 201
        return resp.json()["id"]

    def test_patch_appends_history(self, client, tmp_path):
        fid = self._create(client)
        resp = client.patch(f"/vulnagent/findings/{fid}", headers=_legacy(),
                            json={"status": "verified", "note": "复现确认"})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "verified"
        assert body["history"][-1]["status"] == "verified"
        assert body["history"][-1]["note"] == "复现确认"
        assert body["history"][-1]["user"] == "token-admin"
        assert body["history"][-1]["ts"]
        # persisted to the finding file and reflected in the index listing
        doc = json.loads((tmp_path / "vulnagent" / "findings"
                          / f"{fid}.json").read_text(encoding="utf-8"))
        assert doc["status"] == "verified" and len(doc["history"]) == 1
        listing = client.get("/vulnagent/findings", headers=_legacy()).json()
        assert listing[0]["id"] == fid
        assert listing[0]["status"] == "verified"
        audit = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
        assert "finding_status" in audit

    def test_patch_bad_status_400(self, client):
        fid = self._create(client)
        resp = client.patch(f"/vulnagent/findings/{fid}", headers=_legacy(),
                            json={"status": "closed"})
        assert resp.status_code == 400

    def test_patch_unknown_404(self, client):
        resp = client.patch("/vulnagent/findings/F-nope-nope",
                            headers=_legacy(), json={"status": "verified"})
        assert resp.status_code == 404

    def test_patch_requires_auth(self, client):
        fid = self._create(client)
        resp = client.patch(f"/vulnagent/findings/{fid}",
                            json={"status": "verified"})
        assert resp.status_code == 401


class TestFindingVisibility:
    """Non-admin sees findings on own jobs only; jobless findings hidden."""

    def _create(self, client, **over):
        resp = _post(client, _legacy(), **over)
        assert resp.status_code == 201
        return resp.json()["id"]

    def test_owner_filter(self, client):
        fid = self._create(client)  # job owned by bob
        bob = _bob(client)
        carol = _carol(client)
        assert [f["id"] for f in
                client.get("/vulnagent/findings", headers=bob).json()] == [fid]
        assert client.get(f"/vulnagent/findings/{fid}",
                          headers=bob).status_code == 200
        assert client.get("/vulnagent/findings", headers=carol).json() == []
        assert client.get(f"/vulnagent/findings/{fid}",
                          headers=carol).status_code == 404
        # admin sees all
        assert client.get(f"/vulnagent/findings/{fid}",
                          headers=_legacy()).status_code == 200

    def test_jobless_finding_hidden_from_users(self, client, tmp_path):
        fdir = tmp_path / "vulnagent" / "findings"
        orphan = {"id": "F-orphan-01", "title": "无 job 关联",
                  "severity": "info", "recorded_at": "t"}
        (fdir / "F-orphan-01.json").write_text(json.dumps(orphan),
                                               encoding="utf-8")
        with open(fdir / "index.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(orphan) + "\n")
        assert client.get("/vulnagent/findings/F-orphan-01",
                          headers=_bob(client)).status_code == 404
        assert client.get("/vulnagent/findings/F-orphan-01",
                          headers=_legacy()).status_code == 200

    def test_unknown_job_hidden_from_users(self, client, tmp_path):
        fdir = tmp_path / "vulnagent" / "findings"
        ghost = {"id": "F-ghost-01", "title": "x", "severity": "info",
                 "job_id": "000000000000", "recorded_at": "t"}
        (fdir / "F-ghost-01.json").write_text(json.dumps(ghost),
                                              encoding="utf-8")
        assert client.get("/vulnagent/findings/F-ghost-01",
                          headers=_bob(client)).status_code == 404
        assert client.get("/vulnagent/findings/F-ghost-01",
                          headers=_legacy()).status_code == 200

    def test_legacy_job_without_owner_visible(self, client, tmp_path):
        # pre-ownership jobs (no owner field) stay visible to everyone
        with main._jobs_lock:
            main._jobs[JOB].pop("owner", None)
        fid = self._create(client)
        assert client.get(f"/vulnagent/findings/{fid}",
                          headers=_carol(client)).status_code == 200


class TestSessionOwnership:
    def _seed_session(self, tmp_path, sid, owner=None, status="done"):
        sdir = tmp_path / "vulnagent" / "sessions" / sid
        sdir.mkdir(parents=True)
        state = {"session_id": sid, "task": f"task {sid}", "status": status,
                 "turns": 1, "findings": [], "usage": {},
                 "created_at": "2026-01-01T00:00:00Z",
                 "updated_at": "2026-01-01T00:01:00Z"}
        if owner is not None:
            state["owner"] = owner
        (sdir / "state.json").write_text(json.dumps(state), encoding="utf-8")
        (sdir / "report.md").write_text(f"# report {sid}", encoding="utf-8")
        return sdir

    def test_list_filtered(self, client, tmp_path):
        self._seed_session(tmp_path, "s-aaa-0001", owner="bob")
        self._seed_session(tmp_path, "s-bbb-0002", owner="carol")
        self._seed_session(tmp_path, "s-ccc-0003")  # legacy -> admin
        bob = _bob(client)
        ids = [s["session_id"] for s in
               client.get("/vulnagent/sessions", headers=bob).json()]
        assert ids == ["s-aaa-0001"]
        ids = [s["session_id"] for s in
               client.get("/vulnagent/sessions", headers=_legacy()).json()]
        assert sorted(ids) == ["s-aaa-0001", "s-bbb-0002", "s-ccc-0003"]

    def test_get_stop_report_events_404_for_others(self, client, tmp_path):
        self._seed_session(tmp_path, "s-bbb-0002", owner="carol")
        bob = _bob(client)
        assert client.get("/vulnagent/sessions/s-bbb-0002",
                          headers=bob).status_code == 404
        assert client.get("/vulnagent/sessions/s-bbb-0002/report",
                          headers=bob).status_code == 404
        assert client.post("/vulnagent/sessions/s-bbb-0002/stop",
                           headers=bob).status_code == 404
        assert client.delete("/vulnagent/sessions/s-bbb-0002",
                             headers=bob).status_code == 404
        assert client.get("/vulnagent/sessions/s-bbb-0002/events?follow=0",
                          headers=bob).status_code == 404
        # the owner herself gets through
        carol = _carol(client)
        assert client.get("/vulnagent/sessions/s-bbb-0002",
                          headers=carol).status_code == 200
        assert client.get("/vulnagent/sessions/s-bbb-0002/report",
                          headers=carol).status_code == 200
        # not running -> stop is a 409, not a 404
        assert client.post("/vulnagent/sessions/s-bbb-0002/stop",
                           headers=carol).status_code == 409
        assert client.delete("/vulnagent/sessions/s-bbb-0002",
                             headers=carol).status_code == 200
        assert client.get("/vulnagent/sessions/s-bbb-0002",
                          headers=carol).status_code == 404

    def test_get_session_lists_live_findings(self, client, tmp_path):
        sid = "s-live-0001"
        self._seed_session(tmp_path, sid, owner="bob", status="running")
        fdir = tmp_path / "vulnagent" / "findings"
        fid = "F-abc123-dead"
        (fdir / f"{fid}.json").write_text(json.dumps({
            "id": fid, "session_id": sid, "job_id": JOB,
            "title": "live finding", "status": "draft",
        }), encoding="utf-8")
        body = client.get(f"/vulnagent/sessions/{sid}",
                          headers=_bob(client)).json()
        assert fid in body["findings"]
        assert body["finding_objects"][0]["id"] == fid

    def test_legacy_session_is_admin_owned(self, client, tmp_path):
        self._seed_session(tmp_path, "s-old-0004")  # no owner field
        assert client.get("/vulnagent/sessions/s-old-0004",
                          headers=_bob(client)).status_code == 404
        assert client.get("/vulnagent/sessions/s-old-0004",
                          headers=_legacy()).status_code == 200

    def test_migration_stamps_admin(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
        vulnagent_home = tmp_path / "vulnagent"
        monkeypatch.setattr(vulnagent_api, "VULNAGENT_HOME", vulnagent_home)
        sdir = vulnagent_home / "sessions" / "s-mig-0005"
        sdir.mkdir(parents=True)
        (sdir / "state.json").write_text(json.dumps(
            {"session_id": "s-mig-0005", "status": "done"}),
            encoding="utf-8")
        vulnagent_api._migrate_legacy_owners()
        state = json.loads((sdir / "state.json").read_text())
        assert state["owner"] == "admin"
        # idempotent: existing owner untouched
        (sdir / "state.json").write_text(json.dumps(
            {"session_id": "s-mig-0005", "owner": "bob"}), encoding="utf-8")
        vulnagent_api._migrate_legacy_owners()
        assert json.loads((sdir / "state.json").read_text())["owner"] == "bob"


class TestSessionGate:
    def test_no_job_anywhere_400(self, client):
        resp = client.post("/vulnagent/sessions", headers=_legacy(),
                           json={"task": "挖洞"})
        assert resp.status_code == 400
        assert "job_id" in resp.json()["detail"]

    def test_job_without_graph_409(self, client):
        resp = client.post("/vulnagent/sessions", headers=_legacy(),
                           json={"task": "挖洞", "job_id": JOB})
        assert resp.status_code == 409


class _FakeProc:
    """Popen stand-in: wait() blocks on a gate until the test releases it
    (so findings can be seeded before _watch finalizes), then rc=0."""

    def __init__(self, cmd, cwd=None, env=None, stdout=None, stderr=None,
                 start_new_session=False):
        import threading as _th
        self.cmd, self.env = cmd, env
        self.pid = 999999  # (almost) certainly not a live pid
        self._rc = None
        self.gate = _th.Event()

    def poll(self):
        return self._rc

    def wait(self):
        self.gate.wait(5)
        self._rc = 0
        return 0


class TestSpawnDsh:
    def test_owner_max_turns_pid_and_attribution(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
        vulnagent_home = tmp_path / "vulnagent"
        (vulnagent_home / "sessions").mkdir(parents=True)
        (vulnagent_home / "findings").mkdir(parents=True)
        monkeypatch.setattr(vulnagent_api, "VULNAGENT_HOME", vulnagent_home)
        monkeypatch.setattr(vulnagent_api.subprocess, "Popen", _FakeProc)

        sid = "s-test-0001"
        sdir = vulnagent_home / "sessions" / sid
        sdir.mkdir()
        proc = vulnagent_api._spawn_dsh(sid, sdir, "挖洞", mode="dynamic",
                                        job_id=JOB, max_turns=17,
                                        owner="bob")
        # state.json: owner + max_turns recorded synchronously
        state = json.loads((sdir / "state.json").read_text())
        assert state["owner"] == "bob"
        assert state["max_turns"] == 17
        assert state["job_id"] == JOB
        # max_turns + session id reach the harness via env
        assert proc.env["FWGRAPH_MAX_TURNS"] == "17"
        assert proc.env["FWGRAPH_SESSION_ID"] == sid
        assert (sdir / "runner.pid").read_text() == "999999"

        # _watch attributes findings strictly by session_id
        fdir = vulnagent_home / "findings"
        mine = {"id": "F-mine-01", "session_id": sid, "title": "t",
                "severity": "high", "confidence": 0.5, "evidence": ["e"],
                "recorded_at": "2020-01-01T00:00:00Z"}  # old ts: must still count
        other = {"id": "F-othe-01", "session_id": "s-zzz-9999",
                 "title": "t", "recorded_at": "2999-01-01T00:00:00Z"}
        legacy = {"id": "F-lega-01", "title": "t",
                  "recorded_at": "2999-01-01T00:00:00Z"}  # no session_id
        for doc in (mine, other, legacy):
            (fdir / f"{doc['id']}.json").write_text(json.dumps(doc),
                                                    encoding="utf-8")
        proc.gate.set()  # let the fake runner exit; _watch finalizes now
        deadline = time.time() + 5
        while time.time() < deadline:
            state = json.loads((sdir / "state.json").read_text())
            if state.get("status") != "running":
                break
            time.sleep(0.05)
        assert state["status"] == "done"
        assert state["findings"] == ["F-mine-01"]
        assert (sdir / "report.md").is_file()

    def test_report_failure_goes_to_events_and_log(self, tmp_path,
                                                   monkeypatch):
        monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
        vulnagent_home = tmp_path / "vulnagent"
        (vulnagent_home / "sessions").mkdir(parents=True)
        (vulnagent_home / "findings").mkdir(parents=True)
        monkeypatch.setattr(vulnagent_api, "VULNAGENT_HOME", vulnagent_home)
        monkeypatch.setattr(vulnagent_api.subprocess, "Popen", _FakeProc)

        def _boom(sdir, state):
            raise RuntimeError("report exploded")

        monkeypatch.setattr(vulnagent_api, "_write_report", _boom)
        sid = "s-fail-0002"
        sdir = vulnagent_home / "sessions" / sid
        sdir.mkdir()
        proc = vulnagent_api._spawn_dsh(sid, sdir, "挖洞", owner="bob")
        proc.gate.set()
        deadline = time.time() + 5
        while time.time() < deadline:
            state = json.loads((sdir / "state.json").read_text())
            if state.get("status") != "running":
                break
            time.sleep(0.05)
        assert state["status"] == "done"
        assert "report exploded" in (sdir / "runner.log").read_text()
        events = (sdir / "events.sse").read_text(encoding="utf-8")
        assert "event: error" in events and "report exploded" in events


def test_write_report_without_findings(tmp_path, monkeypatch):
    monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
    va = tmp_path / "vulnagent"
    (va / "findings").mkdir(parents=True)
    monkeypatch.setattr(vulnagent_api, "VULNAGENT_HOME", va)
    sdir = va / "sessions" / "s-empty-0001"
    sdir.mkdir(parents=True)
    state = {
        "session_id": "s-empty-0001",
        "task": "挖掘存在的漏洞",
        "mode": "dynamic",
        "job_id": JOB,
        "turns": 6,
        "max_turns": 80,
        "updated_at": "2026-08-24T06:00:00Z",
        "findings": [],
    }
    tdir = tmp_path / "traces" / JOB / TRACE
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / "trace.json").write_text(json.dumps({
        "trace_id": TRACE,
        "status": "ok_empty_diff",
        "request": {"via": "net", "port": 80},
        "diff": {"function_count": 0},
        "error": "",
    }), encoding="utf-8")
    vulnagent_api._write_report(sdir, state)
    text = (sdir / "report.md").read_text(encoding="utf-8")
    assert "本轮没有入库漏洞" in text
    assert "四、漏洞详情" in text
    assert TRACE in text
    assert "ok_empty_diff" in text


def test_session_report_generates_when_missing(client, tmp_path):
    sdir = tmp_path / "vulnagent" / "sessions" / "s-norep-0001"
    sdir.mkdir(parents=True)
    (sdir / "state.json").write_text(json.dumps({
        "session_id": "s-norep-0001",
        "task": "挖洞",
        "status": "running",
        "turns": 2,
        "max_turns": 80,
        "findings": [],
        "usage": {},
        "mode": "dynamic",
        "job_id": JOB,
        "owner": "admin",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:01:00Z",
    }), encoding="utf-8")
    resp = client.get("/vulnagent/sessions/s-norep-0001/report",
                      headers=_legacy())
    assert resp.status_code == 200
    assert "本轮没有入库漏洞" in resp.text
    assert (sdir / "report.md").is_file()
