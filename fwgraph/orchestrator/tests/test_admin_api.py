"""Unit tests for the admin console API: accounts.py + admin_api.py.

A temp FWGRAPH_DATA isolates users.json/sessions.json/audit.jsonl/
settings.json/reports, and VULNAGENT_HOME is pointed at a temp dir so the
dashboard/report aggregation never touches the real deployment. ORCH_TOKEN
is set, so both the legacy token and session tokens get exercised.
"""

import json
import os

import pytest
from fastapi.testclient import TestClient

from orchestrator.app import accounts, admin_api, main, vulnagent_api

LEGACY = "orch-test-token"
JOB = "abcdef012345"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
    monkeypatch.setenv("ORCH_TOKEN", LEGACY)
    vulnagent_home = tmp_path / "vulnagent"
    (vulnagent_home / "sessions").mkdir(parents=True)
    (vulnagent_home / "findings").mkdir(parents=True)
    monkeypatch.setenv("VULNAGENT_HOME", str(vulnagent_home))
    monkeypatch.setattr(vulnagent_api, "VULNAGENT_HOME", vulnagent_home)
    accounts.create_user("admin", "admin-pass", role="admin")
    accounts.create_user("bob", "bob-pass-1", role="user")
    yield TestClient(main.app)
    with main._jobs_lock:
        main._jobs.pop(JOB, None)


def _legacy():
    return {"Authorization": f"Bearer {LEGACY}"}


def _login(http, username, password):
    return http.post("/auth/login",
                     json={"username": username, "password": password})


def _session(http, username, password):
    resp = _login(http, username, password)
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['token']}"}


class TestAuth:
    def test_login_ok(self, client):
        resp = _login(client, "admin", "admin-pass")
        assert resp.status_code == 200
        body = resp.json()
        assert body["token"].startswith("fws-")
        assert body["user"]["username"] == "admin"
        assert body["user"]["role"] == "admin"
        assert "created_at" in body["user"]

    def test_login_wrong_password(self, client):
        resp = _login(client, "admin", "nope")
        assert resp.status_code == 401
        assert "用户名或密码错误" in resp.json()["detail"]

    def test_login_unknown_user(self, client):
        assert _login(client, "ghost", "whatever").status_code == 401

    def test_login_disabled(self, client):
        accounts.update_user("bob", disabled=True)
        assert _login(client, "bob", "bob-pass-1").status_code == 401

    def test_session_token_access(self, client):
        headers = _session(client, "bob", "bob-pass-1")
        resp = client.get("/auth/me", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["username"] == "bob"
        assert resp.json()["legacy"] is False

    def test_legacy_token_still_works(self, client):
        resp = client.get("/auth/me", headers=_legacy())
        assert resp.status_code == 200
        assert resp.json() == {"username": "token-admin", "role": "admin",
                               "legacy": True, "must_change_password": False}

    def test_no_token_401(self, client):
        assert client.get("/auth/me").status_code == 401
        assert client.get("/users").status_code == 401

    def test_logout_revokes_session(self, client):
        headers = _session(client, "bob", "bob-pass-1")
        assert client.post("/auth/logout", headers=headers).json()["ok"]
        assert client.get("/auth/me", headers=headers).status_code == 401

    def test_logout_legacy_noop(self, client):
        resp = client.post("/auth/logout", headers=_legacy())
        assert resp.status_code == 200

    def test_password_change(self, client):
        headers = _session(client, "bob", "bob-pass-1")
        resp = client.post("/auth/password", headers=headers,
                           json={"old_password": "bob-pass-1",
                                 "new_password": "bob-pass-2"})
        assert resp.status_code == 200
        assert _login(client, "bob", "bob-pass-1").status_code == 401
        assert _login(client, "bob", "bob-pass-2").status_code == 200

    def test_password_change_short_rejected(self, client):
        headers = _session(client, "bob", "bob-pass-1")
        resp = client.post("/auth/password", headers=headers,
                           json={"old_password": "bob-pass-1",
                                 "new_password": "short"})
        assert resp.status_code == 400

    def test_password_change_legacy_400(self, client):
        resp = client.post("/auth/password", headers=_legacy(),
                           json={"old_password": "x",
                                 "new_password": "long-enough"})
        assert resp.status_code == 400


class TestUsers:
    def test_crud_flow(self, client):
        resp = client.post("/users", headers=_legacy(),
                           json={"username": "carol", "password": "carol-pass-1",
                                 "role": "user"})
        assert resp.status_code == 201, resp.text
        users = client.get("/users", headers=_legacy()).json()
        carol = [u for u in users if u["username"] == "carol"][0]
        assert carol["role"] == "user" and carol["disabled"] is False
        assert "password_hash" not in carol and "salt" not in carol

        resp = client.patch("/users/carol", headers=_legacy(),
                            json={"role": "admin"})
        assert resp.json()["role"] == "admin"
        resp = client.patch("/users/carol", headers=_legacy(),
                            json={"disabled": True})
        assert resp.json()["disabled"] is True

        resp = client.delete("/users/carol", headers=_legacy())
        assert resp.status_code == 200
        users = client.get("/users", headers=_legacy()).json()
        assert "carol" not in {u["username"] for u in users}

    def test_create_duplicate_409(self, client):
        resp = client.post("/users", headers=_legacy(),
                           json={"username": "bob", "password": "whatever-pw-1",
                                 "role": "user"})
        assert resp.status_code == 409

    def test_create_bad_username_400(self, client):
        resp = client.post("/users", headers=_legacy(),
                           json={"username": "bad name!",
                                 "password": "whatever", "role": "user"})
        assert resp.status_code == 400

    def test_create_bad_role_400(self, client):
        resp = client.post("/users", headers=_legacy(),
                           json={"username": "dave", "password": "whatever",
                                 "role": "root"})
        assert resp.status_code == 400

    def test_last_admin_demote_protected(self, client):
        resp = client.patch("/users/admin", headers=_legacy(),
                            json={"role": "user"})
        assert resp.status_code == 400

    def test_last_admin_delete_protected(self, client):
        resp = client.delete("/users/admin", headers=_legacy())
        assert resp.status_code == 400

    def test_self_disable_protected(self, client):
        headers = _session(client, "admin", "admin-pass")
        resp = client.patch("/users/admin", headers=headers,
                            json={"disabled": True})
        assert resp.status_code == 400

    def test_non_admin_forbidden(self, client):
        headers = _session(client, "bob", "bob-pass-1")
        assert client.get("/users", headers=headers).status_code == 403
        resp = client.put("/system/config", headers=headers,
                          json={"AUTO_FULL": "1"})
        assert resp.status_code == 403


class TestSystemConfig:
    def test_get_config_keys(self, client):
        resp = client.get("/system/config", headers=_legacy())
        assert resp.status_code == 200
        body = resp.json()
        for key in admin_api.CONFIG_KEYS:
            assert key in body

    def test_put_unknown_key_400(self, client):
        resp = client.put("/system/config", headers=_legacy(),
                          json={"NOT_A_KEY": "1"})
        assert resp.status_code == 400

    def test_put_known_key_applies(self, client, monkeypatch, tmp_path):
        monkeypatch.delenv("IDA_WORKERS", raising=False)
        resp = client.put("/system/config", headers=_legacy(),
                          json={"IDA_WORKERS": 5})
        assert resp.status_code == 200
        assert os.environ["IDA_WORKERS"] == "5"
        settings = json.loads(
            (tmp_path / "settings.json").read_text(encoding="utf-8"))
        assert settings["IDA_WORKERS"] == "5"
        assert client.get("/system/config", headers=_legacy()
                          ).json()["IDA_WORKERS"] == "5"

    def test_system_info_shape(self, client):
        resp = client.get("/system/info", headers=_legacy())
        assert resp.status_code == 200
        body = resp.json()
        for key in ("python", "platform", "uptime_seconds", "pid",
                    "components"):
            assert key in body
        comp = body["components"]
        for key in ("ida", "emba", "cbm", "frida", "dsh", "afl_qemu",
                    "llm", "resources"):
            assert key in comp
        assert set(comp["afl_qemu"]) == {"arm", "aarch64", "mips", "mipsel"}
        assert "mem_total_mb" in comp["resources"]


class TestLogs:
    def _seed_log(self, tmp_path):
        log = tmp_path / "orchestrator.log"
        log.write_text("".join(f"line {i}\n" for i in range(50)),
                       encoding="utf-8")
        return log

    def test_logs_list(self, client, tmp_path):
        self._seed_log(tmp_path)
        resp = client.get("/logs", headers=_legacy())
        assert resp.status_code == 200
        names = {e["name"] for e in resp.json()}
        assert "orchestrator.log" in names

    def test_tail_ok(self, client, tmp_path):
        self._seed_log(tmp_path)
        resp = client.get("/logs/tail?name=orchestrator.log&lines=5",
                          headers=_legacy())
        assert resp.status_code == 200
        body = resp.json()
        assert body["lines"][-1] == "line 49"
        assert len(body["lines"]) == 5

    def test_tail_traversal_rejected(self, client, tmp_path):
        self._seed_log(tmp_path)
        (tmp_path / "secret.txt").write_text("nope", encoding="utf-8")
        for bad in ("../secret.txt", "..%2Fsecret.txt", "/etc/passwd",
                    "secret.txt"):
            resp = client.get(f"/logs/tail?name={bad}", headers=_legacy())
            assert resp.status_code in (400, 404), (bad, resp.status_code)

    def test_logs_require_admin(self, client, tmp_path):
        """S1: orchestrator.log can leak tokens — plain users get 403."""
        self._seed_log(tmp_path)
        headers = _session(client, "bob", "bob-pass-1")
        assert client.get("/logs", headers=headers).status_code == 403
        resp = client.get("/logs/tail?name=orchestrator.log", headers=headers)
        assert resp.status_code == 403


class TestReports:
    def _make_job(self, tmp_path, owner=None):
        job = {"job_id": JOB, "firmware": "mx12.bin", "status": "routed",
               "error": None, "created_at": "t0", "updated_at": "t0",
               "size_bytes": 1}
        if owner:
            job["owner"] = owner
        with main._jobs_lock:
            main._jobs[JOB] = job
        job_dir = tmp_path / "firmware" / JOB
        job_dir.mkdir(parents=True)
        (job_dir / "job.json").write_text(json.dumps(job), encoding="utf-8")

    def test_reports_empty(self, client):
        assert client.get("/reports", headers=_legacy()).json() == []

    def test_job_report_generate_and_fetch(self, client, tmp_path):
        self._make_job(tmp_path)
        resp = client.post(f"/jobs/{JOB}/report", headers=_legacy())
        assert resp.status_code == 200
        assert resp.json() == {"report_id": f"job-{JOB}"}

        listing = client.get("/reports", headers=_legacy()).json()
        assert [r["report_id"] for r in listing] == [f"job-{JOB}"]
        assert listing[0]["kind"] == "job"
        assert "综合报告" in listing[0]["title"]

        resp = client.get(f"/reports/job-{JOB}", headers=_legacy())
        assert resp.status_code == 200
        text = resp.text
        assert "综合安全分析报告" in text
        assert "mx12.bin" in text
        assert "（无数据）" in text  # artifacts absent in the temp dir

        resp = client.get(f"/jobs/{JOB}/report", headers=_legacy())
        assert resp.status_code == 200
        assert "综合安全分析报告" in resp.text

        resp = client.get(f"/reports/job-{JOB}/download", headers=_legacy())
        assert resp.status_code == 200
        assert "text/markdown" in resp.headers["content-type"]

    def test_report_unknown_job_404(self, client):
        resp = client.post("/jobs/000000000000/report", headers=_legacy())
        assert resp.status_code == 404

    def test_report_missing_404(self, client):
        resp = client.get("/reports/job-000000000000", headers=_legacy())
        assert resp.status_code == 404

    def test_report_bad_rid_400(self, client):
        resp = client.get("/reports/job-../../etc", headers=_legacy())
        assert resp.status_code in (400, 404)

    def test_reports_owner_filtered(self, client, tmp_path):
        """S3: non-admin sees/downloads only reports of their own jobs."""
        accounts.create_user("carol", "carol-pass-1", role="user")
        self._make_job(tmp_path, owner="bob")
        resp = client.post(f"/jobs/{JOB}/report", headers=_legacy())
        assert resp.status_code == 200
        bob = _session(client, "bob", "bob-pass-1")
        carol = _session(client, "carol", "carol-pass-1")
        listing = client.get("/reports", headers=bob).json()
        assert [r["report_id"] for r in listing] == [f"job-{JOB}"]
        assert client.get("/reports", headers=carol).json() == []
        assert client.get(f"/reports/job-{JOB}", headers=bob).status_code == 200
        assert client.get(f"/reports/job-{JOB}",
                          headers=carol).status_code == 404
        assert client.get(f"/reports/job-{JOB}/download",
                          headers=carol).status_code == 404
        assert client.get(f"/reports/job-{JOB}/export?fmt=docx",
                          headers=carol).status_code == 404
        # admin still sees everything
        assert client.get(f"/reports/job-{JOB}",
                          headers=_legacy()).status_code == 200

    def test_session_report_owner_filtered(self, client, tmp_path):
        accounts.create_user("carol", "carol-pass-1", role="user")
        sdir = tmp_path / "vulnagent" / "sessions" / "s-rep-0001"
        sdir.mkdir(parents=True)
        (sdir / "state.json").write_text(json.dumps({
            "session_id": "s-rep-0001", "task": "t", "status": "done",
            "owner": "bob", "created_at": "t0", "updated_at": "t1"}),
            encoding="utf-8")
        (sdir / "report.md").write_text("# 报告", encoding="utf-8")
        bob = _session(client, "bob", "bob-pass-1")
        carol = _session(client, "carol", "carol-pass-1")
        listing = client.get("/reports", headers=bob).json()
        assert [r["report_id"] for r in listing] == ["sess-s-rep-0001"]
        assert client.get("/reports/sess-s-rep-0001",
                          headers=bob).status_code == 200
        assert client.get("/reports/sess-s-rep-0001",
                          headers=carol).status_code == 404
        assert client.get("/reports", headers=carol).json() == []

    def test_legacy_report_without_owner_visible(self, client, tmp_path):
        """Pre-ownership jobs (no owner field) stay visible to everyone."""
        accounts.create_user("carol", "carol-pass-1", role="user")
        self._make_job(tmp_path)  # no owner
        assert client.post(f"/jobs/{JOB}/report",
                           headers=_legacy()).status_code == 200
        carol = _session(client, "carol", "carol-pass-1")
        assert client.get(f"/reports/job-{JOB}",
                          headers=carol).status_code == 200


class TestDashboard:
    def test_fields(self, client):
        with main._jobs_lock:
            main._jobs[JOB] = {"job_id": JOB, "firmware": "mx12.bin",
                               "status": "graphing", "error": None,
                               "created_at": "t0", "updated_at": "t1",
                               "size_bytes": 1}
        resp = client.get("/dashboard", headers=_legacy())
        assert resp.status_code == 200
        body = resp.json()
        for key in ("jobs_total", "jobs_by_status", "running",
                    "sessions_total", "sessions_running", "findings_total",
                    "reports_total", "inputs_total", "surfaces_total"):
            assert key in body
        assert body["jobs_total"] == 1
        assert body["jobs_by_status"] == {"graphing": 1}
        assert body["running"][0]["job_id"] == JOB
