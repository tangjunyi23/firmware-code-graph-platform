"""Security-hardening tests: login lockout + timing flatten, password
policy, must_change_password flow, /system/info key masking, quotas and the
can_access contract.

Same isolation pattern as test_admin_api.py: temp FWGRAPH_DATA +
VULNAGENT_HOME + legacy ORCH_TOKEN.
"""

import json

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from orchestrator.app import accounts, main, vulnagent_api

LEGACY = "orch-test-token"


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
    yield TestClient(main.app)


def _legacy():
    return {"Authorization": f"Bearer {LEGACY}"}


def _login(http, username, password):
    return http.post("/auth/login",
                     json={"username": username, "password": password})


def _session(http, username, password):
    resp = _login(http, username, password)
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['token']}"}


class TestLoginLockout:
    def test_five_failures_lock(self, client):
        for _ in range(accounts.LOGIN_MAX_FAILS):
            assert _login(client, "bob", "wrong-wrong").status_code == 401
        resp = _login(client, "bob", "wrong-wrong")
        assert resp.status_code == 429
        assert "秒" in resp.json()["detail"]
        # even the correct password is refused while locked
        assert _login(client, "bob", "bob-pass-123").status_code == 429

    def test_lockout_detail_has_remaining_seconds(self, client):
        for _ in range(accounts.LOGIN_MAX_FAILS):
            _login(client, "bob", "wrong-wrong")
        resp = _login(client, "bob", "wrong-wrong")
        digits = "".join(c for c in resp.json()["detail"] if c.isdigit())
        assert digits and int(digits) > 0

    def test_success_clears_failures(self, client):
        for _ in range(accounts.LOGIN_MAX_FAILS - 1):
            assert _login(client, "bob", "wrong-wrong").status_code == 401
        assert _login(client, "bob", "bob-pass-123").status_code == 200
        # counter was reset: another MAX-1 failures must not lock yet
        for _ in range(accounts.LOGIN_MAX_FAILS - 1):
            assert _login(client, "bob", "wrong-wrong").status_code == 401
        assert _login(client, "bob", "bob-pass-123").status_code == 200

    def test_lockout_is_per_username(self, client):
        for _ in range(accounts.LOGIN_MAX_FAILS):
            _login(client, "bob", "wrong-wrong")
        assert _login(client, "bob", "bob-pass-123").status_code == 429
        # a different account from the same IP is not affected
        assert _login(client, "admin", "admin-pass-1").status_code == 200

    def test_login_fail_audit_has_ip(self, client, tmp_path):
        _login(client, "bob", "wrong-wrong")
        lines = (tmp_path / "audit.jsonl").read_text(
            encoding="utf-8").splitlines()
        rec = [json.loads(l) for l in lines
               if json.loads(l)["action"] == "login_fail"]
        assert rec and "ip=" in rec[-1]["detail"]


class TestLoginTimingFlatten:
    def test_unknown_user_runs_dummy_pbkdf2(self, client, monkeypatch):
        calls = []
        orig = accounts.hash_password

        def spy(password, salt):
            calls.append(salt)
            return orig(password, salt)

        monkeypatch.setattr(accounts, "hash_password", spy)
        assert _login(client, "ghost", "whatever-1").status_code == 401
        assert accounts.DUMMY_SALT in calls

    def test_known_user_uses_real_salt_not_dummy(self, client, monkeypatch):
        calls = []
        orig = accounts.hash_password

        def spy(password, salt):
            calls.append(salt)
            return orig(password, salt)

        monkeypatch.setattr(accounts, "hash_password", spy)
        assert _login(client, "bob", "wrong-wrong").status_code == 401
        assert calls and accounts.DUMMY_SALT not in calls


class TestPasswordPolicy:
    def test_unit_validate_password(self):
        assert accounts.validate_password("a" * 9) is not None
        assert accounts.validate_password("a" * 10) is None
        assert accounts.validate_password("admin123") is not None
        assert accounts.validate_password("FwGraph123") is not None  # ci
        assert accounts.validate_password("correct-horse-42") is None

    def test_create_user_weak_rejected(self, client):
        for weak in ("admin123", "password", "short"):
            resp = client.post("/users", headers=_legacy(),
                               json={"username": "xuser",
                                     "password": weak, "role": "user"})
            assert resp.status_code == 400, weak
        resp = client.post("/users", headers=_legacy(),
                           json={"username": "xuser",
                                 "password": "strong-pass-9", "role": "user"})
        assert resp.status_code == 201

    def test_change_password_weak_rejected(self, client):
        headers = _session(client, "bob", "bob-pass-123")
        resp = client.post("/auth/password", headers=headers,
                           json={"old_password": "bob-pass-123",
                                 "new_password": "qwerty"})
        assert resp.status_code == 400

    def test_admin_reset_weak_rejected(self, client):
        resp = client.patch("/users/bob", headers=_legacy(),
                            json={"password": "123456"})
        assert resp.status_code == 400


class TestMustChangePassword:
    def test_bootstrap_default_password_flagged(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
        monkeypatch.setenv("ORCH_TOKEN", LEGACY)
        monkeypatch.delenv("ADMIN_INITIAL_PASSWORD", raising=False)
        vulnagent_home = tmp_path / "vulnagent"
        (vulnagent_home / "sessions").mkdir(parents=True)
        monkeypatch.setattr(vulnagent_api, "VULNAGENT_HOME", vulnagent_home)
        accounts.ensure_initial_admin()
        user = accounts.find_user("admin")
        assert user["must_change_password"] is True

        http = TestClient(main.app)
        resp = _login(http, "admin", "admin123")
        assert resp.status_code == 200
        assert resp.json()["user"]["must_change_password"] is True
        headers = {"Authorization": f"Bearer {resp.json()['token']}"}
        assert http.get("/auth/me", headers=headers
                        ).json()["must_change_password"] is True

        resp = http.post("/auth/password", headers=headers,
                         json={"old_password": "admin123",
                               "new_password": "new-strong-pw-1"})
        assert resp.status_code == 200, resp.text
        assert http.get("/auth/me", headers=headers
                        ).json()["must_change_password"] is False
        resp = _login(http, "admin", "new-strong-pw-1")
        assert resp.json()["user"]["must_change_password"] is False

    def test_bootstrap_custom_password_not_flagged(self, tmp_path,
                                                   monkeypatch):
        monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
        monkeypatch.setenv("ADMIN_INITIAL_PASSWORD", "custom-pass-42")
        accounts.ensure_initial_admin()
        assert accounts.find_user("admin")["must_change_password"] is False


class TestSystemInfoMasking:
    def test_api_key_admin_only(self, client, monkeypatch):
        monkeypatch.setenv("LLM_API_KEY", "sk-abcdef123456")
        resp = client.get("/system/info", headers=_legacy())
        assert resp.json()["components"]["llm"]["api_key"] == "sk-***3456"

        headers = _session(client, "bob", "bob-pass-123")
        resp = client.get("/system/info", headers=headers)
        llm = resp.json()["components"]["llm"]
        assert "api_key" not in llm
        assert "3456" not in resp.text


class TestQuota:
    def test_check_quota_counts_and_429(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
        monkeypatch.setenv("FUZZ_DAILY_PER_JOB", "2")
        accounts.check_quota("job1", "fuzz")
        accounts.check_quota("job1", "fuzz")
        with pytest.raises(HTTPException) as excinfo:
            accounts.check_quota("job1", "fuzz")
        assert excinfo.value.status_code == 429
        assert "2/2" in excinfo.value.detail
        # other kinds and other jobs are independent
        accounts.check_quota("job1", "trace")
        accounts.check_quota("job2", "fuzz")

    def test_check_quota_unknown_kind_400(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
        with pytest.raises(HTTPException) as excinfo:
            accounts.check_quota("job1", "nope")
        assert excinfo.value.status_code == 400

    def test_check_quota_corrupt_file_tolerated(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
        (tmp_path / "quotas.json").write_text("{corrupt", encoding="utf-8")
        accounts.check_quota("job1", "trace")  # must not raise
        doc = json.loads((tmp_path / "quotas.json").read_text())
        assert sum(doc.values()) == 1

    def test_default_limits(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
        for env in ("TRACE_DAILY_PER_JOB", "FUZZ_DAILY_PER_JOB",
                    "FRIDA_DAILY_PER_JOB", "AIENRICH_DAILY_PER_JOB"):
            monkeypatch.delenv(env, raising=False)
        assert accounts.quota_limit("trace") == 10
        assert accounts.quota_limit("fuzz") == 6
        assert accounts.quota_limit("frida") == 6
        assert accounts.quota_limit("aienrich") == 6


class TestCanAccess:
    def test_contract(self):
        admin = {"username": "root", "role": "admin"}
        user = {"username": "bob", "role": "user"}
        assert accounts.can_access(admin, "bob") is True
        assert accounts.can_access(admin, None) is True
        assert accounts.can_access(user, "bob") is True
        assert accounts.can_access(user, "carol") is False
        for legacy in (None, "", "legacy"):
            assert accounts.can_access(user, legacy) is True
