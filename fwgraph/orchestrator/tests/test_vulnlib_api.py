"""漏洞库 API：收录 CVE/CNVD、检索、按固件任务查 N-day。"""

import pytest
from fastapi.testclient import TestClient

from orchestrator.app import accounts, main, vulnagent_api
from pipeline import vulnlib

LEGACY = "orch-test-token"
AUTH = {"Authorization": f"Bearer {LEGACY}"}
JOB = "abcdef012345"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
    monkeypatch.setenv("ORCH_TOKEN", LEGACY)
    vulnagent_home = tmp_path / "vulnagent"
    (vulnagent_home / "sessions").mkdir(parents=True)
    monkeypatch.setenv("VULNAGENT_HOME", str(vulnagent_home))
    monkeypatch.setattr(vulnagent_api, "VULNAGENT_HOME", vulnagent_home)
    accounts.create_user("admin", "admin-pass-1", role="admin")
    accounts.create_user("bob", "bob-pass-123", role="user")
    job = {
        "job_id": JOB, "firmware": "ArcherC7v2_eu-up-ver1-1-4.bin",
        "status": "surfaced", "error": None, "created_at": "t0",
        "updated_at": "t0", "size_bytes": 1, "owner": "bob",
    }
    with main._jobs_lock:
        main._jobs[JOB] = job
    yield TestClient(main.app)
    with main._jobs_lock:
        main._jobs.pop(JOB, None)


def _login(http, username, password):
    resp = http.post("/auth/login",
                     json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['token']}"}


def _cve(**over):
    base = {
        "id": "CVE-2017-13772",
        "title": "TP-Link Archer C7 httpd 栈溢出",
        "summary": "httpd 处理 PIN 码时栈溢出",
        "vuln_point": "httpd /userRpm/PinRpm.htm → PIN 解析函数 → strcpy 栈缓冲",
        "description": "Archer C7 定制 httpd 处理无线 PIN 时未校验长度，超长 PIN 溢出栈缓冲，可导致远程代码执行。",
        "severity": "high",
        "cvss": 8.8,
        "cwe": "CWE-121",
        "vendors": ["TP-Link"],
        "products": ["Archer C7"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-13772"],
        "published": "2017-09-14",
    }
    base.update(over)
    return base


class TestAuthAndValidation:
    def test_auth_required(self, client):
        assert client.get("/vulnlib").status_code == 401
        assert client.post("/vulnlib", json=_cve()).status_code == 401

    def test_bad_id_422(self, client):
        resp = client.post("/vulnlib", headers=AUTH, json=_cve(id="not-a-cve"))
        assert resp.status_code == 422
        assert "CVE" in resp.json()["detail"]

    def test_title_required(self, client):
        payload = _cve()
        payload.pop("title")
        resp = client.post("/vulnlib", headers=AUTH, json=payload)
        assert resp.status_code == 422
        assert "title" in resp.json()["detail"]


class TestCrudAndSearch:
    def test_create_get_search(self, client):
        resp = client.post("/vulnlib", headers=AUTH, json=_cve())
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["id"] == "CVE-2017-13772"
        assert body["source"] == "cve"
        assert body["cwes"] == ["CWE-121"]
        assert body["vendors"] == ["TP-Link"]
        assert "栈溢出" in body["title"]
        assert "PIN" in body["vuln_point"]
        assert "远程代码执行" in body["description"]

        got = client.get("/vulnlib/CVE-2017-13772", headers=AUTH)
        assert got.status_code == 200
        assert "httpd" in got.json()["description"]

        listed = client.get("/vulnlib?q=archer", headers=AUTH)
        assert listed.status_code == 200
        data = listed.json()
        assert data["total"] == 1
        assert data["items"][0]["id"] == "CVE-2017-13772"

        by_cwe = client.get("/vulnlib?cwe=CWE-121", headers=AUTH)
        assert by_cwe.json()["total"] == 1

        miss = client.get("/vulnlib?q=cisco", headers=AUTH)
        assert miss.json()["total"] == 0

    def test_cnvd_and_stats(self, client):
        client.post("/vulnlib", headers=AUTH, json=_cve())
        cnvd = {
            "id": "CNVD-2019-01348",
            "title": "某路由器命令注入",
            "severity": "critical",
            "vendors": ["小米"],
            "products": ["miwifi R3"],
            "cwes": ["CWE-78"],
        }
        resp = client.post("/vulnlib", headers=AUTH, json=cnvd)
        assert resp.status_code == 201
        assert resp.json()["source"] == "cnvd"

        stats = client.get("/vulnlib/stats", headers=AUTH).json()
        assert stats["total"] == 2
        assert stats["by_source"]["cve"] == 1
        assert stats["by_source"]["cnvd"] == 1
        assert stats["by_severity"]["high"] == 1
        assert stats["by_severity"]["critical"] == 1

    def test_import_list_and_upsert(self, client):
        payload = [
            _cve(),
            {
                "id": "CVE-2019-18371",
                "title": "Xiaomi Mi WiFi R3 command injection",
                "severity": "high",
                "vendors": ["小米"],
                "products": ["miwifi R3"],
                "cwe": "CWE-78",
            },
        ]
        resp = client.post("/vulnlib/import", headers=AUTH, json=payload)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["imported"] == 2
        assert not body["errors"]

        again = client.post("/vulnlib/import", headers=AUTH,
                            json=[_cve(summary="updated pin overflow")])
        assert again.json()["imported"] == 1
        got = client.get("/vulnlib/CVE-2017-13772", headers=AUTH).json()
        assert "pin overflow" in got["summary"]

    def test_patch_and_delete(self, client):
        client.post("/vulnlib", headers=AUTH, json=_cve())
        patched = client.patch("/vulnlib/CVE-2017-13772", headers=AUTH,
                               json={"severity": "critical", "cvss": 9.8})
        assert patched.status_code == 200
        assert patched.json()["severity"] == "critical"
        assert patched.json()["cvss"] == 9.8

        bob = _login(client, "bob", "bob-pass-123")
        denied = client.delete("/vulnlib/CVE-2017-13772", headers=bob)
        assert denied.status_code == 403

        deleted = client.delete("/vulnlib/CVE-2017-13772", headers=AUTH)
        assert deleted.status_code == 200
        assert client.get("/vulnlib/CVE-2017-13772", headers=AUTH).status_code == 404


class TestNday:
    def test_matches_archer_job(self, client):
        client.post("/vulnlib", headers=AUTH, json=_cve())
        client.post("/vulnlib", headers=AUTH, json={
            "id": "CVE-2019-18371",
            "title": "Xiaomi Mi WiFi R3 command injection",
            "severity": "high",
            "vendors": ["小米"],
            "products": ["miwifi R3"],
            "cwe": "CWE-78",
        })
        resp = client.get("/vulnlib/nday", headers=AUTH)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["jobs_considered"] == 1
        ids = [row["id"] for row in data["items"]]
        assert "CVE-2017-13772" in ids
        assert "CVE-2019-18371" not in ids
        hit = data["items"][0]
        assert hit["matches"][0]["job_id"] == JOB
        assert hit["match_score"] >= 40

    def test_job_filter_404_for_stranger(self, client):
        client.post("/vulnlib", headers=AUTH, json=_cve())
        # bob owns the job; a second user without that job gets 404
        accounts.create_user("carol", "carol-pass-1", role="user")
        carol = _login(client, "carol", "carol-pass-1")
        resp = client.get(f"/vulnlib/nday?job_id={JOB}", headers=carol)
        assert resp.status_code == 404

    def test_normalize_guesses_vendor_from_product(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
        doc = vulnlib.normalize({
            "id": "CVE-2018-3948",
            "title": "Archer C7 lanMgrLan overflow",
            "products": ["TP-Link Archer C7"],
            "severity": "high",
        })
        assert "TP-Link" in doc["vendors"]
        assert doc["source"] == "cve"
