"""协议模糊测试 API 与引擎测试（M-ICS-1）。

覆盖：协议清单、参数/授权/公网闸门校验、对本地假 Modbus 服务的完整
生命周期（启动→完成→报告注册进报告中心）、owner 隔离、停止语义。
网络动作只打 127.0.0.1。
"""

import json
import socket
import threading
import time

import pytest
from fastapi.testclient import TestClient

from orchestrator.app import accounts, main, vulnagent_api
from pipeline.protofuzz import engine, protocols

LEGACY = "orch-test-token"
AUTH = {"Authorization": f"Bearer {LEGACY}"}


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
    yield TestClient(main.app)


def _login(client, username, password):
    resp = client.post("/auth/login",
                       json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['token']}"}


class FakeModbus:
    """最小 Modbus TCP 假设备：收任意报文回固定响应。"""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                break
            conn.settimeout(1)
            try:
                conn.recv(4096)
                conn.sendall(b"\x00\x01\x00\x00\x00\x03")
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def _wait_done(client, run_id, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = client.get(f"/protofuzz/{run_id}", headers=AUTH)
        assert resp.status_code == 200, resp.text
        if resp.json()["status"] != "running":
            return resp.json()
        time.sleep(0.3)
    pytest.fail("protofuzz run did not finish in time")


# ---------------------------------------------------------------------------
# engine 单测
# ---------------------------------------------------------------------------

def test_engine_generates_deterministic_cases():
    proto = protocols.get_protocol("modbus_tcp")
    a = engine.generate_cases(proto, seed=42)
    b = engine.generate_cases(proto, seed=42)
    assert len(a) > 30
    assert [c["payload"] for c in a] == [c["payload"] for c in b]  # 确定性
    # 基线种子在前
    assert a[0]["strategy"] == "baseline"
    # overflow 用例变长
    proto_mqtt = protocols.get_protocol("mqtt")
    cases = engine.generate_cases(proto_mqtt, seed=1)
    overflow = [c for c in cases if c["strategy"] == "overflow"]
    seed_len = len(proto_mqtt["templates"][0]["packet"])
    assert overflow and max(len(c["payload"]) for c in overflow) > seed_len


def test_engine_case_limit():
    proto = protocols.get_protocol("s7")
    cases = engine.generate_cases(proto, seed=1, max_cases=10)
    assert len(cases) == 10


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

def test_protocols_catalog(client):
    resp = client.get("/protofuzz/protocols", headers=AUTH)
    assert resp.status_code == 200
    names = {p["name"] for p in resp.json()["protocols"]}
    assert {"modbus_tcp", "s7", "opc_ua", "dnp3", "mqtt", "http"} <= names


def test_auth_required(client):
    assert client.get("/protofuzz").status_code == 401
    assert client.post("/protofuzz", json={}).status_code == 401


def test_acknowledge_and_validation(client):
    base = {"target_host": "127.0.0.1", "protocol": "modbus_tcp"}
    resp = client.post("/protofuzz", json=base, headers=AUTH)
    assert resp.status_code == 400 and "授权" in resp.json()["detail"]
    resp = client.post("/protofuzz", json={**base, "acknowledge": True,
                                           "protocol": "nope"}, headers=AUTH)
    assert resp.status_code == 400
    resp = client.post("/protofuzz", json={**base, "acknowledge": True,
                                           "target_port": 70000}, headers=AUTH)
    assert resp.status_code == 400
    resp = client.post("/protofuzz", json={**base, "acknowledge": True,
                                           "target_host": "bad host!"}, headers=AUTH)
    assert resp.status_code == 400
    # 公网目标被闸门拦截
    resp = client.post("/protofuzz", json={**base, "acknowledge": True,
                                           "target_host": "8.8.8.8"}, headers=AUTH)
    assert resp.status_code == 400 and "公网" in resp.json()["detail"]


def test_full_lifecycle_and_report(client):
    dev = FakeModbus()
    try:
        resp = client.post("/protofuzz", json={
            "target_host": "127.0.0.1", "target_port": dev.port,
            "protocol": "modbus_tcp", "acknowledge": True,
            "case_limit": 15, "delay_ms": 0, "timeout_ms": 500,
        }, headers=AUTH)
        assert resp.status_code == 202, resp.text
        run_id = resp.json()["run_id"]
        detail = _wait_done(client, run_id)
        assert detail["status"] == "done"
        assert detail["cases_done"] == 15
        assert detail["outcome_counts"].get("response", 0) > 0

        # 报告生成并注册进报告中心（pf- 前缀可被 _RID_RE 接受）
        resp = client.post(f"/protofuzz/{run_id}/report", headers=AUTH)
        assert resp.status_code == 200
        rid = resp.json()["report_id"]
        assert rid == run_id
        listing = client.get("/reports", headers=AUTH).json()
        rows = listing if isinstance(listing, list) else listing.get("reports", [])
        assert any(r["report_id"] == rid and r["kind"] == "protofuzz"
                   for r in rows)
        content = client.get(f"/reports/{rid}", headers=AUTH)
        assert content.status_code == 200
        assert "协议模糊测试报告" in content.text
    finally:
        dev.close()


def test_stop_and_owner_isolation(client):
    dev = FakeModbus()
    try:
        bob = _login(client, "bob", "bob-pass-123")
        resp = client.post("/protofuzz", json={
            "target_host": "127.0.0.1", "target_port": dev.port,
            "protocol": "http", "acknowledge": True,
            "case_limit": 5000, "delay_ms": 200, "timeout_ms": 300,
        }, headers=bob)
        assert resp.status_code == 202, resp.text
        run_id = resp.json()["run_id"]
        resp = client.post(f"/protofuzz/{run_id}/stop", headers=bob)
        assert resp.status_code == 200
        detail = _wait_done(client, run_id)
        assert detail["status"] in ("stopped", "done")

        # admin 建一个 run，bob 不可见（404 语义）
        resp = client.post("/protofuzz", json={
            "target_host": "127.0.0.1", "target_port": dev.port,
            "protocol": "modbus_tcp", "acknowledge": True,
            "case_limit": 3, "delay_ms": 0, "timeout_ms": 300,
        }, headers=AUTH)
        admin_run = resp.json()["run_id"]
        _wait_done(client, admin_run)
        assert client.get(f"/protofuzz/{admin_run}", headers=bob).status_code == 404
        bob_runs = client.get("/protofuzz", headers=bob).json()["runs"]
        assert all(r["run_id"] != admin_run for r in bob_runs)
        assert any(r["run_id"] == run_id for r in bob_runs)
    finally:
        dev.close()
