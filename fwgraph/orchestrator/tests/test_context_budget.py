"""上下文预算（P1/P2/P3）服务端测试：

- attack_surface brief=true 掉链节点、只留分诊字段
- cfg/ast 的 max_nodes/max_depth 截断
- 函数 brief 端点（签名头/危险调用行/出边/攻击面标记）
"""

import json

import pytest
from fastapi.testclient import TestClient

from orchestrator.app import accounts, main, vulnagent_api

LEGACY = "orch-test-token"
AUTH = {"Authorization": f"Bearer {LEGACY}"}
JOB = "abcdef012345"
MD5 = "03c6e3b4312c0a8c855cb9298c90dc32"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
    monkeypatch.setenv("ORCH_TOKEN", LEGACY)
    # main.py 的目录常量在 import 时定型，必须显式 patch 到 tmp_path
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "FIRMWARE_DIR", tmp_path / "firmware")
    monkeypatch.setattr(main, "PSEUDOCODE_DIR", tmp_path / "pseudocode")
    monkeypatch.setattr(main, "ATTACK_DIR", tmp_path / "attack")
    vulnagent_home = tmp_path / "vulnagent"
    (vulnagent_home / "sessions").mkdir(parents=True)
    monkeypatch.setenv("VULNAGENT_HOME", str(vulnagent_home))
    monkeypatch.setattr(vulnagent_api, "VULNAGENT_HOME", vulnagent_home)
    accounts.create_user("admin", "admin-pass-1", role="admin")
    _seed(tmp_path)
    yield TestClient(main.app)
    with main._jobs_lock:
        main._jobs.pop(JOB, None)


def _seed(tmp_path):
    job = {"job_id": JOB, "firmware": "t.bin", "status": "graphed",
           "error": None, "created_at": "t0", "updated_at": "t0",
           "size_bytes": 1, "owner": "admin"}
    with main._jobs_lock:
        main._jobs[JOB] = job
    job_dir = tmp_path / "firmware" / JOB
    job_dir.mkdir(parents=True)
    (job_dir / "job.json").write_text(json.dumps(job), encoding="utf-8")

    # symbols.json + 伪代码
    pseudo = tmp_path / "pseudocode" / JOB
    (pseudo / MD5 / "functions").mkdir(parents=True)
    (pseudo / "symbols.json").write_text(json.dumps({
        "binaries": {MD5: {
            "path": "/bin/httpd", "arch": "arm", "bits": 32,
            "endianness": "little",
            "functions": [
                {"addr": "0x1000", "name": "sub_1000", "size": 64,
                 "lines": 12, "tags": ["network_facing"], "domain": "http",
                 "asrc": ["network"], "asink": [], "on_attack_path": True,
                 "path_ids": ["p1"], "observed_in_trace": False,
                 "verified_reachable": False},
                {"addr": "0x2000", "name": "helper", "size": 16,
                 "lines": 3, "tags": []},
            ]}}}), encoding="utf-8")
    (pseudo / MD5 / "functions" / "0x1000.c").write_text(
        "int sub_1000(int fd, char *buf)\n{\n"
        "  int n;\n"
        "  char tmp[64];\n"
        "  n = recv(fd, buf, 512, 0);\n"
        "  strcpy(tmp, buf);\n"
        "  helper(n);\n"
        "  system(tmp);\n"
        "  return n;\n"
        "}\n",
        encoding="utf-8")

    # attack_paths.json（chain 是大头）
    attack = tmp_path / "attack" / JOB
    attack.mkdir(parents=True)
    (attack / "attack_paths.json").write_text(json.dumps({
        "generated_at": "t1", "summary": {"paths_returned": 1},
        "paths": [{
            "path_id": "p1", "score": 5.5, "edge_count": 3,
            "verified_reachable": False, "observed_node_count": 0,
            "source": {"addr": "0x1000", "name": "sub_1000",
                       "ai_name": None, "asrc": ["network"]},
            "sink": {"addr": "0x1000", "name": "sub_1000",
                     "ai_name": None, "asink": ["memunsafe"]},
            "chain": [{"addr": "0x1000", "name": "sub_1000"},
                      {"addr": "0x1001"}, {"addr": "0x1002"}],
            "sanitizers": [],
        }]}), encoding="utf-8")

    # graphext cfg/ast
    cfg_dir = tmp_path / "graphext" / JOB / "cfg"
    cfg_dir.mkdir(parents=True)
    blocks = [{"id": i, "start": hex(0x1000 + i * 4), "end": hex(0x1004 + i * 4),
               "instrs": 1, "text": "x"} for i in range(10)]
    edges = [[hex(0x1000 + i * 4), hex(0x1004 + i * 4), "fall"]
             for i in range(9)]
    (cfg_dir / f"{MD5}.json").write_text(json.dumps(
        {"0x1000": {"blocks": blocks, "edges": edges}}), encoding="utf-8")
    ast_dir = tmp_path / "graphext" / JOB / "ast"
    ast_dir.mkdir(parents=True)

    def tree(depth):
        node = {"type": f"n{depth}"}
        if depth < 6:
            node["children"] = [tree(depth + 1), tree(depth + 1)]
        return node
    (ast_dir / f"{MD5}.json").write_text(json.dumps(
        {"0x1000": {"language": "c", "root": tree(0), "truncated": False}}),
        encoding="utf-8")


def test_attack_surface_brief(client):
    full = client.post("/graph/query", json={
        "job_id": JOB, "op": "attack_surface"}, headers=AUTH).json()
    brief = client.post("/graph/query", json={
        "job_id": JOB, "op": "attack_surface", "brief": True}, headers=AUTH).json()
    assert full["paths"][0]["chain"]  # 全量带链
    b = brief["paths"][0]
    assert "chain" not in b
    assert b["path_id"] == "p1" and b["score"] == 5.5
    assert b["source"]["asrc"] == ["network"]
    assert b["sink"]["asink"] == ["memunsafe"]


def test_cfg_truncation(client):
    full = client.post("/graph/query", json={
        "job_id": JOB, "op": "cfg", "md5": MD5, "addr": "0x1000"},
        headers=AUTH).json()["cfg"]
    assert len(full["blocks"]) == 10 and len(full["edges"]) == 9
    cut = client.post("/graph/query", json={
        "job_id": JOB, "op": "cfg", "md5": MD5, "addr": "0x1000",
        "max_nodes": 3}, headers=AUTH).json()["cfg"]
    assert cut["truncated"] is True and cut["total_blocks"] == 10
    assert len(cut["blocks"]) == 3
    assert all(e[0] in {"0x1000", "0x1004", "0x1008"} for e in cut["edges"])


def test_ast_truncation(client):
    cut = client.post("/graph/query", json={
        "job_id": JOB, "op": "ast", "md5": MD5, "addr": "0x1000",
        "max_depth": 2}, headers=AUTH).json()["ast"]
    assert cut["truncated"] is True
    assert cut["root"]["children"][0]["children"][0]["children"][0]["pruned"]


def test_function_brief(client):
    resp = client.get(f"/jobs/{JOB}/functions/{MD5}/0x1000/brief", headers=AUTH)
    assert resp.status_code == 200, resp.text
    d = resp.json()
    assert d["name"] == "sub_1000" and d["on_attack_path"] is True
    assert d["asrc"] == ["network"] and d["path_ids"] == ["p1"]
    assert d["source_available"] is True
    assert d["head"][0].startswith("int sub_1000")
    calls = {c["text"] for c in d["dangerous_calls"]}
    assert any("strcpy" in c for c in calls)
    assert any("system" in c for c in calls)
    assert any("recv" in c for c in calls)
    assert "helper" in d["callees"]
    # 404 分支
    assert client.get(f"/jobs/{JOB}/functions/{MD5}/0x9999/brief",
                      headers=AUTH).status_code == 404
