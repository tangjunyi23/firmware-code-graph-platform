"""Unit tests for the M4 graph endpoints in orchestrator.app.main.

The ingest worker and the CBM CLI wrapper are monkeypatched; FastAPI's
TestClient drives the HTTP layer. Auth is disabled via empty ORCH_TOKEN.
"""

import json
import threading
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from orchestrator.app import main

JOB = "graphjob0001"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_TOKEN", "")
    monkeypatch.setenv("AUTO_ATTACK", "0")
    monkeypatch.setenv("AUTO_ROUTES", "0")
    monkeypatch.setattr(main, "PSEUDOCODE_DIR", tmp_path / "pseudocode")
    monkeypatch.setattr(main, "CBM_DIR", tmp_path / "cbm")
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "ATTACK_DIR", tmp_path / "attack")
    monkeypatch.setattr(main, "ROUTES_DIR", tmp_path / "routes")
    # _save_job writes <FIRMWARE_DIR>/<job>/job.json; keep the real data/
    # tree free of fake test jobs.
    monkeypatch.setattr(main, "FIRMWARE_DIR", tmp_path / "firmware")
    monkeypatch.setattr(main, "EXTRACTED_DIR", tmp_path / "extracted")
    (main.PSEUDOCODE_DIR / JOB).mkdir(parents=True)
    (main.PSEUDOCODE_DIR / JOB / "symbols.json").write_text(
        json.dumps({"job_id": JOB, "binaries": {}}), encoding="utf-8")
    with main._jobs_lock:
        main._jobs[JOB] = {"job_id": JOB, "firmware": "fw.bin",
                           "status": "ailifted", "error": None,
                           "created_at": "t0", "updated_at": "t0",
                           "size_bytes": 1}
    yield TestClient(main.app), tmp_path
    with main._jobs_lock:
        main._jobs.pop(JOB, None)


class TestTriggerGraph:
    def test_202_then_graphed(self, client, monkeypatch):
        http, tmp_path = client
        threads = []

        class FakeThread:
            def __init__(self, target, args=(), daemon=None):
                threads.append((target, args))

            def start(self):
                pass

        def fake_run_job(job_id, data_dir):
            done = main.CBM_DIR / job_id
            done.mkdir(parents=True)
            (done / "graph_done.json").write_text(
                json.dumps({"job_id": job_id, "status": "ok",
                            "index": {"nodes": 1, "edges": 1}}),
                encoding="utf-8")
            return {"status": "ok"}

        monkeypatch.setattr(main, "threading", SimpleNamespace(Thread=FakeThread))
        monkeypatch.setattr(main.graph_ingest, "run_job", fake_run_job)
        resp = http.post(f"/jobs/{JOB}/graph")
        assert resp.status_code == 202
        assert resp.json()["status"] == "graphing"
        # run the captured worker synchronously
        target, args = threads[0]
        target(*args)
        assert main._jobs[JOB]["status"] == "graphed"
        resp = http.get(f"/jobs/{JOB}/graph")
        assert resp.status_code == 200
        body = resp.json()
        assert body["project"] == "fwgraph_" + JOB
        assert body["summary"]["index"]["nodes"] == 1

    def test_conflict_while_running(self, client):
        http, _ = client
        main._jobs[JOB]["status"] = "decompiling"
        assert http.post(f"/jobs/{JOB}/graph").status_code == 409

    def test_requires_symbols(self, client):
        http, _ = client
        (main.PSEUDOCODE_DIR / JOB / "symbols.json").unlink()
        resp = http.post(f"/jobs/{JOB}/graph")
        assert resp.status_code == 409

    def test_unknown_job_404(self, client):
        http, _ = client
        assert http.post("/jobs/nope/graph").status_code == 404
        assert http.get("/jobs/nope/graph").status_code == 404

    def test_get_before_build_404(self, client):
        http, _ = client
        assert http.get(f"/jobs/{JOB}/graph").status_code == 404


class TestGraphQuery:
    def test_search_dispatch(self, client, monkeypatch):
        http, _ = client
        seen = {}

        def fake_search(project, pattern, label=None, limit=None):
            seen.update(project=project, pattern=pattern, label=label)
            return {"total": 1, "results": []}

        monkeypatch.setattr(main.graph_query, "search", fake_search)
        resp = http.post("/graph/query", json={
            "job_id": JOB, "op": "search", "pattern": "auth", "label": "Function"})
        assert resp.status_code == 200
        assert resp.json()["total"] == 1
        assert seen == {"project": "fwgraph_" + JOB, "pattern": "auth",
                        "label": "Function"}

    def test_cypher_dispatch(self, client, monkeypatch):
        http, _ = client
        monkeypatch.setattr(main.graph_query, "cypher",
                            lambda project, q: {"columns": ["f.name"],
                                                "rows": [["main"]], "total": 1})
        resp = http.post("/graph/query", json={
            "job_id": JOB, "op": "cypher",
            "query": "MATCH (f:Function) RETURN f.name LIMIT 1"})
        assert resp.status_code == 200
        assert resp.json()["rows"] == [["main"]]

    def test_missing_param_400(self, client):
        http, _ = client
        resp = http.post("/graph/query", json={"job_id": JOB, "op": "search"})
        assert resp.status_code == 400

    def test_unknown_op_400(self, client):
        http, _ = client
        resp = http.post("/graph/query", json={"job_id": JOB, "op": "hack"})
        assert resp.status_code == 400

    def test_unknown_job_404(self, client):
        http, _ = client
        resp = http.post("/graph/query", json={"job_id": "nope", "op": "search",
                                               "pattern": "x"})
        assert resp.status_code == 404

    def test_attack_surface_dispatch_and_filter(self, client):
        http, tmp_path = client
        attack_dir = tmp_path / "attack" / JOB
        attack_dir.mkdir(parents=True)
        (attack_dir / "attack_paths.json").write_text(json.dumps({
            "generated_at": "t1", "summary": {"paths_returned": 2},
            "paths": [
                {"path_id": "p1", "source": {"asrc": ["network"]},
                 "sink": {"asink": ["cmdexec"]},
                 "verified_reachable": True},
                {"path_id": "p2", "source": {"asrc": ["file"]},
                 "sink": {"asink": ["memunsafe"]},
                 "verified_reachable": False},
            ]}), encoding="utf-8")
        response = http.post("/graph/query", json={
            "job_id": JOB, "op": "attack_surface",
            "source": "network", "verified_only": True})
        assert response.status_code == 200
        assert response.json()["total"] == 1
        assert response.json()["paths"][0]["path_id"] == "p1"

    def test_compose_evidence_joins_without_fetch(self, client):
        http, _ = client
        response = http.post("/graph/query", json={
            "job_id": JOB, "op": "compose_evidence",
            "binary_md5": "a" * 32, "addr": "0x1000",
            "static_block": {"asink": ["cmdexec"]},
            "decompile_text": "int f(void) { return 0; }",
        })
        assert response.status_code == 200
        body = response.json()
        assert body["producers"] == ["attack_surface", "hexrays"]
        assert body["address"]["addr"] == "0x1000"
        assert body["dynamic"] is None

    def test_routes_dispatch_and_filter(self, client):
        http, tmp_path = client
        route_dir = tmp_path / "routes" / JOB
        route_dir.mkdir(parents=True)
        (route_dir / "routes.json").write_text(json.dumps({
            "generated_at": "t2", "summary": {"routes": 2}, "routes": [
                {"route": "/goform/login", "method": "POST",
                 "binary_md5": "a" * 32, "confidence": 0.98},
                {"route": "/status", "method": None,
                 "binary_md5": "b" * 32, "confidence": 0.90},
            ]}), encoding="utf-8")
        response = http.post("/graph/query", json={
            "job_id": JOB, "op": "routes", "pattern": "login",
            "method": "POST", "min_confidence": 0.95})
        assert response.status_code == 200
        assert response.json()["total"] == 1
        assert response.json()["routes"][0]["route"] == "/goform/login"


class TestAttackEndpoints:
    def test_requires_graph(self, client):
        http, _ = client
        response = http.post(f"/jobs/{JOB}/attack")
        assert response.status_code == 409

    def test_trigger_worker_and_get_summary(self, client, monkeypatch):
        http, tmp_path = client
        graph_dir = tmp_path / "cbm" / JOB
        graph_dir.mkdir(parents=True)
        (graph_dir / "graph_done.json").write_text("{}", encoding="utf-8")
        threads = []

        class FakeThread:
            def __init__(self, target, args=(), daemon=None):
                threads.append((target, args))

            def start(self):
                pass

        def fake_attack(job_id, data_dir):
            out = tmp_path / "attack" / job_id
            out.mkdir(parents=True)
            summary = {"job_id": job_id, "status": "ok",
                       "analysis": {"paths_returned": 1}}
            (out / "attack_done.json").write_text(
                json.dumps(summary), encoding="utf-8")
            return summary

        monkeypatch.setattr(main, "threading", SimpleNamespace(Thread=FakeThread))
        monkeypatch.setattr(main.attack_runner, "run_job", fake_attack)
        response = http.post(f"/jobs/{JOB}/attack")
        assert response.status_code == 202
        target, args = threads[0]
        target(*args)
        assert main._jobs[JOB]["status"] == "attacked"
        response = http.get(f"/jobs/{JOB}/attack")
        assert response.status_code == 200
        assert response.json()["summary"]["analysis"]["paths_returned"] == 1

    def test_cbm_error_502(self, client, monkeypatch):
        http, _ = client

        def boom(project, q):
            raise main.graph_query.CBMError("cbm cli timed out after 30s")

        monkeypatch.setattr(main.graph_query, "cypher", boom)
        resp = http.post("/graph/query", json={
            "job_id": JOB, "op": "cypher", "query": "MATCH (n) RETURN n"})
        assert resp.status_code == 502
        assert "timed out" in resp.json()["detail"]


class TestRouteEndpoints:
    def test_requires_graph(self, client):
        http, _ = client
        response = http.post(f"/jobs/{JOB}/routes")
        assert response.status_code == 409

    def test_trigger_worker_and_get_summary(self, client, monkeypatch):
        http, tmp_path = client
        graph_dir = tmp_path / "cbm" / JOB
        graph_dir.mkdir(parents=True)
        (graph_dir / "graph_done.json").write_text("{}", encoding="utf-8")
        threads = []

        class FakeThread:
            def __init__(self, target, args=(), daemon=None):
                threads.append((target, args))

            def start(self):
                pass

        def fake_routes(job_id, data_dir):
            out = tmp_path / "routes" / job_id
            out.mkdir(parents=True)
            summary = {"job_id": job_id, "status": "ok",
                       "injection": {"inserted": 1}}
            (out / "routes_done.json").write_text(
                json.dumps(summary), encoding="utf-8")
            return summary

        monkeypatch.setattr(main, "threading", SimpleNamespace(Thread=FakeThread))
        monkeypatch.setattr(main.route_runner, "run_job", fake_routes)
        response = http.post(f"/jobs/{JOB}/routes")
        assert response.status_code == 202
        target, args = threads[0]
        target(*args)
        assert main._jobs[JOB]["status"] == "routed"
        response = http.get(f"/jobs/{JOB}/routes")
        assert response.status_code == 200
        assert response.json()["summary"]["injection"]["inserted"] == 1
