"""Endpoint tests for the M6a/M6b inputs & surfaces API."""

import json

import pytest
from fastapi.testclient import TestClient

from orchestrator.app import main

JOB = "inputsjob001"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_TOKEN", "")
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "FIRMWARE_DIR", tmp_path / "firmware")
    monkeypatch.setattr(main, "EXTRACTED_DIR", tmp_path / "extracted")
    monkeypatch.setattr(main, "INPUTS_DIR", tmp_path / "inputs")
    monkeypatch.setattr(main, "SURFACES_DIR", tmp_path / "surfaces")
    (main.EXTRACTED_DIR / JOB).mkdir(parents=True)
    (main.EXTRACTED_DIR / JOB / "manifest.json").write_text(
        json.dumps({"firmware": "fw.bin", "job_id": JOB, "binaries": [],
                    "stats": {}}), encoding="utf-8")
    with main._jobs_lock:
        main._jobs[JOB] = {"job_id": JOB, "firmware": "fw.bin",
                           "status": "done", "error": None,
                           "created_at": "t0", "updated_at": "t0",
                           "size_bytes": 1}
    yield TestClient(main.app), tmp_path
    with main._jobs_lock:
        main._jobs.pop(JOB, None)


class FakeThread:
    threads = []

    def __init__(self, target, args=(), daemon=None):
        FakeThread.threads.append((target, args))

    def start(self):
        pass


def test_inputs_endpoint_cycle(client, monkeypatch):
    http, tmp_path = client
    monkeypatch.setattr(main.threading, "Thread", FakeThread)
    FakeThread.threads.clear()

    # no rootfs under extracted -> worker fails gracefully into failed state
    r = http.post(f"/jobs/{JOB}/inputs")
    assert r.status_code == 202
    target, args = FakeThread.threads[-1]
    target(*args)
    job = main._jobs[JOB]
    assert job["status"] in ("done", "failed")

    # now seed an identification doc and read it back
    doc = {"metadata": {"total_inputs": 1, "excluded": []},
           "inputs": [{"id": "IN-001", "protocol": "http",
                       "service": "lighttpd", "address": "0.0.0.0",
                       "port": 80, "transport": "tcp", "public": True,
                       "input_types": ["URL path"],
                       "entry_files": ["usr/sbin/lighttpd"],
                       "processing_chain": [], "dispatch_chain": [],
                       "evidence": "t", "notes": ""}]}
    idir = main.INPUTS_DIR / JOB
    idir.mkdir(parents=True)
    (idir / "identification.json").write_text(json.dumps(doc),
                                              encoding="utf-8")
    (idir / "inputs_done.json").write_text(json.dumps(
        {"job_id": JOB, "status": "ok", "total_inputs": 1}),
        encoding="utf-8")
    r = http.get(f"/jobs/{JOB}/inputs")
    assert r.status_code == 200 and r.json()["summary"]["total_inputs"] == 1
    r = http.get(f"/jobs/{JOB}/identification")
    assert r.status_code == 200
    assert r.json()["inputs"][0]["id"] == "IN-001"


def test_identification_annotates_md5_via_file_hash(client):
    http, _tmp = client
    ext = main.EXTRACTED_DIR / JOB
    blob = b"\x7fELF dropbear-or-scp-same-inode"
    (ext / "usr" / "bin").mkdir(parents=True, exist_ok=True)
    (ext / "usr" / "bin" / "scp").write_bytes(blob)
    (ext / "usr" / "bin" / "dropbear").write_bytes(blob)
    md5 = __import__("hashlib").md5(blob).hexdigest()
    (ext / "manifest.json").write_text(json.dumps({
        "firmware": "fw.bin", "job_id": JOB,
        "binaries": [{"path": "usr/bin/scp", "arch": "mips", "md5": md5}],
        "stats": {},
    }), encoding="utf-8")
    idir = main.INPUTS_DIR / JOB
    idir.mkdir(parents=True, exist_ok=True)
    (idir / "identification.json").write_text(json.dumps({
        "metadata": {"total_inputs": 1},
        "inputs": [{
            "id": "IN-013", "protocol": "ssh", "service": "dropbear",
            "port": 22, "transport": "tcp",
            "input_types": ["SSH handshake/KEX"],
            "entry_files": ["usr/bin/dropbear"],
            "processing_chain": [{"file": "usr/bin/dropbear", "libs": []}],
        }],
    }), encoding="utf-8")
    r = http.get(f"/jobs/{JOB}/identification")
    assert r.status_code == 200
    inp = r.json()["inputs"][0]
    assert inp["binary_md5"] == md5
    assert f"binary_md5={md5}" in inp["input_types"]
    assert inp["processing_chain"][0]["md5"] == md5
    assert inp["entry_md5s"][0]["md5"] == md5


def test_surfaces_endpoint_cycle(client, monkeypatch):
    http, tmp_path = client
    monkeypatch.setattr(main.threading, "Thread", FakeThread)
    FakeThread.threads.clear()

    # prerequisite missing -> 409
    r = http.post(f"/jobs/{JOB}/surfaces")
    assert r.status_code == 409

    idir = main.INPUTS_DIR / JOB
    idir.mkdir(parents=True)
    (idir / "identification.json").write_text(json.dumps(
        {"metadata": {"total_inputs": 1},
         "inputs": [{"id": "IN-001", "protocol": "http",
                     "service": "lighttpd", "address": "0.0.0.0", "port": 80,
                     "transport": "tcp", "public": True,
                     "input_types": ["URL path"],
                     "entry_files": ["usr/sbin/lighttpd"],
                     "processing_chain": [], "dispatch_chain": [],
                     "evidence": "t", "notes": ""}]}), encoding="utf-8")
    r = http.post(f"/jobs/{JOB}/surfaces")
    assert r.status_code == 202
    target, args = FakeThread.threads[-1]
    target(*args)
    assert main._jobs[JOB]["status"] == "surfaced"

    r = http.get(f"/jobs/{JOB}/surfaces")
    assert r.status_code == 200
    assert "AS-001.json" in r.json()["files"]
    r = http.get(f"/jobs/{JOB}/surfaces/AS-001")
    assert r.status_code == 200
    body = r.json()
    assert body["source_input"] == "IN-001"
    assert body["routing_path"][0]["stage"] == "listen"
    r = http.get(f"/jobs/{JOB}/surfaces/AS-999")
    assert r.status_code == 404
    r = http.get(f"/jobs/{JOB}/surfaces/bad%20id")
    assert r.status_code == 400


def test_unknown_job_404(client):
    http, _ = client
    assert http.post("/jobs/nope/inputs").status_code == 404
    assert http.get("/jobs/nope/identification").status_code == 404
    assert http.post("/jobs/nope/surfaces").status_code == 404
    assert http.get("/jobs/nope/surfaces/AS-001").status_code == 404
