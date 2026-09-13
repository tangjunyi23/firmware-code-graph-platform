"""Unit tests for M2 targeted decompilation by binary_md5.

Covers decompiler.run_job(only_md5s=...) filtering + symbols.json merge
semantics, and POST /jobs/{id}/decompile body validation in main.py.
"""

import json

import pytest
from fastapi.testclient import TestClient

from orchestrator.app import decompiler, main

JOB = "decompjob001"
MD5_A = "a" * 32
MD5_B = "b" * 32
MD5_C = "c" * 32


def _manifest():
    return {
        "firmware": "fw.bin",
        "job_id": JOB,
        "binaries": [
            {"path": "firmware/bin/a", "arch": "mips", "bits": 32,
             "endianness": "le", "md5": MD5_A},
            {"path": "firmware/bin/b", "arch": "mips", "bits": 32,
             "endianness": "le", "md5": MD5_B},
        ],
        "stats": {"total_binaries": 2},
    }


def _symbols(md5, path):
    return {"job_id": JOB, "created_at": "2026-01-01T00:00:00+00:00",
            "binaries": {md5: {"path": path, "md5": md5, "functions": []}}}


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    d = tmp_path / "data"
    ext = d / "extracted" / JOB
    ext.mkdir(parents=True)
    (ext / "manifest.json").write_text(json.dumps(_manifest()),
                                       encoding="utf-8")
    monkeypatch.setenv("IDA_WORKERS", "1")

    calls = []

    def fake_decompile(job_id, binary, data_dir, timeout):
        calls.append(binary["md5"])
        out = data_dir / "pseudocode" / job_id / binary["md5"]
        out.mkdir(parents=True, exist_ok=True)
        (out / "symbols_raw.json").write_text(json.dumps(
            {"meta": {}, "functions": [{"addr": "0x1000", "name": "sub_1000"}]}),
            encoding="utf-8")
        return {"md5": binary["md5"], "path": binary["path"], "status": "ok",
                "error": None, "idb_reused": False, "elapsed_seconds": 0.1,
                "functions": 1, "decompiled": 1, "export_errors": 0,
                "naming": None}

    monkeypatch.setattr(decompiler, "_decompile_binary", fake_decompile)
    monkeypatch.setattr(decompiler.annotate, "annotate_file",
                        lambda path: {"tagged": 0})
    return d, calls


def _read_symbols(data_dir):
    path = data_dir / "pseudocode" / JOB / "symbols.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_run_job_does_not_require_ida_dir(data_dir, monkeypatch):
    monkeypatch.delenv("IDA_DIR", raising=False)
    d, calls = data_dir
    summary = decompiler.run_job(JOB, d, only_md5s={MD5_A})
    assert summary["succeeded"] == 1
    assert calls == [MD5_A]


def test_targeted_run_filters_binaries(data_dir):
    d, calls = data_dir
    summary = decompiler.run_job(JOB, d, only_md5s={MD5_A})
    assert calls == [MD5_A]
    assert summary["total_binaries"] == 1
    assert summary["succeeded"] == 1
    assert summary["only_md5s"] == [MD5_A]
    assert set(_read_symbols(d)["binaries"]) == {MD5_A}


def test_targeted_run_merges_existing_symbols(data_dir):
    d, _ = data_dir
    out_root = d / "pseudocode" / JOB
    out_root.mkdir(parents=True)
    (out_root / "symbols.json").write_text(
        json.dumps(_symbols(MD5_C, "firmware/bin/c")), encoding="utf-8")
    decompiler.run_job(JOB, d, only_md5s={MD5_A})
    assert set(_read_symbols(d)["binaries"]) == {MD5_A, MD5_C}


def test_full_run_rewrites_symbols(data_dir):
    d, calls = data_dir
    out_root = d / "pseudocode" / JOB
    out_root.mkdir(parents=True)
    (out_root / "symbols.json").write_text(
        json.dumps(_symbols(MD5_C, "firmware/bin/c")), encoding="utf-8")
    summary = decompiler.run_job(JOB, d)
    assert sorted(calls) == [MD5_A, MD5_B]
    assert summary["only_md5s"] is None
    assert set(_read_symbols(d)["binaries"]) == {MD5_A, MD5_B}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_TOKEN", "")
    fw_dir = tmp_path / "firmware"
    ext_dir = tmp_path / "extracted"
    monkeypatch.setattr(main, "FIRMWARE_DIR", fw_dir)
    monkeypatch.setattr(main, "EXTRACTED_DIR", ext_dir)
    (fw_dir / JOB).mkdir(parents=True)
    ext = ext_dir / JOB
    ext.mkdir(parents=True)
    (ext / "manifest.json").write_text(json.dumps(_manifest()),
                                       encoding="utf-8")
    with main._jobs_lock:
        main._jobs[JOB] = {
            "job_id": JOB, "firmware": "fw.bin", "status": "done",
            "error": None, "created_at": main._now(),
            "updated_at": main._now(),
            "firmware_path": str(fw_dir / JOB / "firmware.bin"),
            "log_dir": str(ext), "size_bytes": 1,
        }
    threads = []

    class FakeThread:
        def __init__(self, target=None, args=(), daemon=None):
            threads.append({"target": target, "args": args})

        def start(self):
            pass

    monkeypatch.setattr(main.threading, "Thread", FakeThread)
    with TestClient(main.app) as c:
        yield c, threads
    with main._jobs_lock:
        main._jobs.pop(JOB, None)


def test_endpoint_accepts_valid_md5s(client):
    c, threads = client
    resp = c.post(f"/jobs/{JOB}/decompile", json={"binary_md5s": [MD5_A]})
    assert resp.status_code == 202
    assert resp.json()["only_md5s"] == [MD5_A]
    assert len(threads) == 1
    assert threads[0]["target"] is main._decompile_worker
    assert threads[0]["args"] == (JOB, {MD5_A})


def test_endpoint_full_run_without_body(client):
    c, threads = client
    resp = c.post(f"/jobs/{JOB}/decompile")
    assert resp.status_code == 202
    assert resp.json()["only_md5s"] is None
    assert threads[0]["args"] == (JOB, None)


def test_endpoint_rejects_unknown_md5(client):
    c, threads = client
    resp = c.post(f"/jobs/{JOB}/decompile", json={"binary_md5s": [MD5_C]})
    assert resp.status_code == 400
    assert MD5_C in resp.json()["detail"]
    assert threads == []


def test_endpoint_rejects_bad_body(client):
    c, threads = client
    resp = c.post(f"/jobs/{JOB}/decompile", json={"binary_md5s": "notalist"})
    assert resp.status_code == 400
    assert threads == []
