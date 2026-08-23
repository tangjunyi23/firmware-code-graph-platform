"""One-shot qemu-user PoC runner and HTTP endpoints."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from orchestrator.app import main
from pipeline.trace import qemu_exec

JOB = "execjob0001"
MD5 = "ab" * 16


def _mk_job(tmp_path):
    data = tmp_path / "data"
    ext = data / "extracted" / JOB
    (ext / "bin").mkdir(parents=True)
    (ext / "bin" / "httpd").write_bytes(b"\x7fELF")
    (ext / "manifest.json").write_text(json.dumps({
        "job_id": JOB,
        "binaries": [{"path": "bin/httpd", "arch": "mips", "md5": MD5}],
    }), encoding="utf-8")
    return data


class _Proc:
    def __init__(self, rc=139):
        self.pid = 9
        self.returncode = rc

    def wait(self, timeout=None):
        return self.returncode


def test_run_job_classifies_sigsegv(tmp_path, monkeypatch):
    data = _mk_job(tmp_path)
    monkeypatch.setattr(qemu_exec.qemu_cov, "find_rootfs",
                        lambda *_a, **_k: (tmp_path, "/bin/httpd"))
    monkeypatch.setattr(qemu_exec.qemu_cov, "qemu_for", lambda *_a: "qemu-mips")
    monkeypatch.setattr(qemu_exec.qemu_cov, "prepare_rootfs",
                        lambda *_a, **_k: "/qemu-mips")
    monkeypatch.setattr(qemu_exec.qemu_cov, "trace_exec_mode", lambda: "none")
    monkeypatch.setattr(qemu_exec.sandbox, "sandbox_image_present",
                        lambda *_: False)
    monkeypatch.setattr(qemu_exec.subprocess, "Popen",
                        lambda *a, **k: _Proc(139))
    summary = qemu_exec.run_job(JOB, data, MD5, stdin=b"AAAA", seconds=3)
    assert summary["status"] == "crash"
    assert summary["signal"] == 11
    assert summary["crash_kind"] == "payload"
    assert summary["stdin_bytes"] == 4
    stored = qemu_exec.get_run(JOB, data, summary["run_id"])
    assert stored["status"] == "crash"


def test_run_job_empty_stdin_crash_is_startup(tmp_path, monkeypatch):
    data = _mk_job(tmp_path)
    monkeypatch.setattr(qemu_exec.qemu_cov, "find_rootfs",
                        lambda *_a, **_k: (tmp_path, "/bin/httpd"))
    monkeypatch.setattr(qemu_exec.qemu_cov, "qemu_for", lambda *_a: "qemu-mips")
    monkeypatch.setattr(qemu_exec.qemu_cov, "prepare_rootfs",
                        lambda *_a, **_k: "/qemu-mips")
    monkeypatch.setattr(qemu_exec.qemu_cov, "trace_exec_mode", lambda: "none")
    monkeypatch.setattr(qemu_exec.sandbox, "sandbox_image_present",
                        lambda *_: False)
    monkeypatch.setattr(qemu_exec.subprocess, "Popen",
                        lambda *a, **k: _Proc(139))
    summary = qemu_exec.run_job(JOB, data, MD5, seconds=3)
    assert summary["status"] == "crash"
    assert summary["crash_kind"] == "startup"
    assert "不要放弃" in summary["next"]


def test_seed_guest_tmp_copies_model(tmp_path):
    from pipeline.trace import qemu_cov
    rootfs = tmp_path / "root"
    (rootfs / "web" / "oem").mkdir(parents=True)
    (rootfs / "web" / "oem" / "model.conf").write_text("oem", encoding="utf-8")
    out = tmp_path / "guest-tmp"
    qemu_cov.seed_guest_tmp(rootfs, out)
    assert (out / "dec-model.conf").is_file()
    assert (out / "dec-model.conf").stat().st_mode & 0o777 == 0o666
    assert (out / "model.conf").read_text(encoding="utf-8") == "oem"


def test_decode_bytes_rejects_both():
    with pytest.raises(ValueError, match="不能同时"):
        qemu_exec.decode_bytes("x", "00")


def test_classify_rc_timeout_vs_crash_vs_error():
    assert qemu_exec._classify_rc(None) == ("timeout", None)
    assert qemu_exec._classify_rc(-9) == ("timeout", 9)
    assert qemu_exec._classify_rc(137) == ("timeout", 9)
    assert qemu_exec._classify_rc(139) == ("crash", 11)
    assert qemu_exec._classify_rc(-11) == ("crash", 11)
    assert qemu_exec._classify_rc(255) == ("error", None)
    assert qemu_exec._classify_rc(1) == ("error", None)
    assert qemu_exec._classify_rc(0) == ("ok", None)


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_TOKEN", "")
    monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "EXTRACTED_DIR", tmp_path / "extracted")
    monkeypatch.setattr(main, "EXEC_DIR", tmp_path / "qemu_exec")
    (main.EXTRACTED_DIR / JOB).mkdir(parents=True)
    (main.EXTRACTED_DIR / JOB / "manifest.json").write_text(json.dumps({
        "job_id": JOB,
        "binaries": [{"path": "bin/httpd", "arch": "mips", "md5": MD5}],
    }), encoding="utf-8")
    with main._jobs_lock:
        main._jobs[JOB] = {"job_id": JOB, "firmware": "fw.bin",
                           "status": "graphed", "error": None,
                           "created_at": "t0", "updated_at": "t0",
                           "size_bytes": 1}
    yield TestClient(main.app), tmp_path
    with main._jobs_lock:
        main._jobs.pop(JOB, None)


def test_qemu_exec_endpoint_202(client, monkeypatch):
    http, _ = client
    threads = []

    class FakeThread:
        def __init__(self, target, args=(), daemon=None):
            threads.append((target, args))

        def start(self):
            pass

    monkeypatch.setattr(main, "threading", SimpleNamespace(Thread=FakeThread))
    monkeypatch.setattr(main.qemu_exec, "run_job",
                        lambda *a, **k: {"run_id": k["run_id"], "status": "ok"})
    resp = http.post(f"/jobs/{JOB}/qemu-exec", json={
        "binary_md5": MD5, "stdin": "AAAA", "seconds": 3})
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["status"] == "running"
    assert body["run_id"].startswith("qe-")
    threads[0][0](*threads[0][1])
    got = http.get(f"/jobs/{JOB}/qemu-exec/{body['run_id']}")
    assert got.status_code == 200
    assert got.json()["status"] == "ok"
