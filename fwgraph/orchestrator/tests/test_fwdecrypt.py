"""Firmware unwrap / decrypt progress."""

import gzip
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from orchestrator.app import main
from pipeline import fwdecrypt as dec

JOB = "decjob000001"


def test_plain_squashfs_needs_no_decrypt(tmp_path):
    src = tmp_path / "fw.bin"
    src.write_bytes(b"hsqs" + b"\x00" * 128)
    out = tmp_path / "out"
    report = dec.run_job(JOB, "demo.bin", src, out)
    assert report["status"] == "plain"
    assert report["progress"] == 100
    assert report["needed"] is False
    assert report["output"] is None
    assert (out / "decrypt.json").is_file()


def test_gzip_unwraps_inner_squashfs(tmp_path):
    inner = b"hsqs" + b"\x00" * 200
    src = tmp_path / "fw.bin"
    with gzip.open(src, "wb") as fh:
        fh.write(inner)
    report = dec.run_job(JOB, "pack.bin.gz", src, tmp_path / "out")
    assert report["status"] == "decrypted"
    assert report["method"] == "gzip"
    assert Path(report["output"]).read_bytes().startswith(b"hsqs")
    assert "squashfs" in report["inner"]


def test_header_carve(tmp_path):
    src = tmp_path / "archer.bin"
    src.write_bytes(b"TP-LINK" + b"\x00" * (0x200 - 7) + b"hsqs" + b"\x00" * 80)
    report = dec.run_job(JOB, "ArcherC7.bin", src, tmp_path / "out")
    assert report["status"] == "decrypted"
    assert report["method"].startswith("carve@")
    assert report["vendor"] == "TP-Link"
    assert Path(report["output"]).read_bytes().startswith(b"hsqs")


def test_encrypted_container_identified_not_cracked(tmp_path):
    src = tmp_path / "enc.bin"
    src.write_bytes(b"SHRS" + bytes(range(256)) * 8)
    report = dec.run_job(JOB, "dlink.bin", src, tmp_path / "out")
    assert report["status"] == "identified"
    assert report["needed"] is True
    assert report["output"] is None
    assert report["progress"] == 100


def test_high_entropy_marked_encrypted(tmp_path):
    src = tmp_path / "rand.bin"
    src.write_bytes(bytes([i * 17 % 256 for i in range(8192)]))
    # not high enough? use urandom-like
    src.write_bytes(__import__("os").urandom(8192))
    info = dec.fingerprint(src.read_bytes(), "x.bin")
    assert info["encrypted"] is True


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_TOKEN", "")
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "FIRMWARE_DIR", tmp_path / "firmware")
    (tmp_path / "firmware" / JOB).mkdir(parents=True)
    (tmp_path / "firmware" / JOB / "firmware.bin").write_bytes(
        b"hsqs" + b"\x00" * 64)
    with main._jobs_lock:
        main._jobs[JOB] = {
            "job_id": JOB, "firmware": "demo.bin", "status": "done",
            "error": None, "created_at": "t1", "updated_at": "t1",
            "size_bytes": 68, "owner": "admin",
        }
    yield TestClient(main.app)
    with main._jobs_lock:
        main._jobs.pop(JOB, None)


def test_decrypt_endpoints(client, tmp_path):
    listed = client.get("/decrypt")
    assert listed.status_code == 200
    body = listed.json()
    assert body["summary"]["total"] == 1
    one = client.get(f"/jobs/{JOB}/decrypt")
    assert one.status_code == 200
    assert one.json()["job_id"] == JOB

    dec.run_job(JOB, "demo.bin",
                tmp_path / "firmware" / JOB / "firmware.bin",
                tmp_path / "decrypt" / JOB)
    listed = client.get("/decrypt")
    assert listed.json()["summary"]["plain"] == 1
