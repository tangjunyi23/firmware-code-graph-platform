"""Analysis gears (low / high / xhigh) for the chat homepage."""

import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from orchestrator.app import main
from pipeline import profiles


class _FakeThread:
    def __init__(self, target=None, args=(), **kwargs):
        self.target, self.args = target, args

    def start(self):
        pass


def test_auto_unpack_does_not_look_finished(monkeypatch):
    from orchestrator.app import main
    monkeypatch.setenv("AUTO_DECOMPILE", "1")
    assert main._should_mark_unpack_done({"auto": True}) is False
    assert main._should_mark_unpack_done({"auto": False}) is False
    monkeypatch.setenv("AUTO_DECOMPILE", "0")
    assert main._should_mark_unpack_done({"auto": False}) is True
    assert main._should_mark_unpack_done({"auto": True}) is False


def test_spec_default_and_unknown():
    assert profiles.spec(None)["id"] == "high"
    assert profiles.spec("LOW")["id"] == "low"
    assert profiles.spec("xhigh")["decompile_max_binaries"] is None
    assert profiles.spec("low")["attack_ai"] is False
    assert profiles.spec("high")["scoring"]["path_limit"] == 50
    with pytest.raises(profiles.UnknownProfile):
        profiles.spec("turbo")


def test_select_decompile_prefers_network_and_caps(tmp_path):
    job = "job1"
    ext = tmp_path / "extracted" / job
    ext.mkdir(parents=True)
    binaries = [
        {"path": "firmware/0/lib/libunused.so", "md5": "a" * 32, "size": 9000},
        {"path": "firmware/0/usr/sbin/httpd", "md5": "b" * 32, "size": 100},
        {"path": "firmware/0/bin/busybox", "md5": "c" * 32, "size": 50},
    ]
    for i in range(15):
        binaries.append({
            "path": f"firmware/0/lib/pad{i}.so", "md5": f"{i:032x}", "size": 10,
        })
    (ext / "manifest.json").write_text(json.dumps({"binaries": binaries}),
                                       encoding="utf-8")
    ident = tmp_path / "inputs" / job
    ident.mkdir(parents=True)
    (ident / "identification.json").write_text(json.dumps({
        "inputs": [{"entry_files": ["usr/sbin/httpd"],
                    "processing_chain": [{"file": "usr/sbin/httpd"}]}],
    }), encoding="utf-8")
    picked = profiles.select_decompile_targets(job, tmp_path, "low")
    assert picked is not None
    assert len(picked) == 12
    assert "b" * 32 in picked


def test_xhigh_does_not_subset():
    assert profiles.select_decompile_targets("j", "/tmp", "xhigh") is None


def test_attack_runner_reads_job_profile(tmp_path):
    from pipeline.attack import runner as attack_runner
    job = "jobp"
    (tmp_path / "firmware" / job).mkdir(parents=True)
    (tmp_path / "firmware" / job / "job.json").write_text(
        json.dumps({"profile": "low"}), encoding="utf-8")
    spec = attack_runner._profile_spec(job, tmp_path)
    assert spec["id"] == "low"
    assert spec["scoring"]["path_limit"] == 20


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_TOKEN", "")
    monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
    monkeypatch.setattr(main, "FIRMWARE_DIR", tmp_path / "firmware")
    monkeypatch.setattr(main, "EXTRACTED_DIR", tmp_path / "extracted")
    main.FIRMWARE_DIR.mkdir(parents=True)
    main.EXTRACTED_DIR.mkdir(parents=True)
    monkeypatch.setattr(main, "_disk_free_bytes", lambda path: 100 * 1024**3)
    monkeypatch.setattr(main, "threading", SimpleNamespace(Thread=_FakeThread))
    yield TestClient(main.app)


def test_list_profiles_and_upload(client):
    listed = client.get("/analysis-profiles")
    assert listed.status_code == 200
    ids = [p["id"] for p in listed.json()["profiles"]]
    assert ids == ["low", "high", "xhigh"]
    resp = client.post("/firmware?auto=1&profile=low", files={
        "file": ("fw.bin", b"\x00" * 8, "application/octet-stream")})
    assert resp.status_code == 201
    assert resp.json()["profile"] == "low"
    job_id = resp.json()["job_id"]
    assert main._jobs[job_id]["profile"] == "low"
    assert main._jobs[job_id]["auto"] is True
    listed_jobs = client.get("/jobs").json()
    assert listed_jobs[0]["profile"] == "low"
    bad = client.post("/firmware?profile=turbo", files={
        "file": ("fw.bin", b"\x00" * 4, "application/octet-stream")})
    assert bad.status_code == 400
    with main._jobs_lock:
        main._jobs.pop(job_id, None)
