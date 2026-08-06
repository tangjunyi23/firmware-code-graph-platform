"""Unit tests for pipeline.decompile.ai_enrich (AI pseudo-C overlay).

Covers target collection, overlay rendering, run_enrich with a mocked LLM
(original .c immutability included) and the /aienrich endpoints in main.py.
"""

import json

import pytest
from fastapi.testclient import TestClient

from orchestrator.app import main
from pipeline.decompile import ai_enrich
from pipeline.ailift import llm

JOB = "enrichjob01"
MD5 = "30e2839774afea41eebedfe19da24652"


def _func(addr, name, calls=None, tags=None, lines=50):
    return {"addr": addr, "name": name, "size": 100, "lines": lines,
            "calls": calls or [], "strings": [], "tags": tags or [],
            "is_exported": False, "decompile_ok": True}


def _symbols():
    return {"job_id": JOB, "binaries": {MD5: {
        "path": "firmware/usr/sbin/sysapihttpd", "md5": MD5,
        "functions": [
            _func("0x1000", "main", calls=["sub_2000"]),
            _func("0x2000", "sub_2000", tags=["calls_dangerous"],
                  calls=["system"]),
            _func("0x3000", "sub_3000", tags=["network_facing"]),
        ]}}}


@pytest.fixture
def job_dir(tmp_path):
    pseudo = tmp_path / "pseudocode" / JOB
    funcs = pseudo / MD5 / "functions"
    funcs.mkdir(parents=True)
    (pseudo / "symbols.json").write_text(json.dumps(_symbols()),
                                         encoding="utf-8")
    (funcs / "0x2000.c").write_text(
        "// addr=0x2000 name=sub_2000\nint sub_2000(int v1) {\n"
        "  memcpy();\n  return v1;\n}\n", encoding="utf-8")
    (funcs / "0x2000.asm").write_text(
        "// addr=0x2000 name=sub_2000\n00402000: move $a0, $s0\n"
        "00402004: jal memcpy\n", encoding="utf-8")
    (funcs / "0x3000.asm").write_text(
        "// addr=0x3000 name=sub_3000\n00403000: jr $ra\n",
        encoding="utf-8")
    # 0x3000 has no .c (decompile failed); main has neither .c nor .asm
    return tmp_path


def test_collect_targets_requires_asm_and_filters(job_dir):
    symbols = _symbols()
    pseudo_dir = job_dir / "pseudocode" / JOB / MD5
    targets = ai_enrich.collect_targets(symbols, MD5, pseudo_dir)
    # 0x2000 has .c + .asm; 0x3000 lacks .c (excluded w/o include_failed)
    assert [(f["addr"], has_c) for f, has_c in targets] == [("0x2000", True)]
    targets = ai_enrich.collect_targets(symbols, MD5, pseudo_dir,
                                        include_failed=True)
    assert [(f["addr"], has_c) for f, has_c in targets] == [
        ("0x2000", True), ("0x3000", False)]
    targets = ai_enrich.collect_targets(symbols, MD5, pseudo_dir,
                                        addrs={"0x3000"}, include_failed=True)
    assert [(f["addr"], has_c) for f, has_c in targets] == [("0x3000", False)]


def test_render_overlay_applies_renames_and_call_args():
    func = _func("0x2000", "sub_2000")
    code = "int sub_2000(int v1) {\n  memcpy();\n  return v1;\n}\n"
    parsed = {"renames": {"v1": "req"}, "call_args": {"memcpy()": "memcpy(dst, src, 0x42)"},
              "summary": "copies a request buffer", "domain": "util",
              "confidence": 0.8, "model": "m"}
    out = ai_enrich.render_overlay(func, True, code, parsed)
    assert "AI-ENRICHED OVERLAY" in out
    assert "memcpy(dst, src, 0x42);" in out
    assert "int sub_2000(int req)" in out
    assert "return req;" in out
    assert "memcpy();" not in out


def test_render_overlay_synthetic_for_failed_function():
    func = _func("0x3000", "sub_3000")
    parsed = {"synthetic_c": "int sub_3000(void) { return 0; }",
              "summary": "stub", "domain": "unknown", "confidence": 0.4,
              "model": "m"}
    out = ai_enrich.render_overlay(func, False, None, parsed)
    assert "synthetic translation" in out
    assert "int sub_3000(void)" in out


def test_run_enrich_writes_overlay_and_keeps_original(job_dir, monkeypatch):
    def fake_batch(client, items):
        assert len(items) == 1  # only the attack-chain function 0x2000
        func = items[0]["func"]
        return [(items[0], {
            "renames": {"v1": "req"},
            "call_args": {"memcpy()": "memcpy(dst, src, 0x42)"},
            "summary": "runs a command", "domain": "sys",
            "confidence": 0.9}, None)] if func["addr"] == "0x2000" else []

    monkeypatch.setattr(llm, "suggest_batch", fake_batch)
    before = (job_dir / "pseudocode" / JOB / MD5 / "functions" / "0x2000.c") \
        .read_text(encoding="utf-8")
    summary = ai_enrich.run_enrich(JOB, job_dir, MD5, attack_only=True)
    assert summary["status"] == "ok"
    assert summary["targets"] == 1
    assert summary["enriched"] == 1
    ai_dir = job_dir / "pseudocode" / JOB / MD5 / "ai"
    overlay = json.loads((ai_dir / "0x2000.json").read_text(encoding="utf-8"))
    assert overlay["source"] == "ai"
    assert overlay["call_args"] == {"memcpy()": "memcpy(dst, src, 0x42)"}
    assert "memcpy(dst, src, 0x42);" in (ai_dir / "0x2000.c") \
        .read_text(encoding="utf-8")
    # original Hex-Rays output untouched
    after = (job_dir / "pseudocode" / JOB / MD5 / "functions" / "0x2000.c") \
        .read_text(encoding="utf-8")
    assert after == before


def test_run_enrich_llm_error_isolated(job_dir, monkeypatch):
    monkeypatch.setattr(llm, "suggest_batch",
                        lambda client, items: [
                            (items[0], None, "Timeout: boom")])
    summary = ai_enrich.run_enrich(JOB, job_dir, MD5, attack_only=False,
                                   addrs={"0x2000"})
    assert summary["status"] == "ok"
    assert summary["enriched"] == 0
    assert summary["errors"] == 1


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_TOKEN", "")
    monkeypatch.setattr(main, "FIRMWARE_DIR", tmp_path / "firmware")
    monkeypatch.setattr(main, "PSEUDOCODE_DIR", tmp_path / "pseudocode")
    (main.FIRMWARE_DIR / JOB).mkdir(parents=True)
    pseudo = main.PSEUDOCODE_DIR / JOB
    (pseudo / MD5 / "functions").mkdir(parents=True)
    (pseudo / "symbols.json").write_text(json.dumps(_symbols()),
                                         encoding="utf-8")
    (pseudo / MD5 / "functions" / "0x2000.c").write_text(
        "int sub_2000(int v1) {\n  memcpy();\n}\n", encoding="utf-8")
    (pseudo / MD5 / "functions" / "0x3000.c").write_text(
        "int sub_3000(void) {\n  return 0;\n}\n", encoding="utf-8")
    (pseudo / MD5 / "ai").mkdir(parents=True)
    (pseudo / MD5 / "ai" / "0x2000.c").write_text(
        "// AI-ENRICHED OVERLAY\nint sub_2000(int req) {\n"
        "  memcpy(dst, src, 0x42);\n}\n", encoding="utf-8")
    with main._jobs_lock:
        main._jobs[JOB] = {
            "job_id": JOB, "firmware": "fw.bin", "status": "decompiled",
            "error": None, "created_at": main._now(),
            "updated_at": main._now(),
            "firmware_path": str(main.FIRMWARE_DIR / JOB / "firmware.bin"),
            "log_dir": "", "size_bytes": 1,
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


def test_aienrich_endpoint_accepts(client):
    c, threads = client
    resp = c.post(f"/jobs/{JOB}/aienrich", json={"binary_md5": MD5})
    assert resp.status_code == 202
    assert resp.json()["status"] == "aienriching"
    assert threads[0]["target"] is main._aienrich_worker
    assert threads[0]["args"] == (JOB, MD5, None, True, True, 0)


def test_aienrich_endpoint_validates(client):
    c, threads = client
    resp = c.post(f"/jobs/{JOB}/aienrich", json={"binary_md5": "nope"})
    assert resp.status_code == 400
    resp = c.post(f"/jobs/{JOB}/aienrich", json={"binary_md5": "0" * 32})
    assert resp.status_code == 404
    assert threads == []


def test_source_endpoint_serves_original_by_default(client):
    c, _ = client
    resp = c.get(f"/jobs/{JOB}/functions/{MD5}/0x2000/source")
    assert resp.status_code == 200
    assert "memcpy();" in resp.text
    assert "AI-ENRICHED" not in resp.text


def test_source_endpoint_serves_ai_overlay(client):
    c, _ = client
    resp = c.get(f"/jobs/{JOB}/functions/{MD5}/0x2000/source?ai=1")
    assert resp.status_code == 200
    assert "AI-ENRICHED OVERLAY" in resp.text
    assert "memcpy(dst, src, 0x42);" in resp.text


def test_source_endpoint_ai_overlay_missing(client):
    c, _ = client
    resp = c.get(f"/jobs/{JOB}/functions/{MD5}/0x3000/source?ai=1")
    assert resp.status_code == 404
    # original still reachable for the same function
    resp = c.get(f"/jobs/{JOB}/functions/{MD5}/0x3000/source")
    assert resp.status_code == 200


def test_aienrich_list_endpoint_unknown_job(client):
    c, _ = client
    resp = c.get("/jobs/nope00/aienrich")
    assert resp.status_code == 404


def test_aienrich_list_endpoint_all_unenriched(client):
    # no overlay *.json on disk: the directory still lists every function
    # from symbols.json, plainly marked enriched=false
    c, _ = client
    resp = c.get(f"/jobs/{JOB}/aienrich")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 0
    assert body["total_functions"] == 3
    assert len(body["binaries"]) == 1
    binary = body["binaries"][0]
    assert binary["count"] == 0
    assert binary["total"] == 3
    assert [f["addr"] for f in binary["functions"]] == [
        "0x1000", "0x2000", "0x3000"]
    assert all(f["enriched"] is False for f in binary["functions"])


def test_aienrich_list_endpoint_populated(client):
    c, _ = client
    ai_dir = main.PSEUDOCODE_DIR / JOB / MD5 / "ai"
    (ai_dir / "ai_enrich.json").write_text('{"status": "ok"}',
                                           encoding="utf-8")
    (ai_dir / "0x2000.json").write_text(json.dumps({
        "addr": "0x2000", "name": "sub_2000", "source": "ai",
        "has_c": True, "synthetic": False, "model": "m",
        "renames": {"v1": "req", "v2": "len"},
        "call_args": {"memcpy()": "memcpy(dst, src, 0x42)"},
        "summary": "runs a command", "domain": "sys",
        "confidence": 0.9}), encoding="utf-8")
    # overlay without a symbols entry: still listed, appended by address
    (ai_dir / "0x4000.json").write_text(json.dumps({
        "addr": "0x4000", "source": "ai", "has_c": False,
        "synthetic": True, "model": "m", "renames": {},
        "call_args": {}, "summary": "asm stub", "domain": "unknown",
        "confidence": 0.4}), encoding="utf-8")
    resp = c.get(f"/jobs/{JOB}/aienrich")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 2
    assert body["total_functions"] == 4
    assert len(body["binaries"]) == 1
    binary = body["binaries"][0]
    assert binary["md5"] == MD5
    assert binary["path"] == "firmware/usr/sbin/sysapihttpd"
    assert binary["count"] == 2
    assert binary["total"] == 4
    functions = binary["functions"]
    assert [f["addr"] for f in functions] == [
        "0x1000", "0x2000", "0x3000", "0x4000"]  # sorted by address
    assert functions[0]["enriched"] is False
    assert functions[0]["name"] == "main"
    fn = functions[1]
    assert fn["enriched"] is True
    assert fn["name"] == "sub_2000"
    assert fn["renames"] == 2
    assert fn["call_args"] == 1
    assert fn["confidence"] == 0.9
    assert fn["has_original"] is True
    assert fn["synthetic"] is False
    assert functions[2]["enriched"] is False
    syn = functions[3]
    assert syn["enriched"] is True
    assert syn["name"] == "0x4000"  # no name in meta or symbols -> addr
    assert syn["synthetic"] is True
    assert syn["has_original"] is False  # no functions/0x4000.c
