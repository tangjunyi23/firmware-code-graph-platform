"""Protocol reverse: decode, crypto ID, assessment, HTTP endpoints."""

import json

import pytest
from fastapi.testclient import TestClient

from orchestrator.app import main
from pipeline import protocol_reverse as pr

JOB = "protorev0001"
MD5 = "9e39391af855fd996cdd90437e2eeb7b"


def test_decode_http_and_modbus_and_tls():
    http = pr.decode_traffic(bytes.fromhex(
        "474554202f20485454502f312e310d0a486f73743a20780d0a0d0a"))
    assert http["protocol"] == "http"
    assert http["fields"][0]["value"].startswith("GET /")

    mb = pr.decode_traffic(bytes.fromhex("00010000000601030000000a"))
    assert mb["protocol"] == "modbus"
    assert mb["fields"][1]["value"] == "0"

    tls = pr.decode_traffic(bytes.fromhex("160301000401000000"))
    assert tls["protocol"] == "tls"
    assert "Handshake" in tls["label"]


def test_decode_rejects_odd_hex():
    with pytest.raises(ValueError):
        pr.parse_payload("abc")


def test_crypto_skips_destroy_and_flags_weak():
    symbols = {
        "binaries": {
            MD5: {
                "path": "usr/sbin/httpd",
                "functions": [
                    {"addr": "0x1000", "name": "pthread_mutex_destroy",
                     "strings": []},
                    {"addr": "0x2000", "name": "AES_encrypt",
                     "strings": ["AES-128", "CBC"],
                     "on_attack_path": True},
                    {"addr": "0x3000", "name": "hmac_md5",
                     "strings": ["-----BEGIN CERTIFICATE-----"],
                     "observed_in_trace": True},
                    {"addr": "0x4000", "name": "DesEncrypt", "strings": []},
                ],
            }
        }
    }
    crypto = pr.identify_crypto(symbols)
    ids = {a["id"] for a in crypto["algorithms"]}
    assert "aes" in ids and "md5" in ids and "hmac" in ids and "des" in ids
    names = {f["name"] for f in crypto["functions"]}
    assert "pthread_mutex_destroy" not in names
    assert "AES_encrypt" in names
    assert any(a["id"] == "md5" for a in crypto["weak"])
    assert crypto["materials"]


def test_assess_public_http_is_high():
    ident = {
        "metadata": {"target": "demo.bin", "total_inputs": 1},
        "inputs": [{
            "id": "IN-001", "protocol": "http", "service": "httpd",
            "address": "0.0.0.0", "port": 80, "transport": "tcp",
            "public": True,
            "input_types": ["URL path", "query string", "POST body"],
            "evidence": "kb httpd",
        }],
    }
    protocols = pr.identify_protocols(ident)
    assert protocols["families"][0]["label"] == "Web"
    crypto = {"weak": [{"id": "md5", "label": "MD5"}], "legacy": []}
    assessment = pr.assess_attack_surface(
        protocols, crypto,
        {"surfaces": 2, "static_only": 1, "auth_chains": 0},
        [{"surface_id": "AS-001", "source_input": "IN-001",
          "final_handler": {"function": "unknown"}}],
        {"analysis": {"source_counts": {"network": 40}, "paths_returned": 10}},
    )
    assert assessment["ranked"][0]["score"] >= 60
    assert assessment["level"] in ("中", "高", "严重")
    assert any("HTTP" in r or "MD5" in r or "弱" in r
               for r in assessment["recommendations"])


def test_reverse_mentions_sbox():
    src = "const uint8_t sbox[] = { 0x63, 0x7c, 0x77, 0x7b, 0xf2 };\nAES_encrypt(buf);\n"
    out = pr.reverse_function({"name": "do_aes", "addr": "0x1"}, src)
    assert any(p["id"] == "aes" for p in out["primitives"])
    assert "AES S-box" in out["constants"]
    assert "破解" in out["narrative"]


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_TOKEN", "")
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    (tmp_path / "inputs" / JOB).mkdir(parents=True)
    (tmp_path / "pseudocode" / JOB / MD5 / "functions").mkdir(parents=True)
    (tmp_path / "surfaces" / JOB / "information").mkdir(parents=True)
    (tmp_path / "attack" / JOB).mkdir(parents=True)
    (tmp_path / "inputs" / JOB / "identification.json").write_text(
        json.dumps({
            "metadata": {"target": "demo.bin", "total_inputs": 1,
                         "gate_1": "ok", "gate_2": "ok"},
            "inputs": [{
                "id": "IN-001", "protocol": "telnet", "service": "telnetd",
                "address": "0.0.0.0", "port": 23, "transport": "tcp",
                "public": True, "input_types": ["login credentials"],
                "entry_files": ["usr/sbin/telnetd"],
                "evidence": "kb telnetd",
            }],
        }), encoding="utf-8")
    (tmp_path / "pseudocode" / JOB / "symbols.json").write_text(
        json.dumps({
            "binaries": {
                MD5: {
                    "path": "usr/sbin/telnetd",
                    "arch": "mips",
                    "functions": [
                        {"addr": "0x401000", "name": "AES_set_encrypt_key",
                         "strings": ["AES-128"], "decompile_ok": True},
                    ],
                }
            }
        }), encoding="utf-8")
    (tmp_path / "pseudocode" / JOB / MD5 / "functions" / "0x401000.c").write_text(
        "void AES_set_encrypt_key(void) { /* 0x63, 0x7c, 0x77, 0x7b */ }\n",
        encoding="utf-8")
    (tmp_path / "surfaces" / JOB / "surfaces_done.json").write_text(
        json.dumps({"job_id": JOB, "surfaces": 1, "auth_chains": 0,
                    "static_only": 1}), encoding="utf-8")
    (tmp_path / "surfaces" / JOB / "information" / "AS-001.json").write_text(
        json.dumps({"surface_id": "AS-001", "source_input": "IN-001",
                    "final_handler": {"function": "unknown"}}),
        encoding="utf-8")
    (tmp_path / "attack" / JOB / "attack_done.json").write_text(
        json.dumps({"analysis": {"source_counts": {"network": 3},
                                 "paths_returned": 2}}),
        encoding="utf-8")
    with main._jobs_lock:
        main._jobs[JOB] = {"job_id": JOB, "firmware": "demo.bin",
                           "status": "done", "error": None,
                           "created_at": "t0", "updated_at": "t0",
                           "size_bytes": 1}
    yield TestClient(main.app)
    with main._jobs_lock:
        main._jobs.pop(JOB, None)


def test_protocol_reverse_endpoints(client):
    r = client.post("/protocol/decode", json={"text": "474554202f20485454502f312e31"})
    assert r.status_code == 200
    assert r.json()["protocol"] == "http"

    bad = client.post("/protocol/decode", json={"text": "zz"})
    assert bad.status_code == 400

    doc = client.get(f"/jobs/{JOB}/protocol-reverse")
    assert doc.status_code == 200
    body = doc.json()
    assert body["protocols"]["items"][0]["protocol"] == "telnet"
    assert body["crypto"]["algorithms"]
    assert body["assessment"]["ranked"]
    assert "identification" not in body["missing"]

    rev = client.get(
        f"/jobs/{JOB}/protocol-reverse/functions/{MD5}/0x401000")
    assert rev.status_code == 200
    assert "AES" in rev.json()["narrative"] or rev.json()["primitives"]

    missing = client.get(f"/jobs/{JOB}/protocol-reverse/functions/{MD5}/0x1")
    assert missing.status_code == 404
