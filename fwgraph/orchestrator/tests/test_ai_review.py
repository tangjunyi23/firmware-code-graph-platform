"""Attack-path AI review overlay (mocked LLM, no network)."""

import json

from pipeline.attack import ai_review
from pipeline import llm as llm_mod


def _path(path_id="p1"):
    return {
        "path_id": path_id, "score": 4.2, "edge_count": 1,
        "binary_md5": "a" * 32,
        "source": {"addr": "0x1000", "name": "sub_1000", "asrc": ["network"]},
        "sink": {"addr": "0x2000", "name": "sub_2000", "asink": ["memunsafe"]},
        "sanitizers": [], "verified_reachable": False,
        "chain": [{"addr": "0x1000", "name": "sub_1000"},
                  {"addr": "0x2000", "name": "sub_2000"}],
    }


def test_validate_row_rejects_unknown_path_and_bad_priority():
    known = {"p1"}
    assert ai_review._validate_row({"path_id": "nope", "priority": "P0"},
                                   known) is None
    assert ai_review._validate_row({"path_id": "p1", "priority": "P9"},
                                   known) is None
    row = ai_review._validate_row({
        "path_id": "p1", "priority": "P0", "vuln_class_hint": "bof",
        "cwe_hint": "CWE-78 / CWE-121", "dataflow": "likely",
        "sanitizer_effective": "yes", "reason": "x" * 500,
    }, known)
    assert row["cwe_hint"] is None
    assert row["sanitizer_effective"] is None
    assert len(row["reason"]) == 200
    assert row["vuln_class_hint"] == "bof"


def test_review_merges_valid_rows(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "sk-test")
    monkeypatch.setenv("AUTO_ATTACK_AI", "1")
    job = "jobai0000001"
    pseudo = tmp_path / "pseudocode" / job / ("a" * 32) / "functions"
    pseudo.mkdir(parents=True)
    (pseudo / "0x1000.c").write_text(
        "int sub_1000() {\n  recv();\n  strcpy(dst, src);\n}\n",
        encoding="utf-8")
    artifact = {"paths": [_path(), _path("p2")]}

    def fake_chat(system, user, **kwargs):
        return [
            {"path_id": "p1", "priority": "P0", "vuln_class_hint": "bof",
             "cwe_hint": "CWE-121", "sanitizer_effective": False,
             "dataflow": "likely", "reason": "strcpy 无界"},
            {"path_id": "p2", "priority": "bogus"},
        ]

    monkeypatch.setattr(llm_mod, "chat_json", fake_chat)
    stats = ai_review.review(job, tmp_path, artifact,
                             tmp_path / "pseudocode" / job)
    assert stats["status"] == "ok"
    assert stats["reviewed"] == 1
    assert artifact["paths"][0]["ai_review"]["priority"] == "P0"
    assert "ai_review" not in artifact["paths"][1]
    overlay = json.loads(
        (tmp_path / "attack" / job / "ai_review.json").read_text())
    assert overlay["reviewed"] == 1


def test_review_llm_error_does_not_raise(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "sk-test")
    monkeypatch.setenv("AUTO_ATTACK_AI", "1")
    job = "jobai0000002"
    artifact = {"paths": [_path()]}

    def boom(*args, **kwargs):
        raise RuntimeError("gateway down")

    monkeypatch.setattr(llm_mod, "chat_json", boom)
    stats = ai_review.review(
        job, tmp_path, artifact, tmp_path / "pseudocode" / job)
    assert stats["status"] == "error"
    assert "gateway down" in stats["error"]
    assert "ai_review" not in artifact["paths"][0]


def test_enabled_respects_env(monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("AUTO_ATTACK_AI", raising=False)
    assert ai_review.enabled() is False
    monkeypatch.setenv("LLM_API_KEY", "sk")
    assert ai_review.enabled() is True
    monkeypatch.setenv("AUTO_ATTACK_AI", "0")
    assert ai_review.enabled() is False


def test_parse_json_fence():
    assert llm_mod.parse_json("```json\n[1]\n```") == [1]
    assert llm_mod.parse_json('noise {"a": 1}') == {"a": 1}


def test_content_from_openai_and_anthropic():
    assert llm_mod.content_from_response({
        "choices": [{"message": {"content": "[1]"}}]}) == "[1]"
    assert llm_mod.content_from_response({
        "content": [{"type": "text", "text": "{\"a\":1}"}]}) == '{"a":1}'
