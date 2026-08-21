"""Evidence Address, envelope pagination, and composition (Firida-adapted)."""

from pipeline import evidence as ev
from pipeline.attack import cross, paths, surface
from pipeline.inputs import elfchain


def test_canonical_addr_and_join_key():
    addr = ev.make_address("a" * 32, "0x10A0", job_id="job1")
    assert addr["schema"] == ev.SCHEMA_ADDRESS
    assert addr["addr"] == "0x10a0"
    assert addr["binary_md5"] == "a" * 32
    assert addr["job_id"] == "job1"
    assert ev.canonical_addr("10A0") == "0x10a0"
    assert ev.canonical_addr("") == ""


def test_envelope_truncation_marks_incomplete():
    items = [{"n": i} for i in range(5)]
    full = ev.wrap_envelope(
        producer="trace", view_kind="trace_flow", job_id="j",
        capture_id="t1", items=items)
    assert full["pagination"]["analysis_complete"] is True
    assert full["attribution"] == ev.ATTRIBUTION_OBSERVED
    cut = ev.wrap_envelope(
        producer="trace", view_kind="trace_flow", job_id="j",
        items=items, limit=2)
    assert cut["pagination"] == {
        "offset": 0, "items_returned": 2, "items_total": 5,
        "has_more": True, "analysis_complete": False,
    }
    assert "not request-caused" in cut["note"].lower()


def test_compose_does_not_invent_producers():
    out = ev.compose(job_id="j", binary_md5="a" * 32, addr="0x1")
    assert out["producers"] == []
    assert out["static_block"] is None
    joined = ev.compose(
        job_id="j", binary_md5="a" * 32, addr="0x1",
        static_block={"asink": ["cmdexec"]},
        decompile_text="int f() { return 0; }\n",
        dynamic_envelope={"producer": "trace", "attribution": "observed_in_window",
                          "scope": {"capture_id": "t1"}, "items": []},
    )
    assert joined["producers"] == ["attack_surface", "hexrays", "dynamic"]
    assert joined["decompile"]["chars"] == len("int f() { return 0; }\n")
    assert joined["dynamic"]["capture_id"] == "t1"


def test_paths_stamp_address_and_keep_short_path_first(tmp_path):
    from orchestrator.tests.test_attack import _fixture
    pseudo, symbols = _fixture(tmp_path)
    config = surface.load_config()
    analysis = surface.analyze(symbols, pseudo, config, job_id="job")
    result = paths.compute(analysis, config)
    assert result["paths"][0]["edge_count"] == 1
    src = result["paths"][0]["source"]["evidence_address"]
    assert src["job_id"] == "job"
    assert src["addr"] == "0x1000"
    assert result["paths"][0]["danger_calls"] >= 1
    assert result["paths"][0]["entry_outdegree"] >= 1
    assert result["paths"][0]["attribution"] == ev.ATTRIBUTION_STATIC
    assert result["summary"]["decompile_gaps"] == 0


def test_decompile_gaps_count_failed_functions(tmp_path):
    from orchestrator.tests.test_attack import _fixture, MD5
    pseudo, symbols = _fixture(tmp_path)
    symbols["binaries"][MD5]["functions"].append({
        "addr": "0x4000", "name": "sub_4000", "decompile_ok": False,
        "calls": [],
    })
    analysis = surface.analyze(symbols, pseudo)
    assert analysis["decompile_gaps"] == 1
    assert f"{MD5}:0x4000" not in analysis["nodes"]


def test_attribution_verified_requires_one_trace(tmp_path):
    from orchestrator.tests.test_attack import _fixture, MD5
    import json
    pseudo, symbols = _fixture(tmp_path)
    config = surface.load_config()
    analysis = surface.analyze(symbols, pseudo, config)
    result = paths.compute(analysis, config)
    trace_root = tmp_path / "traces"
    only_src = trace_root / "partial"
    only_src.mkdir(parents=True)
    (only_src / "trace.json").write_text(json.dumps({
        "trace_id": "partial", "status": "ok", "binary": {"md5": MD5},
        "diff": {"functions": [{"addr": "0x1000"}]},
    }), encoding="utf-8")
    cross.apply(analysis, result, trace_root)
    two_edge = next(p for p in result["paths"] if p["edge_count"] == 2)
    assert two_edge["verified_reachable"] is False
    assert two_edge["attribution"] == ev.ATTRIBUTION_OBSERVED
    assert two_edge["observed_node_count"] >= 1


def test_unresolved_needed_lists_missing_sonames(tmp_path):
    root = tmp_path / "rootfs"
    (root / "lib").mkdir(parents=True)
    (root / "lib" / "libc.so.6").write_bytes(b"x")
    needed = ["libc.so.6", "libmissing.so.1"]
    mapped = elfchain.resolve_libs(root, needed)
    assert mapped[0] == "lib/libc.so.6"
    assert elfchain.unresolved_needed(needed, mapped) == ["libmissing.so.1"]
