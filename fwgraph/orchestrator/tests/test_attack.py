"""Tests for AS-1 classification, bounded paths, and CBM injection."""

import json
import sqlite3

from pipeline.attack import cross, inject, paths, surface

MD5 = "a" * 32


def _fixture(tmp_path):
    pseudo = tmp_path / "pseudocode" / "job"
    funcs = pseudo / MD5 / "functions"
    funcs.mkdir(parents=True)
    functions = [
        {"addr": "0x1000", "name": "sub_1000",
         "decompile_ok": True, "calls": ["sub_2000"],
         "strings": ["modbus request"]},
        {"addr": "0x2000", "name": "sub_2000",
         "decompile_ok": True, "calls": ["sub_3000"], "strings": []},
        {"addr": "0x3000", "name": "sub_3000",
         "decompile_ok": True, "calls": [], "strings": [],
         "libc_equiv": "strcpy"},
    ]
    code = {
        "0x1000": "int sub_1000(void) { return sub_2000(); }\n",
        "0x2000": ("char *sub_2000(char *d, char *s) { do { "
                   "*d++ = *s++; } while (*s != 0); return d; }\n"),
        "0x3000": "int sub_3000(void) { return 0; }\n",
    }
    for addr, text in code.items():
        (funcs / f"{addr}.c").write_text(text, encoding="utf-8")
    symbols = {"binaries": {MD5: {
        "path": "bin/fw", "arch": "mips", "functions": functions}}}
    return pseudo, symbols


def test_classifies_ics_and_anonymous_memunsafe(tmp_path):
    pseudo, symbols = _fixture(tmp_path)
    analysis = surface.analyze(symbols, pseudo)
    source = analysis["nodes"][f"{MD5}:0x1000"]
    anonymous = analysis["nodes"][f"{MD5}:0x2000"]
    sink = analysis["nodes"][f"{MD5}:0x3000"]
    assert source["asrc"] == ["fieldbus_ics"]
    assert "memunsafe_like" in anonymous["asink"]
    assert "memunsafe" in sink["asink"]
    assert analysis["adjacency"][f"{MD5}:0x1000"] == [f"{MD5}:0x2000"]


def test_paths_are_bounded_scored_and_deterministic(tmp_path):
    pseudo, symbols = _fixture(tmp_path)
    config = surface.load_config()
    analysis = surface.analyze(symbols, pseudo, config)
    first = paths.compute(analysis, config)
    second = paths.compute(analysis, config)
    assert first["paths"] == second["paths"]
    assert first["summary"]["paths_returned"] == 2
    assert first["paths"][0]["edge_count"] == 1
    assert len(first["paths"][0]["path_id"]) == 16
    surface.apply_annotations(symbols, analysis, first["path_ids_by_key"])
    first_func = symbols["binaries"][MD5]["functions"][0]
    assert first_func["on_attack_path"] is True


def test_inject_metadata_is_idempotent(tmp_path):
    pseudo, symbols = _fixture(tmp_path)
    config = surface.load_config()
    analysis = surface.analyze(symbols, pseudo, config)
    result = paths.compute(analysis, config)
    surface.apply_annotations(symbols, analysis, result["path_ids_by_key"])
    database = tmp_path / "graph.db"
    db = sqlite3.connect(database)
    db.execute("CREATE TABLE nodes (id TEXT, project TEXT, label TEXT, "
               "file_path TEXT, properties TEXT)")
    for func in symbols["binaries"][MD5]["functions"]:
        db.execute("INSERT INTO nodes VALUES (?, ?, 'Function', ?, '{}')",
                   (func["addr"], "fwgraph_job",
                    f"fw_{MD5[:8]}/{func['addr']}_{func['name']}.c"))
    db.commit()
    db.close()
    first = inject.inject_metadata(database, symbols, "fwgraph_job")
    second = inject.inject_metadata(database, symbols, "fwgraph_job")
    assert first == second
    assert first["matched"] == 3
    db = sqlite3.connect(database)
    props = json.loads(db.execute(
        "SELECT properties FROM nodes WHERE id='0x1000'").fetchone()[0])
    db.close()
    assert props["asrc"] == ["fieldbus_ics"]
    assert props["on_attack_path"] == 1
    assert props["observed_in_trace"] == 0
    assert props["verified_reachable"] == 0
    assert props["trace_ids"] == []


def test_fmt_sink_requires_nonliteral_format(tmp_path):
    pseudo, symbols = _fixture(tmp_path)
    functions = symbols["binaries"][MD5]["functions"]
    functions[0]["calls"] = ["printf"]
    source_file = pseudo / MD5 / "functions" / "0x1000.c"
    source_file.write_text('int f(char *s) { return printf("%s", s); }\n',
                           encoding="utf-8")
    analysis = surface.analyze(symbols, pseudo)
    assert "fmt" not in analysis["nodes"][f"{MD5}:0x1000"]["asink"]
    source_file.write_text("int f(char *s) { return printf(s); }\n",
                           encoding="utf-8")
    analysis = surface.analyze(symbols, pseudo)
    assert "fmt" in analysis["nodes"][f"{MD5}:0x1000"]["asink"]


def test_cross_validation_distinguishes_partial_and_full_path(tmp_path):
    pseudo, symbols = _fixture(tmp_path)
    config = surface.load_config()
    analysis = surface.analyze(symbols, pseudo, config)
    result = paths.compute(analysis, config)
    trace_root = tmp_path / "traces"
    partial = trace_root / "partial"
    full = trace_root / "full"
    partial.mkdir(parents=True)
    full.mkdir(parents=True)
    base = {"status": "ok", "binary": {"md5": MD5}}
    (partial / "trace.json").write_text(json.dumps({
        **base, "trace_id": "partial",
        "diff": {"functions": [{"addr": "0x1000"}]}
    }), encoding="utf-8")
    (full / "trace.json").write_text(json.dumps({
        **base, "trace_id": "full",
        "diff": {"functions": [
            {"addr": "0x1000"}, {"addr": "0x2000"},
            {"addr": "0x3000"}]}
    }), encoding="utf-8")
    stats = cross.apply(analysis, result, trace_root)
    assert stats["traces_considered"] == 2
    assert stats["verified_paths"] == 2
    two_edge = next(path for path in result["paths"]
                    if path["edge_count"] == 2)
    assert two_edge["trace_ids"] == ["full"]
    assert two_edge["observed_trace_ids"] == ["full", "partial"]
    surface.apply_annotations(symbols, analysis, result["path_ids_by_key"])
    assert all(func["observed_in_trace"]
               for func in symbols["binaries"][MD5]["functions"])
    assert all(func["verified_reachable"]
               for func in symbols["binaries"][MD5]["functions"])


def test_cross_validation_skips_bad_traces_and_isolates_binaries(tmp_path):
    other_md5 = "b" * 32
    key_a = surface.function_key(MD5, "0x1000")
    key_b = surface.function_key(other_md5, "0x1000")
    analysis = {"nodes": {
        key_a: {"binary_md5": MD5, "addr": "0x1000"},
        key_b: {"binary_md5": other_md5, "addr": "0x1000"},
    }}
    result = {"path_ids_by_key": {key_b: ["p1"]}, "paths": [{
        "binary_md5": other_md5,
        "chain": [{"addr": "0x1000"}],
    }]}
    trace_root = tmp_path / "traces"
    for trace_id in ("failed", "corrupt", "valid"):
        (trace_root / trace_id).mkdir(parents=True)
    (trace_root / "failed" / "trace.json").write_text(json.dumps({
        "trace_id": "failed", "status": "failed", "binary": {"md5": MD5},
        "diff": {"functions": [{"addr": "0x1000"}]},
    }), encoding="utf-8")
    (trace_root / "corrupt" / "trace.json").write_text("{", encoding="utf-8")
    (trace_root / "valid" / "trace.json").write_text(json.dumps({
        "trace_id": "valid", "status": "ok", "binary": {"md5": other_md5},
        "diff": {"functions": [{"addr": "0x1000"}]},
    }), encoding="utf-8")

    stats = cross.apply(analysis, result, trace_root)

    assert stats == {"traces_considered": 1, "observed_functions": 1,
                     "verified_functions": 1, "verified_paths": 1}
    assert analysis["nodes"][key_a]["observed_in_trace"] is False
    assert analysis["nodes"][key_b]["trace_ids"] == ["valid"]
    assert result["paths"][0]["verified_reachable"] is True
