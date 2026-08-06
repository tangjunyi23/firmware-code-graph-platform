"""Unit tests for M3 (pipeline.ailift): funnel, validator, registry, prompts,
libc_equiv backfill.

No network: the LLM client is never instantiated against the real API; the
runner test monkeypatches pipeline.ailift.llm.suggest_batch.
"""

import json
import sqlite3

import pytest

from pipeline.ailift import backfill, funnel, llm, runner
from pipeline.ailift.registry import Registry, SpecValidator
from pipeline.decompile.annotate import load_spec


def test_anthropic_style_chat(monkeypatch):
    """LLMClient(style="anthropic") posts Messages-API shape and parses
    text blocks (skipping thinking) plus input/output token usage."""
    import asyncio

    client = llm.LLMClient("http://gw/v1", "k", "deepseek-v4-flash",
                           style="anthropic")
    seen = {}

    async def fake_post(payload):
        seen.update(payload)
        return {
            "content": [
                {"type": "thinking", "thinking": "chain"},
                {"type": "text", "text": '{"domain": "http", "confidence": 0.9,'
                                         ' "reason": "serves http"}'},
            ],
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }

    monkeypatch.setattr(client, "_post", fake_post)
    out = asyncio.run(client.chat("sys prompt", "user prompt"))
    assert seen["system"] == "sys prompt"
    assert seen["messages"] == [{"role": "user", "content": "user prompt"}]
    assert "response_format" not in seen
    assert out["domain"] == "http"
    assert out["confidence"] == 0.9
    assert client.usage["prompt_tokens"] == 10
    assert client.usage["completion_tokens"] == 5
    assert client.usage["total_tokens"] == 15


def make_func(addr="0x1000", name="sub_1000", size=100, lines=50, calls=None,
              strings=None, tags=None, decompile_ok=True, rule_name=None,
              rule_confidence=None):
    func = {
        "addr": addr, "name": name, "size": size, "lines": lines,
        "calls": calls or [], "strings": strings or [], "tags": tags or [],
        "is_exported": False, "decompile_ok": decompile_ok,
    }
    if rule_name:
        func["rule_name"] = rule_name
        func["rule_confidence"] = rule_confidence
        func["rule_source"] = "libc_combo"
    return func


# ---------------------------------------------------------------------------
# funnel
# ---------------------------------------------------------------------------

class TestFunnel:
    def test_l1_skips_real_name(self):
        funcs = [make_func(name="printf"), make_func(name="main")]
        out = funnel.run_funnel(funcs)
        assert out["stats"]["l1_skipped"]["has_real_name"] == 2
        assert out["candidates"] == []

    def test_l1_skips_thunk_and_trivial(self):
        funcs = [
            make_func(addr="0x1", name="sub_1", calls=["malloc"], size=16),
            make_func(addr="0x2", name="sub_2", lines=4),
            make_func(addr="0x3", name="nullsub_1", lines=1),
        ]
        out = funnel.run_funnel(funcs)
        assert out["stats"]["l1_skipped"]["thunk"] == 2  # sub_1 + nullsub_1
        assert out["stats"]["l1_skipped"]["trivial"] == 1

    def test_l1_skips_high_confidence_rule_name(self):
        funcs = [make_func(rule_name="net_run_server", rule_confidence=0.85)]
        out = funnel.run_funnel(funcs)
        assert out["stats"]["l1_skipped"]["rule_named"] == 1
        assert out["candidates"] == []

    def test_low_confidence_rule_name_is_not_skipped(self):
        funcs = [make_func(rule_name="util_copy_buffer", rule_confidence=0.70,
                           strings=["hello world"])]
        out = funnel.run_funnel(funcs)
        assert len(out["candidates"]) == 1

    def test_l2_tag_gives_priority_2(self):
        funcs = [make_func(tags=["calls_dangerous"], calls=["system"])]
        out = funnel.run_funnel(funcs)
        cand = out["candidates"][0]
        assert cand["priority"] == 2
        assert "tag:calls_dangerous" in cand["reasons"]

    def test_l3_reasons(self):
        noisy = "\n".join("a = CONCAT22(b, c) + __PAIR__(d, e);" for _ in range(30))
        funcs = [
            make_func(addr="0x10", name="sub_10", decompile_ok=False, lines=0),
            make_func(addr="0x11", name="sub_11", lines=250),
            make_func(addr="0x12", name="sub_12", strings=["/etc/passwd"]),
            make_func(addr="0x13", name="sub_13", lines=30),
        ]
        # 4 callers of sub_13
        funcs += [make_func(addr=f"0x2{i}", name=f"sub_2{i}", calls=["sub_13"])
                  for i in range(4)]
        out = funnel.run_funnel(
            funcs, code_reader=lambda addr: noisy if addr == "0x13" else "int x;\n" * 30)
        by_addr = {c["addr"]: c for c in out["candidates"]}
        assert "decompile_failed" in by_addr["0x10"]["reasons"]
        assert "large_function" in by_addr["0x11"]["reasons"]
        assert "has_strings" in by_addr["0x12"]["reasons"]
        assert "many_callers" in by_addr["0x13"]["reasons"]
        assert "noisy_pseudocode" in by_addr["0x13"]["reasons"]
        assert all(c["priority"] == 1 for c in out["candidates"])

    def test_no_signal_skipped(self):
        funcs = [make_func(lines=40)]
        out = funnel.run_funnel(funcs)
        assert out["candidates"] == []
        assert out["stats"]["no_signal"] == 1

    def test_hub_tier_sorts_near_l2(self):
        # one hub (9 callers) + one plain many_callers (4) + one L2 tag
        funcs = [make_func(addr="0x10", name="sub_10", lines=30),
                 make_func(addr="0x11", name="sub_11", lines=30),
                 make_func(addr="0x12", name="sub_12", lines=30,
                           tags=["network_facing"])]
        funcs += [make_func(addr=f"0x2{i}", name=f"sub_2{i}", calls=["sub_10"])
                  for i in range(9)]
        funcs += [make_func(addr=f"0x4{i}", name=f"sub_4{i}", calls=["sub_11"])
                  for i in range(4)]
        out = funnel.run_funnel(funcs)
        by_addr = {c["addr"]: c for c in out["candidates"]}
        assert "hub_callers" in by_addr["0x10"]["reasons"]
        assert "many_callers" not in by_addr["0x10"]["reasons"]
        assert by_addr["0x10"]["priority"] == funnel.PRIORITY_HUB
        assert "many_callers" in by_addr["0x11"]["reasons"]
        assert by_addr["0x11"]["priority"] == funnel.PRIORITY_L3
        assert by_addr["0x12"]["priority"] == funnel.PRIORITY_L2
        # sort order: L2 > hub > plain L3
        assert [c["addr"] for c in out["candidates"]] == ["0x12", "0x10", "0x11"]
        # hub beats plain L3 even on truncation
        out = funnel.run_funnel(funcs, max_funcs=2)
        assert [c["addr"] for c in out["candidates"]] == ["0x12", "0x10"]

    def test_cap_and_ordering(self):
        funcs = [make_func(addr=f"0x{i:x}", name=f"sub_{i:x}",
                           tags=["network_facing"], calls=["socket"])
                 for i in range(20)]
        funcs += [make_func(addr=f"0x9{i}", name=f"sub_9{i}", lines=300)
                  for i in range(20)]
        out = funnel.run_funnel(funcs, max_funcs=15)
        assert len(out["candidates"]) == 15
        assert out["stats"]["truncated"] == 25
        assert all(c["priority"] == 2 for c in out["candidates"])  # L2 first


# ---------------------------------------------------------------------------
# validator
# ---------------------------------------------------------------------------

class TestSpecValidator:
    @pytest.fixture
    def validator(self):
        return SpecValidator(load_spec())

    def test_valid_name(self, validator):
        assert validator.check("http_parse_header") == (True, "ok")

    def test_rejects_uppercase_and_banned(self, validator):
        assert validator.check("HttpParse")[0] is False
        assert validator.check("sub_401000")[0] is False
        assert validator.check("util_handle_thing")[0] is False

    def test_rejects_shape_and_length(self, validator):
        assert validator.check("init")[0] is False           # single segment
        assert validator.check("_lead_underscore")[0] is False
        assert validator.check("a" * 41)[0] is False
        assert validator.check("util_" + "_".join(["x"] * 6))[0] is False  # >5 segs

    def test_domain_vocab(self, validator):
        assert validator.check("foo_process_bar")[0] is False  # unknown domain
        assert validator.check("get_config")[0] is True        # generic verb first
        assert validator.check("nvram_get_wifi_key")[0] is True

    def test_libc_conflict_gets_impl(self, validator):
        name, why = validator.resolve("net_recv_data",
                                      known_names={"net_recv_data"}, used=set())
        assert (name, why) == ("net_recv_data_impl", "ok")

    def test_uniqueness_gets_numeric_suffix(self, validator):
        name, _ = validator.resolve("http_parse_header", known_names=set(),
                                    used={"http_parse_header",
                                          "http_parse_header_2"})
        assert name == "http_parse_header_3"

    def test_impl_then_unique(self, validator):
        name, _ = validator.resolve("net_recv_data",
                                    known_names={"net_recv_data"},
                                    used={"net_recv_data_impl"})
        assert name == "net_recv_data_impl_2"


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------

class TestRegistry:
    def test_record_lookup_renames(self, tmp_path):
        reg = Registry(tmp_path / "reg.db")
        assert reg.record("job", "m1", "0x10", "sub_10", "net_recv_data",
                          0.9, "reads socket", "ai", "accepted")
        assert reg.is_resolved("m1", "0x10")
        assert reg.renames("m1") == {"0x10": "net_recv_data"}
        reg.mark_done("m1")
        assert reg.pending_apply("m1") == 0
        assert reg.stats()["done"] == 1
        reg.close()

    def test_low_confidence_yields_to_high(self, tmp_path):
        reg = Registry(tmp_path / "reg.db")
        reg.record("job", "m1", "0x10", "sub_10", "net_recv_data", 0.8,
                   "first", "ai", "accepted")
        # lower confidence must not replace
        assert not reg.record("job", "m1", "0x10", "sub_10", "sys_read_file",
                              0.7, "second", "ai", "accepted")
        assert reg.lookup("m1", "0x10")["new_name"] == "net_recv_data"
        # strictly higher replaces
        assert reg.record("job", "m1", "0x10", "sub_10", "net_parse_packet",
                          0.95, "third", "ai", "accepted")
        row = reg.lookup("m1", "0x10")
        assert row["new_name"] == "net_parse_packet"
        assert row["confidence"] == 0.95
        reg.close()

    def test_error_rows_are_retryable(self, tmp_path):
        reg = Registry(tmp_path / "reg.db")
        reg.record("job", "m1", "0x10", "sub_10", None, None, "timeout",
                   "ai", "error")
        assert not reg.is_resolved("m1", "0x10")
        assert reg.record("job", "m1", "0x10", "sub_10", "util_copy_buffer",
                          0.7, "ok", "ai", "accepted")
        reg.close()

    def test_libc_equiv_roundtrip_and_stats(self, tmp_path):
        reg = Registry(tmp_path / "reg.db")
        reg.record("job", "m1", "0x10", "sub_10", "util_strcpy", 0.9,
                   "copies strings", "ai", "accepted", libc_equiv="strcpy",
                   domain="util")
        reg.record("job", "m1", "0x20", "sub_20", "http_parse_config", 0.8,
                   "parses", "ai", "accepted")
        assert reg.lookup("m1", "0x10")["libc_equiv"] == "strcpy"
        assert reg.lookup("m1", "0x20")["libc_equiv"] is None
        assert reg.stats()["libc_equiv"] == 1
        assert reg.stats()["domain"] == 1
        assert reg.samples(1)[0]["libc_equiv"] == "strcpy"
        assert reg.samples(1)[0]["domain"] == "util"
        reg.close()

    def test_pre_libc_equiv_db_is_migrated(self, tmp_path):
        # a registry db created before the libc_equiv column existed
        db_path = tmp_path / "old.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "CREATE TABLE name_registry ("
            "job_id TEXT NOT NULL, md5 TEXT NOT NULL, addr TEXT NOT NULL,"
            "old_name TEXT, new_name TEXT, confidence REAL, reason TEXT,"
            "source TEXT, status TEXT NOT NULL, ts TEXT,"
            " UNIQUE(md5, addr))")
        conn.execute(
            "INSERT INTO name_registry (job_id, md5, addr, old_name, new_name,"
            " confidence, reason, source, status, ts)"
            " VALUES ('j', 'm1', '0x10', 'sub_10', 'util_strcpy', 0.9,"
            " 'r', 'ai', 'accepted', 't')")
        conn.commit()
        conn.close()
        reg = Registry(db_path)  # must ALTER TABLE, not crash
        row = reg.lookup("m1", "0x10")
        assert row["new_name"] == "util_strcpy"
        assert row["libc_equiv"] is None
        assert row["domain"] is None
        reg.close()


# ---------------------------------------------------------------------------
# backfill (heuristic libc_equiv, zero tokens)
# ---------------------------------------------------------------------------

class TestBackfill:
    @pytest.mark.parametrize("name,expected", [
        ("util_strcpy", "strcpy"),
        ("sys_memcpy", "memcpy"),
        ("net_socket", "socket"),
        ("log_printf", "printf"),
        ("sys_setenv", "setenv"),
        ("util_strncpy", "strncpy"),
        ("socket", "socket"),            # full-name hit (no prefix needed)
        ("util_strcpy_impl", None),      # not an exact symbol after the prefix
        ("util_free_mem", None),
        ("http_parse_config", None),
        ("net_send_mail", None),
        ("firmware_strcpy", None),       # unknown domain prefix
        ("sub_401000", None),
        ("", None),
        (None, None),
    ])
    def test_guess_libc_equiv(self, name, expected):
        assert backfill.guess_libc_equiv(name) == expected

    def test_symbol_table_size_and_shape(self):
        assert 150 <= len(backfill.LIBC_SYMBOLS) <= 250
        for sym in backfill.LIBC_SYMBOLS:
            assert llm.LIBC_EQUIV_RE.match(sym), sym

    def test_backfill_registry(self, tmp_path):
        reg = Registry(tmp_path / "reg.db")
        reg.record("job", "m1", "0x10", "sub_10", "util_strcpy", 0.9,
                   "r", "ai", "accepted")
        reg.record("job", "m1", "0x20", "sub_20", "http_parse_config", 0.9,
                   "r", "ai", "accepted")
        reg.record("job", "m1", "0x30", "sub_30", "util_memcpy", 0.9,
                   "r", "ai", "accepted", libc_equiv="memcpy")
        reg.record("job", "m1", "0x40", "sub_40", "util_strcat", 0.5,
                   "r", "ai", "rejected")
        out = backfill.backfill_registry(reg)
        # 0x30 already has libc_equiv; 0x40 is rejected: both out of scope
        assert out["checked"] == 2
        assert out["updated"] == 1
        assert out["hits"] == {"util_strcpy": "strcpy"}
        assert reg.lookup("m1", "0x10")["libc_equiv"] == "strcpy"
        assert reg.lookup("m1", "0x10")["source"] == "backfill"
        assert reg.lookup("m1", "0x20")["libc_equiv"] is None
        assert reg.lookup("m1", "0x30")["libc_equiv"] == "memcpy"
        assert reg.lookup("m1", "0x30")["source"] == "ai"  # untouched
        again = backfill.backfill_registry(reg)
        assert again["updated"] == 0  # idempotent
        reg.close()

    def test_backfill_job_patches_symbols_json(self, tmp_path):
        job = "jobbf"
        pseudo = tmp_path / "pseudocode" / job
        pseudo.mkdir(parents=True)
        symbols = {"job_id": job, "binaries": {"m1": {
            "path": "bin/x", "arch": "mips",
            "functions": [
                {"addr": "0x10", "name": "util_strcpy", "decompile_ok": True},
                {"addr": "0x20", "name": "sub_20", "decompile_ok": True}]}}}
        (pseudo / "symbols.json").write_text(json.dumps(symbols),
                                             encoding="utf-8")
        reg = Registry(pseudo / "name_registry.db")
        reg.record(job, "m1", "0x10", "sub_10", "util_strcpy", 0.9,
                   "r", "ai", "accepted")
        reg.close()
        out = backfill.backfill_job(job, tmp_path)
        assert out["updated"] == 1
        assert out["symbols_patched"] == 1
        patched = json.loads((pseudo / "symbols.json").read_text())
        funcs = {f["addr"]: f for f in patched["binaries"]["m1"]["functions"]}
        assert funcs["0x10"]["libc_equiv"] == "strcpy"
        assert "libc_equiv" not in funcs["0x20"]


# ---------------------------------------------------------------------------
# prompts / parsing
# ---------------------------------------------------------------------------

class TestPrompts:
    def test_system_prompt_carries_domains_and_json_constraint(self):
        prompt = llm.build_system_prompt({"http", "net"})
        assert "http" in prompt and "net" in prompt
        assert "ONLY a JSON object" in prompt
        assert '"domain"' in prompt
        assert "immutable" in prompt
        assert "sk-" not in prompt  # no API key leakage

    def test_system_prompt_asks_libc_question(self):
        prompt = llm.build_system_prompt({"util"})
        assert "libc" in prompt
        assert '"libc_equiv"' in prompt       # present in the JSON template
        assert "or null" in prompt
        assert "strcpy" in prompt             # example canonical name

    def test_user_prompt_contents_and_truncation(self):
        func = make_func(name="sub_401000", tags=["network_facing"],
                         calls=["socket", "recv"],
                         strings=["http://x/y", "User-Agent: z"])
        pseudo = "int x;\n" * 2000  # > MAX_PSEUDOCODE_CHARS
        prompt = llm.build_user_prompt(func, pseudo, ["sub_400000"],
                                       binary_path="bin/busybox", arch="mips")
        assert "sub_401000" in prompt
        assert "network_facing" in prompt
        assert "socket" in prompt and "sub_400000" in prompt
        assert "http://x/y" in prompt
        assert "JSON only" in prompt
        assert len(prompt) < llm.MAX_PSEUDOCODE_CHARS + 3000

    def test_parse_json_object_strict_and_fallback(self):
        out = llm.parse_json_object('{"domain":"net","confidence":0.9,'
                                    '"reason":"reads from socket",'
                                    '"libc_equiv":null}')
        assert out == {"domain": "net", "confidence": 0.9,
                       "reason": "reads from socket", "libc_equiv": None}
        md = 'Sure! ```json\n{"domain":null,"libc_equiv":null,' \
             '"confidence":1.7}\n```'
        out = llm.parse_json_object(md)
        assert out["domain"] is None
        assert out["confidence"] == 1.0  # clamped
        with pytest.raises(ValueError):
            llm.parse_json_object("no json here at all")

    def test_parse_libc_equiv_schema(self):
        out = llm.parse_json_object(
            '{"domain":"util","confidence":0.9,"reason":"copies",'
            '"libc_equiv":"strcpy"}')
        assert out["libc_equiv"] == "strcpy"
        # compiler built-ins keep their leading underscores
        out = llm.parse_json_object(
            '{"domain":"util","libc_equiv":"__divdi3"}')
        assert out["libc_equiv"] == "__divdi3"
        # explicit null / missing / schema violations all normalize to None
        assert llm.parse_json_object(
            '{"domain":null,"libc_equiv":null}')["libc_equiv"] is None
        assert llm.parse_json_object(
            '{"domain":null,"libc_equiv":"StrCpy"}')["libc_equiv"] is None
        assert llm.parse_json_object(
            '{"domain":null,"libc_equiv":"not a libc fn"}')["libc_equiv"] is None
        assert llm.parse_json_object(
            '{"domain":null,"libc_equiv":""}')["libc_equiv"] is None
        assert llm.parse_libc_equiv(42) is None


# ---------------------------------------------------------------------------
# runner phase A with a mocked LLM
# ---------------------------------------------------------------------------

class TestRunnerPhaseA:
    def _make_job(self, tmp_path):
        job_id = "jobtest"
        md5 = "abc123"
        funcs_dir = tmp_path / "pseudocode" / job_id / md5 / "functions"
        funcs_dir.mkdir(parents=True)
        functions = [
            make_func(addr="0x1000", name="sub_1000", tags=["calls_dangerous"],
                      calls=["system"], strings=["/bin/sh"]),
            make_func(addr="0x2000", name="sub_2000", lines=300),
            make_func(addr="0x3000", name="sub_3000", lines=5),  # trivial
        ]
        for func in functions:
            (funcs_dir / f"{func['addr']}.c").write_text(
                f"// addr={func['addr']} name={func['name']}\nint f();\n",
                encoding="utf-8")
        symbols = {"job_id": job_id, "binaries": {md5: {
            "path": "bin/busybox", "arch": "mips", "md5": md5,
            "functions": functions}}}
        pseudo_root = tmp_path / "pseudocode" / job_id
        (pseudo_root / "symbols.json").write_text(json.dumps(symbols),
                                                  encoding="utf-8")
        return job_id, md5, pseudo_root

    def test_job_budget_prefers_web_binary_over_library(self, tmp_path):
        pseudo = tmp_path / "pseudocode" / "job"
        symbols = {"binaries": {
            "lib": {
                "path": "firmware/lib/libgeneric.so",
                "functions": [make_func(
                    addr="0x1000", name="sub_1000",
                    tags=["calls_dangerous"], strings=["system"])]},
            "web": {
                "path": "firmware/usr/sbin/httpd",
                "functions": [make_func(
                    addr="0x2000", name="sub_2000",
                    tags=["calls_dangerous"], strings=["request"])]},
        }}
        plans, selected, stats = runner._plan_job_candidates(
            symbols, pseudo, max_funcs=150, noise_ratio=0.2, max_job=1)
        assert set(plans) == {"lib", "web"}
        assert selected == {"web": {"0x2000"}}
        assert stats == {
            "eligible": 2, "selected": 1, "truncated": 1,
            "selected_binaries": 1, "attack_chains_only": False}

    def test_attack_chains_only_filters_candidates(self, tmp_path):
        md5 = "abc123"
        symbols = {"binaries": {md5: {
            "path": "firmware/usr/sbin/sysapihttpd",
            "functions": [
                make_func(addr="0x1000", name="main", calls=["sub_2000"]),
                make_func(addr="0x2000", name="sub_2000",
                          tags=["calls_dangerous"], calls=["system"]),
                make_func(addr="0x3000", name="sub_3000",
                          tags=["network_facing"]),
            ]}}}
        _plans, selected, stats = runner._plan_job_candidates(
            symbols, tmp_path, max_funcs=150, noise_ratio=0.2, max_job=10,
            attack_only=True)
        # main -> sub_2000(system) is the only attack chain; the
        # network_facing sub_3000 stays off-chain and is not tagged.
        assert selected == {md5: {"0x2000"}}
        assert stats["eligible"] == 1
        assert stats["attack_chains_only"] is True

        _plans, selected, stats = runner._plan_job_candidates(
            symbols, tmp_path, max_funcs=150, noise_ratio=0.2, max_job=10,
            attack_only=False)
        assert selected == {md5: {"0x2000", "0x3000"}}
        assert stats["eligible"] == 2

    def test_zero_job_budget_selects_no_candidates(self, tmp_path):
        symbols = {"binaries": {"main": {
            "path": "firmware/bin/main",
            "functions": [make_func(
                addr="0x1000", name="sub_1000", strings=["input"])]}}}
        _plans, selected, stats = runner._plan_job_candidates(
            symbols, tmp_path, max_funcs=150, noise_ratio=0.2, max_job=0)
        assert selected == {}
        assert stats["eligible"] == 1
        assert stats["selected"] == 0
        assert stats["truncated"] == 1

    def test_phase_a_mocked_llm(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AI_ATTACK_CHAINS_ONLY", "0")
        job_id, md5, pseudo_root = self._make_job(tmp_path)

        def fake_suggest_batch(client, items):
            assert len(items) == 2  # trivial one filtered by the funnel
            assert "ONLY a JSON object" in items[0]["system"]
            return [
                (items[0], {"domain": "sys", "confidence": 0.9,
                            "reason": "invokes system()",
                            "libc_equiv": "system"}, None),
                (items[1], {"domain": "not-a-domain", "confidence": 0.9,
                            "reason": "bad", "libc_equiv": None}, None),
            ]

        monkeypatch.setattr(llm, "suggest_batch", fake_suggest_batch)
        summary = runner.run_job(job_id, tmp_path)

        reg = Registry(pseudo_root / "name_registry.db")
        assert reg.renames(md5) == {}
        row = reg.lookup(md5, "0x1000")
        assert row["new_name"] is None and row["domain"] == "sys"
        stats = reg.stats()
        assert stats["done"] == 1 and stats["rejected"] == 1
        reg.close()

        assert not (pseudo_root / "renames.json").exists()
        symbols = json.loads((pseudo_root / "symbols.json").read_text())
        by_addr = {f["addr"]: f
                   for f in symbols["binaries"][md5]["functions"]}
        assert by_addr["0x1000"]["name"] == "sub_1000"
        assert "ai_name" not in by_addr["0x1000"]
        assert by_addr["0x1000"]["domain"] == "sys"
        assert by_addr["0x1000"]["libc_equiv"] == "system"
        assert by_addr["0x1000"]["ai_confidence"] == 0.9
        assert "domain" not in by_addr["0x2000"]
        assert summary["binaries"][md5]["tagged"] == 1
        assert summary["mode"] == "tag"

        # resume: second run sends nothing to the LLM
        def fail_batch(client, items):  # pragma: no cover - must not be hit
            raise AssertionError(f"LLM called on resume with {len(items)} items")
        monkeypatch.setattr(llm, "suggest_batch", fail_batch)
        runner.run_job(job_id, tmp_path)

    def test_llm_error_is_resumable(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AI_ATTACK_CHAINS_ONLY", "0")
        job_id, md5, pseudo_root = self._make_job(tmp_path)

        monkeypatch.setattr(llm, "suggest_batch", lambda client, items: [
            (item, None, "Timeout: boom") for item in items])
        runner.run_job(job_id, tmp_path)
        reg = Registry(pseudo_root / "name_registry.db")
        assert reg.stats()["error"] == 2
        assert not reg.renames(md5)
        reg.close()

        # next run retries the errored functions and succeeds
        monkeypatch.setattr(llm, "suggest_batch", lambda client, items: [
            (item, {"domain": "sys", "confidence": 0.8,
                    "reason": "ok", "libc_equiv": None}, None)
            for item in items])
        runner.run_job(job_id, tmp_path)
        reg = Registry(pseudo_root / "name_registry.db")
        assert reg.stats()["done"] == 2
        reg.close()

    def test_libc_equiv_flows_to_registry_and_symbols(self, tmp_path,
                                                      monkeypatch):
        monkeypatch.setenv("AI_ATTACK_CHAINS_ONLY", "0")
        job_id, md5, pseudo_root = self._make_job(tmp_path)
        symbols_path = pseudo_root / "symbols.json"
        symbols = json.loads(symbols_path.read_text())
        symbols["binaries"][md5]["functions"][1]["rule_name"] = "util_strcpy"
        symbols_path.write_text(json.dumps(symbols), encoding="utf-8")

        def fake_suggest_batch(client, items):
            return [
                (items[0], {"domain": "sys", "confidence": 0.9,
                            "reason": "invokes system()",
                            "libc_equiv": "system"}, None),
                # LLM leaves libc_equiv null; backfill must catch it
                (items[1], {"domain": "util", "confidence": 0.9,
                            "reason": "copies strings",
                            "libc_equiv": None}, None),
            ]

        monkeypatch.setattr(llm, "suggest_batch", fake_suggest_batch)
        summary = runner.run_job(job_id, tmp_path)

        reg = Registry(pseudo_root / "name_registry.db")
        assert reg.lookup(md5, "0x1000")["libc_equiv"] == "system"
        row = reg.lookup(md5, "0x2000")
        assert row["libc_equiv"] == "strcpy"
        assert row["source"] == "backfill"
        reg.close()

        symbols = json.loads((pseudo_root / "symbols.json").read_text())
        by_addr = {f["addr"]: f
                   for f in symbols["binaries"][md5]["functions"]}
        assert by_addr["0x1000"]["libc_equiv"] == "system"
        assert by_addr["0x2000"]["libc_equiv"] == "strcpy"
        assert by_addr["0x2000"]["domain"] == "util"
        assert summary["backfill"][md5] == {"checked": 0, "updated": 0}
