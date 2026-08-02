"""Unit tests for pipeline.decompile.annotate (tagging + rule naming).

Fixtures mimic the merged data/pseudocode/<job>/symbols.json produced by
orchestrator.app.decompiler: per binary a list of function dicts with
addr/name/calls/strings/is_exported as exported by ida_export.py.
"""

import json

import pytest

from pipeline.decompile import annotate


def make_func(name, calls=(), strings=(), is_exported=False, addr="0x1000"):
    return {
        "addr": addr,
        "name": name,
        "size": 32,
        "lines": 4,
        "calls": list(calls),
        "strings": list(strings),
        "is_exported": is_exported,
        "decompile_ok": True,
        "decompile_error": None,
    }


def make_symbols(functions):
    return {
        "job_id": "testjob",
        "binaries": {
            "a" * 32: {
                "path": "firmware/bin/test",
                "arch": "mips",
                "bits": 32,
                "endianness": "be",
                "md5": "a" * 32,
                "functions": functions,
            },
        },
    }


def annotate_funcs(functions):
    symbols = make_symbols(functions)
    annotate.annotate_symbols(symbols)
    return symbols


# ---------------------------------------------------------------------------
# tagging
# ---------------------------------------------------------------------------

def test_tag_calls_dangerous():
    f = make_func("sub_401000", calls=["strcpy", "memcpy"])
    out = annotate_funcs([f])["binaries"]["a" * 32]["functions"][0]
    assert "calls_dangerous" in out["tags"]


def test_tag_dangerous_via_thunk_and_dedup_names():
    # j_ thunk prefix and IDA _N dedup suffix must still match the table
    f = make_func("sub_401000", calls=["j_system", "sprintf_0"])
    out = annotate_funcs([f])["binaries"]["a" * 32]["functions"][0]
    assert "calls_dangerous" in out["tags"]


def test_tag_network_facing_by_calls():
    f = make_func("sub_401000", calls=["socket", "recvfrom"])
    out = annotate_funcs([f])["binaries"]["a" * 32]["functions"][0]
    assert "network_facing" in out["tags"]


def test_tag_network_facing_by_strings():
    f = make_func("sub_401000", strings=["POST /cgi-bin/x HTTP/1.1", "User-Agent: curl"])
    out = annotate_funcs([f])["binaries"]["a" * 32]["functions"][0]
    assert "network_facing" in out["tags"]


def test_tag_auth_related():
    f = make_func("sub_401000", strings=["please enter your password"])
    out = annotate_funcs([f])["binaries"]["a" * 32]["functions"][0]
    assert "auth_related" in out["tags"]


def test_tag_entrypoint():
    f_exp = make_func("sub_401000", is_exported=True)
    f_main = make_func("main", addr="0x2000")
    f_plain = make_func("sub_403000", addr="0x3000")
    funcs = annotate_funcs([f_exp, f_main, f_plain])["binaries"]["a" * 32]["functions"]
    assert "entrypoint" in funcs[0]["tags"]
    assert "entrypoint" in funcs[1]["tags"]
    assert funcs[2]["tags"] == []


# ---------------------------------------------------------------------------
# rule naming
# ---------------------------------------------------------------------------

def test_rule_libc_combo_server():
    f = make_func("sub_401000", calls=["socket", "bind", "listen", "printf"])
    out = annotate_funcs([f])["binaries"]["a" * 32]["functions"][0]
    assert out["rule_name"] == "net_init_server"
    assert out["rule_source"] == "libc_combo"
    assert out["rule_confidence"] == pytest.approx(0.85)


def test_rule_libc_combo_prefers_specific_combo():
    f = make_func("sub_401000", calls=["socket", "bind", "listen", "accept", "recv"])
    out = annotate_funcs([f])["binaries"]["a" * 32]["functions"][0]
    assert out["rule_name"] == "net_run_server"


def test_rule_libc_combo_read_file():
    f = make_func("sub_401000", calls=["open", "read", "close"])
    out = annotate_funcs([f])["binaries"]["a" * 32]["functions"][0]
    assert out["rule_name"] == "sys_read_file"


def test_rule_nvram_key_get():
    f = make_func("sub_401000", calls=["getenv", "strlen"], strings=["WLAN_SSID", "x"])
    out = annotate_funcs([f])["binaries"]["a" * 32]["functions"][0]
    assert out["rule_name"] == "nvram_get_wlan_ssid"
    assert out["rule_source"] == "nvram_key"
    assert out["rule_confidence"] == pytest.approx(0.85)


def test_rule_nvram_key_beats_libc_combo():
    # both rules could fire; nvram_key is more specific and must win
    f = make_func("sub_401000", calls=["getenv", "system"], strings=["WAN_IP_ADDR"])
    out = annotate_funcs([f])["binaries"]["a" * 32]["functions"][0]
    assert out["rule_source"] == "nvram_key"
    assert out["rule_name"] == "nvram_get_wan_ip_addr"


def test_rule_string_xref_usage():
    f = make_func("sub_401000", strings=["Usage: telnetd [-b ADDR]", ""])
    out = annotate_funcs([f])["binaries"]["a" * 32]["functions"][0]
    assert out["rule_name"] == "sys_handle_telnetd"
    assert out["rule_source"] == "string_xref"


def test_rule_string_xref_domain_from_content():
    f = make_func("sub_401000", strings=["/etc/nvram.conf"])
    out = annotate_funcs([f])["binaries"]["a" * 32]["functions"][0]
    assert out["rule_name"] == "nvram_handle_nvram"
    assert out["rule_source"] == "string_xref"


def test_rule_export_symbol_cleans_camelcase():
    f = make_func("onHttpdInit", is_exported=True)
    out = annotate_funcs([f])["binaries"]["a" * 32]["functions"][0]
    assert out["rule_name"] == "on_httpd_init"
    assert out["rule_source"] == "export_symbol"
    assert out["rule_confidence"] == pytest.approx(0.90)


def test_rule_export_symbol_rejects_single_segment():
    # "start" cleans to a single segment which fails the spec pattern
    f = make_func("start", is_exported=True)
    out = annotate_funcs([f])["binaries"]["a" * 32]["functions"][0]
    assert "rule_name" not in out


def test_uniqueness_conflict_gets_suffix():
    f1 = make_func("sub_401000", calls=["getenv"], strings=["WLAN_SSID"])
    f2 = make_func("sub_402000", calls=["nvram_get"], strings=["WLAN_SSID"], addr="0x2000")
    funcs = annotate_funcs([f1, f2])["binaries"]["a" * 32]["functions"]
    assert funcs[0]["rule_name"] == "nvram_get_wlan_ssid"
    assert funcs[1]["rule_name"] == "nvram_get_wlan_ssid_2"


def test_libc_like_names_are_not_renamed():
    f = make_func("strcpy", calls=["memcpy"])
    out = annotate_funcs([f])["binaries"]["a" * 32]["functions"][0]
    assert "rule_name" not in out


def test_sub_without_evidence_keeps_name():
    f = make_func("sub_40ABCC", calls=["sub_401000"], strings=["x"])
    out = annotate_funcs([f])["binaries"]["a" * 32]["functions"][0]
    assert "rule_name" not in out
    assert out["tags"] == []


# ---------------------------------------------------------------------------
# validator + driver
# ---------------------------------------------------------------------------

def test_validator_against_naming_spec():
    v = annotate.NameValidator(annotate.load_spec())
    assert v.is_valid("http_parse_header")
    assert v.is_valid("nvram_get_wlan_ssid")
    assert not v.is_valid("sub_401000")     # banned residue
    assert not v.is_valid("HttpdMain")      # uppercase banned
    assert not v.is_valid("main")           # single segment fails pattern
    assert not v.is_valid("a" * 41)         # max_length
    assert not v.is_valid("sys_do_" + "x" * 40)


def test_annotate_file_roundtrip(tmp_path):
    symbols = make_symbols([
        make_func("sub_401000", calls=["socket", "bind", "listen"]),
        make_func("sub_402000", strings=["Usage: httpd -p PORT"], addr="0x2000"),
    ])
    path = tmp_path / "symbols.json"
    path.write_text(json.dumps(symbols), encoding="utf-8")

    stats = annotate.annotate_file(path)

    reloaded = json.loads(path.read_text(encoding="utf-8"))
    funcs = reloaded["binaries"]["a" * 32]["functions"]
    assert funcs[0]["rule_name"] == "net_init_server"
    assert "network_facing" in funcs[0]["tags"]
    assert funcs[1]["rule_name"] == "sys_handle_httpd"
    assert stats["functions"] == 2
    assert stats["named_total"] == 2
    assert stats["sub_remaining"] == 0
    assert reloaded["annotate_stats"]["named"]["libc_combo"] == 1


def test_stats_track_sub_residual():
    symbols = make_symbols([
        make_func("sub_401000", calls=["system"]),          # gets named
        make_func("sub_402000", addr="0x2000"),             # stays sub_
        make_func("helper_copy_data", addr="0x3000"),       # already named, left alone
    ])
    stats = annotate.annotate_symbols(symbols)
    assert stats["sub_initial"] == 2
    assert stats["named_total"] == 1
    assert stats["sub_remaining"] == 1
