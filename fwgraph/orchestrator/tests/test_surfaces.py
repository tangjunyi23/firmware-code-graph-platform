"""Tests for pipeline.surfaces (per-input attack-surface export, M6b)."""

import json
from pathlib import Path

import pytest

from pipeline.surfaces import classify, runner


def _symbols(md5="m" * 32):
    return {
        "job_id": "job1",
        "binaries": {
            md5: {
                "path": "usr/sbin/lighttpd",
                "arch": "mips32le",
                "functions": [
                    {"addr": "0x401000", "name": "main", "decompile_ok": True,
                     "calls": ["socket", "bind", "listen", "accept",
                               "http_request_parse", "dispatch_request"],
                     "strings": ["http/1.1"], "tags": ["entrypoint",
                                                       "network_facing"]},
                    {"addr": "0x401100", "name": "http_request_parse",
                     "decompile_ok": True,
                     "calls": ["strtok", "sscanf", "url_decode"],
                     "strings": ["content-length"], "tags": []},
                    {"addr": "0x401200", "name": "url_decode",
                     "decompile_ok": True, "calls": [], "strings": [],
                     "tags": []},
                    {"addr": "0x401300", "name": "dispatch_request",
                     "decompile_ok": True, "calls": ["handle_login"],
                     "strings": [], "tags": []},
                    {"addr": "0x401400", "name": "handle_login",
                     "decompile_ok": True, "calls": ["auth_check"],
                     "strings": ["password"], "tags": []},
                    {"addr": "0x401500", "name": "auth_check",
                     "decompile_ok": True, "calls": ["strcmp"],
                     "strings": ["password"], "tags": ["auth_related"]},
                ],
            },
        },
    }


def _inputs_doc():
    return {
        "metadata": {"total_inputs": 2},
        "inputs": [
            {"id": "IN-001", "protocol": "http", "service": "lighttpd",
             "address": "0.0.0.0", "port": 80, "transport": "tcp",
             "public": True, "input_types": ["URL path", "POST body"],
             "entry_files": ["usr/sbin/lighttpd"],
             "processing_chain": [], "dispatch_chain": [],
             "evidence": "test", "notes": ""},
            {"id": "IN-002", "protocol": "dns", "service": "dnsmasq",
             "address": "0.0.0.0", "port": 53, "transport": "udp",
             "public": True, "input_types": ["DNS query packets"],
             "entry_files": ["usr/sbin/dnsmasq"],
             "processing_chain": [], "dispatch_chain": [],
             "evidence": "test", "notes": ""},
        ],
    }


def _write_pseudo(pseudo_root: Path, md5="m" * 32):
    d = pseudo_root / md5 / "functions"
    d.mkdir(parents=True)
    (d / "0x401400.c").write_text(
        "// addr=0x401400 name=handle_login\n"
        "int handle_login(void *req) {\n"
        "  char *user = getenv(\"HTTP_AUTHORIZATION\");\n"
        "  char buf[64];\n"
        "  recv(fd, buf, 63, 0);\n"
        "  char name[32];\n"
        "  sscanf(buf, \"user=%s\", name);\n"
        "}\n", encoding="utf-8")
    (d / "0x401500.c").write_text(
        "// addr=0x401500 name=auth_check\n"
        "int auth_check(char *input, char *password) {\n"
        "  if (strcmp(input, password) != 0)\n"
        "    return -1;   /* reject branch */\n"
        "  return 0;\n"
        "}\n", encoding="utf-8")
    for addr, name in (("0x401000", "main"), ("0x401100", "http_request_parse"),
                       ("0x401200", "url_decode"),
                       ("0x401300", "dispatch_request")):
        (d / f"{addr}.c").write_text(f"// {name}\nvoid {name}(void){{}}\n",
                                     encoding="utf-8")


def _busybox_symbols(md5="b" * 32):
    """busybox-style multicall binary: a dispatcher referencing the exact
    applet-name string, plus an unrelated applet that must stay out."""
    return {
        "job_id": "job1",
        "binaries": {
            md5: {
                "path": "bin/busybox",
                "arch": "arm32le",
                "functions": [
                    {"addr": "0x1000", "name": "main", "decompile_ok": True,
                     "calls": ["applet_dispatch"], "strings": [],
                     "tags": ["entrypoint"]},
                    {"addr": "0x2000", "name": "applet_dispatch",
                     "decompile_ok": True, "calls": ["sub_3000"],
                     "strings": ["telnetd", "usage: telnetd"], "tags": []},
                    {"addr": "0x3000", "name": "sub_3000",
                     "decompile_ok": True,
                     "calls": ["recv", "telnet_proto_parse"],
                     "strings": [], "tags": []},
                    {"addr": "0x3100", "name": "telnet_proto_parse",
                     "decompile_ok": True, "calls": ["strtok"],
                     "strings": [], "tags": []},
                    {"addr": "0x4000", "name": "sub_4000",
                     "decompile_ok": True, "calls": ["http_get_parse"],
                     "strings": ["wget"], "tags": []},
                    {"addr": "0x4100", "name": "http_get_parse",
                     "decompile_ok": True, "calls": ["sscanf"],
                     "strings": ["content-length"], "tags": []},
                ],
            },
        },
    }


def test_classify_roles():
    funcs = {f["addr"]: f for f in _symbols()["binaries"]["m" * 32]
             ["functions"]}
    assert "accept" in classify.classify_function(funcs["0x401000"], "")
    assert "parse" in classify.classify_function(funcs["0x401100"], "")
    assert "normalize" in classify.classify_function(funcs["0x401200"], "")
    assert "dispatch" in classify.classify_function(funcs["0x401300"], "")
    assert "handler" in classify.classify_function(funcs["0x401400"], "")
    assert "auth" in classify.classify_function(funcs["0x401500"], "")


def test_stub_name_detection():
    assert classify.is_stub_name("__imp_websDefineHandler")
    assert classify.is_stub_name("j_websAddRoute")
    assert classify.is_stub_name("thunk_foo")
    assert not classify.is_stub_name("websDefineHandler")
    assert not classify.is_stub_name("sub_12A80")
    assert not classify.is_stub_name(None)


def test_carrier_bindings_from_source():
    func = {"addr": "0x401400", "name": "handle_login"}
    src = ("char *user = getenv(\"QUERY_STRING\");\n"
           "recv(fd, buf, 63, 0);\n"
           "sscanf(buf, \"user=%s\", name);\n")
    b = classify.extract_carrier_bindings(func, src)
    carriers = " ".join(x["carrier"] for x in b)
    assert "QUERY_STRING" in carriers
    assert any(x["destination"] == "buf" for x in b)
    assert any(x["destination"] == "name" for x in b)
    assert all("0x401400:" in x["evidence"] for x in b)


def test_carrier_accessor_token_matching():
    # substring accidents must not bind: platform_get / format() are not
    # form accessors; websGetVar(wp, "name") binds its quoted parameter
    func = {"addr": "0x9", "name": "h"}
    src = ("v1 = platform_get(\"format\");\n"
           "v2 = format(\"mount\", 1);\n"
           "v3 = websGetVar(wp, \"username\");\n")
    b = classify.extract_carrier_bindings(func, src)
    dests = {x["destination"] for x in b}
    assert "v1" not in dests and "v2" not in dests
    hit = [x for x in b if x["destination"] == "v3"]
    assert hit and "username" in hit[0]["carrier"]


def test_carrier_read_fd_discrimination():
    func = {"addr": "0x9", "name": "h"}
    file_src = ("fd = fopen(\"/etc/cfg\", \"r\");\n"
                "read(fd, cfgbuf, 16);\n")
    b = classify.extract_carrier_bindings(func, file_src)
    assert any(x["carrier"] == "file content buffer" and
               x["destination"] == "cfgbuf" for x in b)
    sock_src = ("s = socket(2, 1, 0);\n"
                "read(s, netbuf, 16);\n")
    b = classify.extract_carrier_bindings(func, sock_src)
    assert any(x["carrier"] == "socket/request buffer" and
               x["destination"] == "netbuf" for x in b)


def test_auth_evidence_requires_structure():
    # compare call + password-class data + rejection branch
    good = {"addr": "0x1", "name": "verify", "calls": ["strcmp"],
            "strings": ["password"]}
    assert classify.auth_evidence(good, "if (strcmp(a,b)) return -1;")
    # no rejection branch -> not evidence
    assert classify.auth_evidence(good, "strcmp(a, b); return 0;") is None
    # no credential-class data -> not evidence
    other = {"addr": "0x2", "name": "cmp_version", "calls": ["strcmp"],
             "strings": ["1.2.3"]}
    assert classify.auth_evidence(
        other, "if (strcmp(a,b)) return -1;") is None
    # no compare call -> not evidence
    nocomp = {"addr": "0x3", "name": "check", "calls": ["free"],
              "strings": ["password"]}
    assert classify.auth_evidence(nocomp, "return -1;") is None


def test_build_surfaces_full(tmp_path):
    md5 = "m" * 32
    pseudo_root = tmp_path / "pseudocode" / "job1"
    _write_pseudo(pseudo_root, md5)
    doc = _inputs_doc()
    surfaces, auth_docs = runner.build_surfaces(
        doc, _symbols(md5), routes=[], pseudo_root=pseudo_root)
    assert len(surfaces) == 2

    s1 = next(s for s in surfaces if s["surface_id"] == "AS-001")
    stages = [r["stage"] for r in s1["routing_path"]]
    assert stages[0] == "listen"
    assert "accept" in stages
    assert s1["parsers"], "http_request_parse should be a parser"
    assert any("url_decode" in n["function"] for n in s1["normalizers"])
    assert s1["final_handler"]["function"] == "handle_login"
    assert s1["dispatchers"]
    assert s1["auth_chain_refs"] == ["AS-AUTH-001"]
    assert auth_docs and auth_docs[0]["applies_to"] == ["AS-001"]
    assert auth_docs[0]["chain"][0]["stage"] == "credential-verify"
    dests = " ".join(b["destination"] for b in s1["carrier_bindings"])
    assert "user" in dests or "buf" in dests

    errors, warnings = runner.validate(doc, surfaces, auth_docs)
    assert errors == []

    # static-only surface (dnsmasq not decompiled) still schema-complete,
    # with the placeholder split out of the real bindings
    s2 = next(s for s in surfaces if s["surface_id"] == "AS-002")
    assert s2["final_handler"]["function"] == "unknown"
    assert s2["carrier_bindings"] == []
    assert s2["carrier_hint"]["quality"] == "placeholder"
    assert any("static-only" in w for w in warnings)
    assert any("placeholder" in w for w in warnings)


def test_stub_final_handler_gate_fails(tmp_path):
    # gate: an import stub/thunk must never occupy final_handler
    doc = _inputs_doc()
    surfaces, auth_docs = runner.build_surfaces(doc, None, None,
                                                tmp_path / "none")
    bad = dict(surfaces[0])
    bad["final_handler"] = {"file": "bin/httpd",
                            "function": "__imp_websDefineHandler",
                            "route": "", "detail": "forged"}
    errors, _ = runner.validate(doc, [bad] + surfaces[1:], auth_docs)
    assert any("stub" in e or "thunk" in e for e in errors)


def test_applet_anchor_trims_busybox_roam(tmp_path):
    md5 = "b" * 32
    doc = {"metadata": {"total_inputs": 1},
           "inputs": [{"id": "IN-001", "protocol": "telnet",
                       "service": "telnetd", "address": None, "port": 23,
                       "transport": "tcp", "public": True,
                       "input_types": ["telnet IAC negotiation"],
                       "entry_files": ["usr/sbin/telnetd", "bin/busybox"],
                       "processing_chain": [], "dispatch_chain": [],
                       "evidence": "t", "notes": ""}]}
    surfaces, _ = runner.build_surfaces(doc, _busybox_symbols(md5), [],
                                        tmp_path / "none")
    s = surfaces[0]
    assert "applet-anchored" in s["evidence"]
    # the unrelated wget-side parser must stay out of the telnetd surface
    assert all("http_get_parse" not in p["function"] for p in s["parsers"])
    assert any("telnet_proto_parse" in p["function"] for p in s["parsers"])
    assert s.get("applet_boundary") != "unresolved"


def test_applet_boundary_unresolved_no_roam(tmp_path):
    md5 = "b" * 32
    sym = _busybox_symbols(md5)
    # remove every applet-name string -> boundary cannot be resolved
    for f in sym["binaries"][md5]["functions"]:
        f["strings"] = [s for s in f["strings"] if s != "telnetd"]
        if f["name"] == "applet_dispatch":
            f["strings"] = []
    doc = {"metadata": {"total_inputs": 1},
           "inputs": [{"id": "IN-001", "protocol": "telnet",
                       "service": "telnetd", "address": None, "port": 23,
                       "transport": "tcp", "public": True,
                       "input_types": ["telnet IAC negotiation"],
                       "entry_files": ["bin/busybox"],
                       "processing_chain": [], "dispatch_chain": [],
                       "evidence": "t", "notes": ""}]}
    surfaces, _ = runner.build_surfaces(doc, sym, [], tmp_path / "none")
    s = surfaces[0]
    stages = [r["stage"] for r in s["routing_path"]]
    assert "unresolved" in stages
    assert s["parsers"] == [] and s["dispatchers"] == []
    assert "multicall binary, applet boundary unresolved" in s["evidence"]
    assert s.get("applet_boundary") == "unresolved"
    assert s.get("confidence") == "low"


def test_cross_library_route_attribution(tmp_path):
    # GoAhead route table lives in libgo.so; the httpd input whose
    # processing chain links libgo.so owns those routes
    md5_h, md5_g = "h" * 32, "g" * 32
    symbols = {"job_id": "job1", "binaries": {
        md5_h: {"path": "squashfs-root/bin/httpd", "arch": "arm32le",
                "functions": [
                    {"addr": "0x1000", "name": "main", "decompile_ok": True,
                     "calls": ["__imp_websDefineHandler"], "strings": [],
                     "tags": ["entrypoint", "network_facing"]}]},
        md5_g: {"path": "squashfs-root/lib/libgo.so", "arch": "arm32le",
                "functions": [
                    {"addr": "0x9000", "name": "RealHandler",
                     "decompile_ok": True, "calls": [], "strings": [],
                     "tags": []}]},
    }}
    doc = {"metadata": {"total_inputs": 1},
           "inputs": [{"id": "IN-001", "protocol": "http",
                       "service": "httpd", "address": None, "port": 80,
                       "transport": "tcp", "public": True,
                       "input_types": ["URL path"],
                       "entry_files": ["squashfs-root/bin/httpd"],
                       "processing_chain": [{
                           "file": "squashfs-root/bin/httpd",
                           "libs": ["lib/libgo.so"]}],
                       "dispatch_chain": [], "evidence": "t", "notes": ""}]}
    routes = [{"route": "/goform/ate", "method": None, "confidence": 0.98,
               "binary_path": "squashfs-root/lib/libgo.so",
               "handler_addr": "0x9000", "handler_name": "RealHandler"},
              {"route": "/goform/stub", "method": None, "confidence": 0.99,
               "binary_path": "squashfs-root/lib/libgo.so",
               "handler_addr": "0x118", "handler_name": "__imp_websError"}]
    surfaces, _ = runner.build_surfaces(doc, symbols, routes,
                                        tmp_path / "none")
    s = surfaces[0]
    # the higher-confidence route points at an import stub and must be
    # skipped in favour of the real handler
    assert s["final_handler"]["function"] == "RealHandler"
    assert [e["route"] for e in s["endpoints"]] == ["/goform/ate"]
    errors, _ = runner.validate(doc, surfaces, [])
    assert errors == []


def test_goahead_routes_from_pseudocode(tmp_path):
    md5 = "r" * 32
    symbols = {"job_id": "job1", "binaries": {
        md5: {"path": "bin/httpd", "arch": "arm32le", "functions": [
            {"addr": "0x100", "name": "initWebDefine", "decompile_ok": True,
             "calls": ["websDefineHandler"], "strings": [], "tags": []},
            {"addr": "0x200", "name": "unrelated", "decompile_ok": True,
             "calls": ["free"], "strings": [], "tags": []}]}}}
    view = classify.BinaryView(md5, symbols["binaries"][md5])
    src = {"0x100": 'websDefineHandler("/goform/login", loginHandler, 0);\n',
           "0x200": 'free(x);\n'}
    routes = classify.extract_goahead_routes(view, src.get)
    assert [r["route"] for r in routes] == ["/goform/login"]
    assert routes[0]["handler_name"] == "loginHandler"


def test_gate1_missing_surface_detected(tmp_path):
    doc = _inputs_doc()
    surfaces, auth_docs = runner.build_surfaces(doc, None, None,
                                                tmp_path / "none")
    surfaces = surfaces[1:]   # drop AS-001 -> gate 1 must fire
    errors, _ = runner.validate(doc, surfaces, auth_docs)
    assert any("IN-001" in e for e in errors)


def test_run_job_writes_information_dir(tmp_path):
    data_dir = tmp_path / "data"
    md5 = "m" * 32
    (data_dir / "inputs" / "job1").mkdir(parents=True)
    (data_dir / "inputs" / "job1" / "identification.json").write_text(
        json.dumps(_inputs_doc()), encoding="utf-8")
    pseudo = data_dir / "pseudocode" / "job1"
    _write_pseudo(pseudo, md5)
    (pseudo / "symbols.json").write_text(json.dumps(_symbols(md5)),
                                         encoding="utf-8")
    summary = runner.run_job("job1", data_dir)
    assert summary["status"] == "ok"
    assert "placeholder_bindings" in summary
    info = data_dir / "surfaces" / "job1" / "information"
    as1 = json.loads((info / "AS-001.json").read_text(encoding="utf-8"))
    assert as1["source_input"] == "IN-001"
    assert (info / "AS-002.json").is_file()
    assert (info / "AS-AUTH-001.json").is_file()
    assert (info / "identification.json").is_file()
