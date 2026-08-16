"""Unit tests for M7: qemu exec-log parsing, address->function mapping,
baseline/trigger diffing, and the trace endpoints in orchestrator.app.main.

qemu itself is never executed here; run_coverage is monkeypatched at the
HTTP layer.
"""

import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from orchestrator.app import main
from pipeline.trace import mapper, qemu_cov, tracer

JOB = "tracejob0001"
MD5 = "9e39391af855fd996cdd90437e2eeb7b"

QEMU10_LOG = """\
Trace 0: 0x713468000100 [00000000/0000000000400290/000000e2/00000000]
Linking TBs 0x713468000100 index 0 -> 0x713468000240
Trace 0: 0x713468000240 [00000000/000000000040029c/000000e2/00000000]
Trace 0: 0x7134680005c0 [00000000/000000000042b78c/000000e2/00000000]
Trace 0: 0x713468000100 [00000000/0000000000400290/000000e2/00000000]
"""

OLD_LOG = """\
Trace 0x713468000100 [0x400290]
Trace 0x713468000240 [0x40029c]
Trace 0x713468000100 [0x400290]
"""

FUNCS = [
    {"addr": "0x400290", "size": 12, "name": "entry", "ai_name": None,
     "libc_equiv": None},
    {"addr": "0x40029c", "size": 16, "name": "sub_40029C",
     "ai_name": "http_handle_request", "libc_equiv": None},
    {"addr": "0x42b78c", "size": 32, "name": "sub_42B78C",
     "ai_name": "util_strcpy", "libc_equiv": "strcpy"},
]


class TestParseExecLog:
    def test_qemu10_format(self, tmp_path):
        log = tmp_path / "cov.log"
        log.write_text(QEMU10_LOG, encoding="utf-8")
        assert qemu_cov.parse_exec_log(log) == [0x400290, 0x40029c, 0x42b78c]

    def test_old_format(self, tmp_path):
        log = tmp_path / "cov.log"
        log.write_text(OLD_LOG, encoding="utf-8")
        assert qemu_cov.parse_exec_log(log) == [0x400290, 0x40029c]

    def test_empty_and_garbage(self, tmp_path):
        log = tmp_path / "cov.log"
        log.write_text("Linking TBs 0x1 index 0 -> 0x2\nnot a trace\n",
                       encoding="utf-8")
        assert qemu_cov.parse_exec_log(log) == []


class TestQemuSelection:
    @pytest.fixture
    def fake_qemu_dir(self, tmp_path, monkeypatch):
        for name in ("qemu-mips", "qemu-mipsel", "qemu-arm",
                     "qemu-aarch64"):
            (tmp_path / name).write_bytes(b"x")
        monkeypatch.setattr(qemu_cov, "QEMU_BIN_DIR", str(tmp_path))
        return tmp_path

    def test_mapping(self, fake_qemu_dir):
        assert qemu_cov.qemu_for("mips", "be") == "qemu-mips"
        assert qemu_cov.qemu_for("mips", "le") == "qemu-mipsel"
        assert qemu_cov.qemu_for("arm", "le") == "qemu-arm"
        assert qemu_cov.qemu_for("arm64", "le") == "qemu-aarch64"

    def test_unknown_arch(self):
        with pytest.raises(qemu_cov.QemuError):
            qemu_cov.qemu_for("sparc", "be")

    def test_missing_binary(self, tmp_path, monkeypatch):
        monkeypatch.setattr(qemu_cov, "QEMU_BIN_DIR", str(tmp_path))
        with pytest.raises(qemu_cov.QemuError):
            qemu_cov.qemu_for("mips", "be")


class TestDynamicLinker:
    def test_static_binary_needs_no_sysroot(self, tmp_path, monkeypatch):
        target = tmp_path / "bin" / "busybox"
        target.parent.mkdir()
        target.write_bytes(b"ELF")
        calls = []

        def fake_readelf(args, binary):
            calls.append(args)
            return "Program Headers:\n"

        monkeypatch.setattr(qemu_cov, "_readelf", fake_readelf)
        out = qemu_cov.inspect_dynamic_linker(tmp_path, "/bin/busybox")
        assert out == {"dynamic": False, "interpreter": None,
                       "sysroot": None, "needed": [], "search_paths": []}
        assert calls == [["-lW"]]

    def test_dynamic_loader_and_needed_are_resolved(self, tmp_path, monkeypatch):
        target = tmp_path / "usr" / "sbin" / "httpd"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"ELF")
        (tmp_path / "lib").mkdir()
        (tmp_path / "lib" / "ld-uClibc.so.0").write_bytes(b"loader")
        (tmp_path / "lib" / "libc.so.0").write_bytes(b"libc")

        def fake_readelf(args, binary):
            if args == ["-lW"]:
                return "Requesting program interpreter: /lib/ld-uClibc.so.0]"
            return ("Dynamic section at offset 0x0 contains 2 entries:\n"
                    " 0x00000001 (NEEDED) Shared library: [libc.so.0]\n")

        monkeypatch.setattr(qemu_cov, "_readelf", fake_readelf)
        out = qemu_cov.inspect_dynamic_linker(tmp_path, "/usr/sbin/httpd")
        assert out["dynamic"] is True
        assert out["sysroot"] == "/"
        assert out["resolved"] == {"libc.so.0": "/lib/libc.so.0"}

    def test_dynamic_missing_needed_is_explicit(self, tmp_path, monkeypatch):
        target = tmp_path / "bin" / "app"
        target.parent.mkdir()
        target.write_bytes(b"ELF")
        (tmp_path / "lib").mkdir()
        (tmp_path / "lib" / "ld.so").write_bytes(b"loader")

        def fake_readelf(args, binary):
            if args == ["-lW"]:
                return "Requesting program interpreter: /lib/ld.so]"
            return "Shared library: [libmissing.so]"

        monkeypatch.setattr(qemu_cov, "_readelf", fake_readelf)
        with pytest.raises(qemu_cov.QemuError, match="libmissing.so"):
            qemu_cov.inspect_dynamic_linker(tmp_path, "/bin/app")


class TestFindRootfs:
    def test_bin_layout(self, tmp_path):
        binary = tmp_path / "firmware/binwalk_extracted/x/0/bin/busybox"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"ELF")
        rootfs, inner = qemu_cov.find_rootfs(
            tmp_path, "firmware/binwalk_extracted/x/0/bin/busybox")
        assert rootfs == tmp_path / "firmware/binwalk_extracted/x/0"
        assert inner == "/bin/busybox"

    def test_usr_layout_picks_shallowest(self, tmp_path):
        binary = tmp_path / "root/0/usr/sbin/httpd"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"ELF")
        rootfs, inner = qemu_cov.find_rootfs(tmp_path, "root/0/usr/sbin/httpd")
        assert rootfs == tmp_path / "root/0"
        assert inner == "/usr/sbin/httpd"

    def test_missing_binary(self, tmp_path):
        with pytest.raises(qemu_cov.QemuError):
            qemu_cov.find_rootfs(tmp_path, "nope/bin/x")


class TestMapper:
    def test_interval_lookup(self):
        idx = mapper.FunctionIndex(FUNCS)
        assert idx.lookup(0x400290)["name"] == "entry"
        assert idx.lookup(0x400295)["name"] == "entry"     # inside size
        assert idx.lookup(0x40029c)["ai_name"] == "http_handle_request"
        assert idx.lookup(0x42b78c + 31)["libc_equiv"] == "strcpy"
        assert idx.lookup(0x42b78c + 32) is None           # past the end
        assert idx.lookup(0x1000) is None                  # before all

    def test_zero_size_still_matches_entry(self):
        idx = mapper.FunctionIndex([{"addr": "0x1000", "size": 0,
                                     "name": "f"}])
        assert idx.lookup(0x1000)["name"] == "f"
        assert idx.lookup(0x1001) is None

    def test_map_addresses_order_and_unknown(self):
        seq, unknown = mapper.map_addresses(
            [0x400290, 0x999999, 0x42b78c, 0x400295, 0x40029c], FUNCS)
        assert unknown == 1
        assert [f["name"] for f in seq] == ["entry", "sub_42B78C",
                                            "sub_40029C"]
        assert [f["first_seen_idx"] for f in seq] == [0, 2, 4]

    def test_empty(self):
        seq, unknown = mapper.map_addresses([], FUNCS)
        assert seq == [] and unknown == 0


class TestDiff:
    def test_trigger_only_in_order(self):
        base = [{"addr": "0x1"}, {"addr": "0x2"}]
        trig = [{"addr": "0x2"}, {"addr": "0x3"}, {"addr": "0x1"},
                {"addr": "0x4"}]
        assert [f["addr"] for f in tracer.diff_functions(base, trig)] == \
            ["0x3", "0x4"]

    def test_empty_diff(self):
        base = [{"addr": "0x1"}]
        assert tracer.diff_functions(base, base) == []

    def test_trigger_error_is_explicit_success_variant(self):
        meta = {"trigger_result": {"error": "RemoteDisconnected: closed"}}
        assert tracer._successful_trace_status([{"addr": "0x2"}], meta) == \
            "ok_trigger_error"
        assert tracer._successful_trace_status([], meta) == \
            "ok_empty_diff_trigger_error"

    def test_clean_trigger_keeps_existing_statuses(self):
        assert tracer._successful_trace_status([{"addr": "0x2"}], {}) == "ok"
        assert tracer._successful_trace_status([], {}) == "ok_empty_diff"


class TestHttpTrigger:
    def test_remote_disconnect_is_preserved(self, monkeypatch):
        closed = []

        class FakeConnection:
            def __init__(self, host, port, timeout):
                assert (host, port, timeout) == ("127.0.0.1", 8098, 5)

            def request(self, method, path):
                assert (method, path) == ("GET", "/")

            def getresponse(self):
                raise tracer.http.client.RemoteDisconnected("closed")

            def close(self):
                closed.append(True)

        monkeypatch.setattr(tracer.http.client, "HTTPConnection", FakeConnection)
        result = tracer._http_trigger(8098, "/")
        assert result == {"kind": "http_get", "path": "/",
                          "status": None, "bytes": 0,
                          "error": "RemoteDisconnected: closed"}
        assert closed == [True]


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------

TRACE_FIXTURE = {
    "trace_id": "abc123def456",
    "job_id": JOB,
    "status": "ok",
    "error": None,
    "created_at": "t0",
    "elapsed_seconds": 7.5,
    "binary": {"md5": MD5, "path": "firmware/x/0/bin/busybox", "arch": "mips",
               "bits": 32, "endianness": "be"},
    "argv": ["httpd", "-f", "-p", "8080", "-h", "/www"],
    "request": {"port": 8080, "path": "/index.html"},
    "baseline": {"functions": 100, "unknown_addrs": 5},
    "trigger": {"functions": 130, "unknown_addrs": 8},
    "diff": {
        "function_count": 3,
        "functions": [
            {"addr": "0x40029c", "name": "sub_40029C",
             "ai_name": "http_handle_request", "libc_equiv": None,
             "first_seen_idx": 100},
            {"addr": "0x42b78c", "name": "sub_42B78C",
             "ai_name": "util_strcpy", "libc_equiv": "strcpy",
             "first_seen_idx": 105},
            {"addr": "0x410000", "name": "sub_410000",
             "ai_name": None, "libc_equiv": None,
             "first_seen_idx": 110},
        ],
    },
}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_TOKEN", "")
    monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))  # 配额/审计走临时目录，免污染真实 data
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "FIRMWARE_DIR", tmp_path / "firmware")
    monkeypatch.setattr(main, "EXTRACTED_DIR", tmp_path / "extracted")
    monkeypatch.setattr(main, "PSEUDOCODE_DIR", tmp_path / "pseudocode")
    monkeypatch.setattr(main, "CBM_DIR", tmp_path / "cbm")
    monkeypatch.setattr(main, "TRACES_DIR", tmp_path / "traces")
    monkeypatch.setattr(main, "ATTACK_DIR", tmp_path / "attack")
    (main.EXTRACTED_DIR / JOB).mkdir(parents=True)
    (main.EXTRACTED_DIR / JOB / "manifest.json").write_text(json.dumps({
        "job_id": JOB,
        "binaries": [{"path": "firmware/x/0/bin/busybox", "arch": "mips",
                      "bits": 32, "endianness": "be", "md5": MD5}],
    }), encoding="utf-8")
    (main.PSEUDOCODE_DIR / JOB).mkdir(parents=True)
    (main.PSEUDOCODE_DIR / JOB / "symbols.json").write_text(
        json.dumps({"job_id": JOB, "binaries": {}}), encoding="utf-8")
    trace_dir = main.TRACES_DIR / JOB / "abc123def456"
    trace_dir.mkdir(parents=True)
    (trace_dir / "trace.json").write_text(json.dumps(TRACE_FIXTURE),
                                          encoding="utf-8")
    with main._jobs_lock:
        main._jobs[JOB] = {"job_id": JOB, "firmware": "fw.bin",
                           "status": "graphed", "error": None,
                           "created_at": "t0", "updated_at": "t0",
                           "size_bytes": 1}
    yield TestClient(main.app), tmp_path
    with main._jobs_lock:
        main._jobs.pop(JOB, None)


class TestTriggerTrace:
    def test_202_and_worker(self, client, monkeypatch):
        http, _ = client
        threads = []

        class FakeThread:
            def __init__(self, target, args=(), daemon=None):
                threads.append((target, args))

            def start(self):
                pass

        seen = {}

        def fake_run_trace(job_id, data_dir, md5, argv, port=None,
                           request_path=None, trace_id=None,
                           cbm_project=None, argv0=None):
            seen.update(job_id=job_id, md5=md5, argv=argv, port=port,
                        request_path=request_path, trace_id=trace_id,
                        argv0=argv0)
            return {"status": "ok"}

        attack_dir = main.ATTACK_DIR / JOB
        attack_dir.mkdir(parents=True)
        (attack_dir / "attack_paths.json").write_text("{}", encoding="utf-8")
        refreshed = {}

        def fake_attack(job_id, data_dir):
            refreshed.update(job_id=job_id, data_dir=data_dir)

        monkeypatch.setattr(main, "threading", SimpleNamespace(Thread=FakeThread))
        monkeypatch.setattr(main.tracer, "run_trace", fake_run_trace)
        monkeypatch.setattr(main.attack_runner, "run_job", fake_attack)
        resp = http.post(f"/jobs/{JOB}/trace", json={
            "binary_md5": MD5, "argv": ["httpd", "-f", "-p", "8080"],
            "port": 8080, "request_path": "/index.html"})
        assert resp.status_code == 202
        body = resp.json()
        assert body["status"] == "running"
        target, args = threads[0]
        target(*args)
        assert seen["md5"] == MD5
        assert seen["argv"] == ["httpd", "-f", "-p", "8080"]
        assert seen["port"] == 8080
        assert seen["request_path"] == "/index.html"
        assert seen["trace_id"] == body["trace_id"]
        assert refreshed == {"job_id": JOB, "data_dir": main.DATA_DIR}

    def test_bad_md5_400(self, client):
        http, _ = client
        resp = http.post(f"/jobs/{JOB}/trace",
                         json={"binary_md5": "zz", "argv": ["x"]})
        assert resp.status_code == 400

    def test_bad_argv_400(self, client):
        http, _ = client
        resp = http.post(f"/jobs/{JOB}/trace",
                         json={"binary_md5": MD5, "argv": []})
        assert resp.status_code == 400

    def test_unknown_binary_404(self, client):
        http, _ = client
        resp = http.post(f"/jobs/{JOB}/trace", json={
            "binary_md5": "0" * 32, "argv": ["x"]})
        assert resp.status_code == 404

    def test_unknown_job_404(self, client):
        http, _ = client
        resp = http.post("/jobs/nope/trace",
                         json={"binary_md5": MD5, "argv": ["x"]})
        assert resp.status_code == 404
        assert http.get("/jobs/nope/traces").status_code == 404
        assert http.get("/jobs/nope/traces/abc123def456").status_code == 404

    def test_requires_symbols_409(self, client):
        http, _ = client
        (main.PSEUDOCODE_DIR / JOB / "symbols.json").unlink()
        resp = http.post(f"/jobs/{JOB}/trace",
                         json={"binary_md5": MD5, "argv": ["x"]})
        assert resp.status_code == 409

    def test_busy_lock_409(self, client, monkeypatch):
        http, _ = client

        class BusyLock:
            def acquire(self, blocking=False):
                return False

        monkeypatch.setattr(main, "TRACE_LOCK", BusyLock())
        resp = http.post(f"/jobs/{JOB}/trace",
                         json={"binary_md5": MD5, "argv": ["x"]})
        assert resp.status_code == 409


class TestTraceReads:
    def test_list(self, client):
        http, _ = client
        resp = http.get(f"/jobs/{JOB}/traces")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        row = body["traces"][0]
        assert row["trace_id"] == "abc123def456"
        assert row["diff_functions"] == 3
        assert row["baseline_functions"] == 100

    def test_detail(self, client):
        http, _ = client
        resp = http.get(f"/jobs/{JOB}/traces/abc123def456")
        assert resp.status_code == 200
        assert resp.json()["diff"]["function_count"] == 3

    def test_missing_trace_404(self, client):
        http, _ = client
        resp = http.get(f"/jobs/{JOB}/traces/ffffffffffff")
        assert resp.status_code == 404

    def test_bad_trace_id_400(self, client):
        http, _ = client
        assert http.get(f"/jobs/{JOB}/traces/../../etc").status_code in \
            (400, 404, 422)


class TestTraceFlow:
    def test_happy_path(self, client):
        http, _ = client
        resp = http.post("/graph/query", json={
            "job_id": JOB, "op": "trace_flow", "trace_id": "abc123def456"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["function_count"] == 3
        names = [f["name"] for f in body["sequence"]]
        assert names == ["http_handle_request", "util_strcpy", "sub_410000"]
        assert [f["first_seen_idx"] for f in body["sequence"]] == \
            [100, 105, 110]
        assert body["dangerous_count"] == 1
        assert body["dangerous"][0]["matched"] == "strcpy"
        assert body["dangerous"][0]["addr"] == "0x42b78c"

    def test_missing_trace_404(self, client):
        http, _ = client
        resp = http.post("/graph/query", json={
            "job_id": JOB, "op": "trace_flow", "trace_id": "ffffffffffff"})
        assert resp.status_code == 404

    def test_missing_trace_id_400(self, client):
        http, _ = client
        resp = http.post("/graph/query", json={
            "job_id": JOB, "op": "trace_flow"})
        assert resp.status_code == 400
