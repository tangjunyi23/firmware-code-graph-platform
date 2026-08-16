"""Tests for pipeline.fuzz (AFL++ qemu mode) and pipeline.frida stages."""

import json
from pathlib import Path

import pytest

from pipeline.fuzz import runner as fuzz_runner
from pipeline.frida import runner as frida_runner


def _mk_job(tmp_path):
    """Minimal extracted job tree: manifest with one ARM ELF + rootfs."""
    data_dir = tmp_path / "data"
    ext = data_dir / "extracted" / "job1"
    rootfs = ext / "firmware" / "0"
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "etc").mkdir(parents=True)
    elf = rootfs / "bin" / "httpd"
    elf.write_bytes(b"\x7fELF fake binary with -some-strings tokenAAAA")
    md5 = "a" * 32
    (ext / "manifest.json").write_text(json.dumps({
        "firmware": "fw.bin", "job_id": "job1",
        "binaries": [{"path": "firmware/0/bin/httpd", "arch": "arm",
                      "bits": 32, "endianness": "le", "md5": md5}],
        "stats": {}}), encoding="utf-8")
    return data_dir, md5


class _FakeProc:
    def __init__(self, rc=0):
        self.pid = 4242
        self.returncode = rc

    def communicate(self, timeout=None):
        return "", "fake afl stderr"

    def wait(self):
        return self.returncode


def test_fuzz_writes_summary(tmp_path, monkeypatch):
    data_dir, md5 = _mk_job(tmp_path)
    monkeypatch.setenv("FUZZ_AFL_QEMU", "/bin/true")  # pretend runtime exists

    def fake_popen(cmd, **kw):
        out = Path(kw["cwd"]) / "afl_out" / "default"
        (out / "crashes").mkdir(parents=True)
        (out / "crashes" / "id:000000,sig:06").write_bytes(b"boom")
        (out / "fuzzer_stats").write_text(
            "execs_done : 1234\nexecs_per_sec : 42.0\npaths_total : 17\n")
        return _FakeProc(0)

    monkeypatch.setattr(fuzz_runner.subprocess, "Popen", fake_popen)
    summary = fuzz_runner.run_job("job1", data_dir, md5, argv=["@@"],
                                  seconds=5)
    assert summary["status"] == "ok"
    assert summary["execs"] == 1234
    assert summary["crashes"] == 1
    assert summary["paths"] == 17
    runs = fuzz_runner.list_runs("job1", data_dir)
    assert len(runs) == 1 and runs[0]["run_id"] == summary["run_id"]
    assert fuzz_runner.get_run("job1", data_dir, summary["run_id"])["execs"] == 1234


def test_fuzz_missing_runtime_fails_loud(tmp_path, monkeypatch):
    data_dir, md5 = _mk_job(tmp_path)
    monkeypatch.setattr(fuzz_runner, "_afl_qemu_trace", lambda *_a: None)
    with pytest.raises(RuntimeError, match="afl-qemu-trace"):
        fuzz_runner.run_job("job1", data_dir, md5, seconds=5)


def test_fuzz_bad_md5(tmp_path):
    data_dir, _ = _mk_job(tmp_path)
    with pytest.raises(KeyError):
        fuzz_runner.run_job("job1", data_dir, "b" * 32, seconds=5)


def test_frida_unreachable_device(tmp_path, monkeypatch):
    import types
    fake = types.SimpleNamespace()
    fake.ProcessNotFoundError = type("ProcessNotFoundError", (Exception,), {})

    class _Mgr:
        def add_remote_device(self, host, timeout=10):
            raise OSError("connection refused")

    fake.get_device_manager = lambda: _Mgr()
    monkeypatch.setitem(__import__("sys").modules, "frida", fake)
    with pytest.raises(RuntimeError, match="frida-server unreachable"):
        frida_runner.run_job("job1", tmp_path, "192.0.2.1", "httpd",
                             [{"symbol": "main", "module": "httpd"}],
                             seconds=5)


def test_frida_run_records_hits(tmp_path, monkeypatch):
    import types
    events = []

    class _Script:
        def on(self, *_a): pass

        def load(self):
            events.append({"type": "hooked", "target": "main",
                           "at": "0x4001000"})
            events.append({"type": "hit", "target": "main", "ts": 1,
                           "args": [{"i": 0, "ptr": "0x1"}]})

        def unload(self): pass

    class _Session:
        def create_script(self, _js): return _Script()

        def detach(self): pass

    class _Device:
        def attach(self, _p): return _Session()

    class _Mgr:
        def add_remote_device(self, host, timeout=10): return _Device()

    fake = types.SimpleNamespace()
    fake.ProcessNotFoundError = type("ProcessNotFoundError", (Exception,), {})
    fake.get_device_manager = lambda: _Mgr()
    monkeypatch.setitem(__import__("sys").modules, "frida", fake)
    monkeypatch.setattr(frida_runner.time, "sleep", lambda _s: None)

    summary = frida_runner.run_job("job1", tmp_path, "192.0.2.1", "httpd",
                                   [{"symbol": "main", "module": "httpd"}],
                                   seconds=5)
    assert summary["status"] == "ok"
    assert summary["engine"] == "frida"
    assert frida_runner.get_run("job1", tmp_path,
                                summary["run_id"])["run_id"] == summary["run_id"]
