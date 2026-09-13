"""Tests for pipeline.fuzz (AFL++ qemu mode) and pipeline.frida stages."""

import json
import os
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
    # 固定宿主直跑：docker 可用且沙箱镜像存在时 fuzz 会改走容器路径
    # （Phase 2 起），本用例语义是宿主 afl 输出解析
    monkeypatch.setattr(fuzz_runner.sandbox, "backend_for",
                        lambda _component: "none")
    monkeypatch.setattr(fuzz_runner, "_afl_fuzz_bin", lambda: "afl-fuzz")
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


def test_afl_fuzz_resolves_from_repo(tmp_path, monkeypatch):
    fake = tmp_path / "AFLplusplus" / "afl-fuzz"
    fake.parent.mkdir()
    fake.write_bytes(b"\x7fELFfake")
    fake.chmod(0o755)
    monkeypatch.delenv("AFL_FUZZ", raising=False)
    monkeypatch.setenv("AFL_REPO", str(fake.parent))
    monkeypatch.setattr(fuzz_runner.shutil, "which", lambda _n: None)
    assert fuzz_runner._afl_fuzz_bin() == str(fake)


def test_fuzz_missing_afl_fuzz_fails_loud(tmp_path, monkeypatch):
    data_dir, md5 = _mk_job(tmp_path)
    monkeypatch.setattr(fuzz_runner.sandbox, "backend_for",
                        lambda _component: "none")
    monkeypatch.setenv("FUZZ_AFL_QEMU", "/bin/true")
    monkeypatch.delenv("AFL_FUZZ", raising=False)
    monkeypatch.setenv("AFL_REPO", str(tmp_path / "no-afl"))
    monkeypatch.setattr(fuzz_runner.shutil, "which", lambda _n: None)
    with pytest.raises(RuntimeError, match="afl-fuzz not found"):
        fuzz_runner.run_job("job1", data_dir, md5, seconds=5)


def test_fuzz_bad_md5(tmp_path):
    data_dir, _ = _mk_job(tmp_path)
    with pytest.raises(KeyError):
        fuzz_runner.run_job("job1", data_dir, "b" * 32, seconds=5)


def test_fuzz_function_mode_sets_persistent_env(tmp_path, monkeypatch):
    data_dir, md5 = _mk_job(tmp_path)
    hook = tmp_path / "fake.so"
    hook.write_bytes(b"x")
    monkeypatch.setattr(fuzz_runner, "_hook_for", lambda *_a, **_k: hook)
    monkeypatch.setattr(fuzz_runner.sandbox, "backend_for",
                        lambda _component: "none")
    monkeypatch.setattr(fuzz_runner, "_afl_fuzz_bin", lambda: "afl-fuzz")
    monkeypatch.setenv("FUZZ_AFL_QEMU", "/bin/true")
    seen = {}

    def fake_popen(cmd, **kw):
        seen["env"] = kw.get("env") or {}
        out = Path(kw["cwd"]) / "afl_out" / "default"
        out.mkdir(parents=True)
        (out / "fuzzer_stats").write_text("execs_done : 3\n")
        return _FakeProc(0)

    monkeypatch.setattr(fuzz_runner.subprocess, "Popen", fake_popen)
    summary = fuzz_runner.run_job(
        "job1", data_dir, md5, function="0x401000",
        args=["buf", "len"], seconds=5)
    assert summary["mode"] == "function"
    assert summary["function"] == "0x401000"
    assert seen["env"]["AFL_QEMU_PERSISTENT_ADDR"] == "0x401000"
    assert seen["env"]["AFL_ENTRYPOINT"] == "0x401000"
    assert seen["env"]["AFL_QEMU_PERSISTENT_HOOK"] == str(hook)
    assert seen["env"]["FUZZHOOK_ARGS"] == "buf,len"
    assert seen["env"]["FUZZHOOK_FUNC_ADDR"] == "0x401000"
    assert seen["env"]["AFL_MAP_SIZE"] == "10000000"


def _afl_api_h():
    return (Path(os.environ.get("AFL_REPO", str(Path.home() / "AFLplusplus")))
            / "qemu_mode" / "qemuafl" / "qemuafl" / "api.h")


@pytest.mark.skipif(not _afl_api_h().is_file(),
                    reason="AFL++ qemuafl api.h not present")
def test_fuzz_mips_hook_compiles(tmp_path):
    hook = fuzz_runner._hook_for("mips", tmp_path / "hooks")
    assert hook.is_file() and hook.stat().st_size > 1000
    import subprocess
    exported = subprocess.check_output(["nm", "-D", str(hook)], text=True)
    assert "afl_persistent_hook" in exported


@pytest.mark.skipif(not _afl_api_h().is_file(),
                    reason="AFL++ qemuafl api.h not present")
def test_fuzz_hook_rebuilds_when_src_newer(tmp_path, monkeypatch):
    import os
    import time
    src = tmp_path / "fw_fuzzhook.c"
    src.write_text(fuzz_runner.HOOK_SRC.read_text(encoding="utf-8"))
    monkeypatch.setattr(fuzz_runner, "HOOK_SRC", src)
    cache = tmp_path / "hooks"
    hook = fuzz_runner._hook_for("mips", cache)
    older = hook.stat().st_mtime - 120
    os.utime(hook, (older, older))
    os.utime(src, None)
    rebuilt = fuzz_runner._hook_for("mips", cache)
    assert rebuilt.stat().st_mtime > older + 60
    # cache hit when src is not newer
    m2 = rebuilt.stat().st_mtime
    time.sleep(0.05)
    again = fuzz_runner._hook_for("mips", cache)
    assert again.stat().st_mtime == m2


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
