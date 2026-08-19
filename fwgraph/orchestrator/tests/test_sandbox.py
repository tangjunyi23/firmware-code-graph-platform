"""Phase 2 Docker 沙箱执行层测试。

全程 mock/monkeypatch：不触碰真实 docker daemon，不构建镜像。
"""

import json
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from pipeline import sandbox
from pipeline.fuzz import runner as fuzz_runner
from pipeline.frida import runner as frida_runner
from pipeline.sandbox import docker_backend
from pipeline.trace import qemu_cov


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """每个用例从干净的后端配置与 docker 可用性缓存出发。"""
    for name in ("SANDBOX_BACKEND", "FUZZ_SANDBOX_BACKEND",
                 "FRIDA_SANDBOX_BACKEND", "TRACE_SANDBOX_BACKEND"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(docker_backend, "_DOCKER_OK", None)
    yield


# ---------------------------------------------------------------------------
# docker 命令构造
# ---------------------------------------------------------------------------

class _FakeProc:
    def __init__(self, rc=0):
        self.pid = 2**22
        self.returncode = rc

    def communicate(self, timeout=None):
        return "", "fake stderr"

    def wait(self, timeout=None):
        return self.returncode

    def poll(self):
        return self.returncode


class TestRunSandboxedCmd:
    def _capture(self, monkeypatch):
        seen = {}

        def fake_popen(cmd, **kw):
            seen["cmd"] = list(cmd)
            seen["kw"] = kw
            return _FakeProc()

        monkeypatch.setattr(docker_backend.subprocess, "Popen", fake_popen)
        return seen

    def test_isolation_flags_and_mounts(self, monkeypatch):
        seen = self._capture(monkeypatch)
        proc = sandbox.run_sandboxed(
            ["/bin/target", "-f"], image="fwgraph-sandbox:local",
            mounts=[("/data/rootfs", "/data/rootfs", "ro"),
                    ("/data/work", "/data/work", "rw")],
            workdir="/data/work", env={"QEMU_LD_PREFIX": "/data/rootfs"},
            timeout=None)
        cmd = seen["cmd"]
        assert cmd[:2] == ["docker", "run"]
        for flag in ("--rm", "--read-only", "--tmpfs"):
            assert flag in cmd
        assert "--network" in cmd and cmd[cmd.index("--network") + 1] == "none"
        assert cmd[cmd.index("--cap-drop") + 1] == "ALL"
        assert "no-new-privileges" in cmd
        assert cmd[cmd.index("--pids-limit") + 1] == "256"
        assert cmd[cmd.index("--memory") + 1] == "2g"
        assert cmd[cmd.index("--cpus") + 1] == "2"
        vols = [cmd[i + 1] for i, v in enumerate(cmd) if v == "-v"]
        assert "/data/rootfs:/data/rootfs:ro" in vols
        assert "/data/work:/data/work:rw" in vols
        envs = [cmd[i + 1] for i, v in enumerate(cmd) if v == "--env"]
        assert "QEMU_LD_PREFIX=/data/rootfs" in envs
        assert cmd[cmd.index("-w") + 1] == "/data/work"
        img_idx = cmd.index("fwgraph-sandbox:local")
        assert cmd[img_idx + 1:] == ["/bin/target", "-f"]
        # 默认断网且无端口发布
        assert "-p" not in cmd
        # 返回 Popen 供调用方沿用等待/杀进程逻辑，并暴露容器名
        assert proc.sandbox_container == cmd[cmd.index("--name") + 1]
        # 无 log_path 时 stderr=PIPE（对齐 fuzz 的 communicate 用法）
        assert seen["kw"]["stderr"] == subprocess.PIPE
        assert seen["kw"]["start_new_session"] is True

    def test_ports_extra_hosts_and_log_path(self, monkeypatch, tmp_path):
        seen = self._capture(monkeypatch)
        log = tmp_path / "container.log"
        sandbox.run_sandboxed(
            ["/usr/bin/qemu-arm", "/bin/httpd"], image="img",
            mounts=[], network="bridge", ports=[8080],
            extra_hosts=["fwgraph:127.0.0.1"], log_path=str(log),
            mem="1g", cpus=1, pids=64, name="fwgraph-trace-x1")
        cmd = seen["cmd"]
        assert cmd[cmd.index("--network") + 1] == "bridge"
        pubs = [cmd[i + 1] for i, v in enumerate(cmd) if v == "-p"]
        assert pubs == ["127.0.0.1:8080:8080"]
        assert "fwgraph:127.0.0.1" in \
            [cmd[i + 1] for i, v in enumerate(cmd) if v == "--add-host"]
        assert cmd[cmd.index("--memory") + 1] == "1g"
        assert cmd[cmd.index("--cpus") + 1] == "1"
        assert cmd[cmd.index("--pids-limit") + 1] == "64"
        assert cmd[cmd.index("--name") + 1] == "fwgraph-trace-x1"
        # log_path 给定时 stdout/stderr 进文件而不是 PIPE
        assert seen["kw"]["stderr"] == subprocess.STDOUT
        assert seen["kw"]["stdout"].name == str(log)

    def test_timeout_watchdog_removes_container(self, monkeypatch):
        removed = threading.Event()
        calls = []

        class HangProc(_FakeProc):
            def wait(self, timeout=None):
                if timeout is None:
                    return 0
                raise subprocess.TimeoutExpired(cmd="x", timeout=timeout)

        monkeypatch.setattr(docker_backend.subprocess, "Popen",
                            lambda cmd, **kw: HangProc())

        def fake_run(cmd, **kw):
            calls.append(list(cmd))
            if cmd[:3] == ["docker", "rm", "-f"]:
                removed.set()
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(docker_backend.subprocess, "run", fake_run)
        sandbox.run_sandboxed(["/bin/x"], image="img", mounts=[],
                              timeout=0.05, name="fwgraph-sbx-wd")
        assert removed.wait(5), "看门狗应 docker rm -f 超期容器"
        assert ["docker", "rm", "-f", "fwgraph-sbx-wd"] in calls


# ---------------------------------------------------------------------------
# backend_for 回退矩阵
# ---------------------------------------------------------------------------

class TestBackendFor:
    def test_default_is_docker(self, monkeypatch):
        monkeypatch.setattr(docker_backend, "_DOCKER_OK", True)
        assert sandbox.backend_for("fuzz") == "docker"
        assert sandbox.backend_for("trace") == "docker"

    def test_docker_unavailable_fallbacks(self, monkeypatch):
        monkeypatch.setattr(docker_backend, "_DOCKER_OK", False)
        assert sandbox.backend_for("fuzz") == "none"    # 宿主直跑（调用方告警）
        assert sandbox.backend_for("frida") == "none"
        assert sandbox.backend_for("trace") == "userns"  # 原有路径兜底

    def test_explicit_none_and_userns_win(self, monkeypatch):
        monkeypatch.setattr(docker_backend, "_DOCKER_OK", True)
        monkeypatch.setenv("SANDBOX_BACKEND", "none")
        assert sandbox.backend_for("fuzz") == "none"
        monkeypatch.setenv("SANDBOX_BACKEND", "userns")
        assert sandbox.backend_for("trace") == "userns"

    def test_component_override(self, monkeypatch):
        monkeypatch.setattr(docker_backend, "_DOCKER_OK", True)
        monkeypatch.setenv("SANDBOX_BACKEND", "none")
        monkeypatch.setenv("FUZZ_SANDBOX_BACKEND", "docker")
        assert sandbox.backend_for("fuzz") == "docker"
        assert sandbox.backend_for("frida") == "none"
        monkeypatch.setenv("TRACE_SANDBOX_BACKEND", "userns")
        assert sandbox.backend_for("trace") == "userns"

    def test_invalid_value_falls_back_to_default(self, monkeypatch):
        monkeypatch.setattr(docker_backend, "_DOCKER_OK", True)
        monkeypatch.setenv("SANDBOX_BACKEND", "k8s")
        assert sandbox.backend_for("fuzz") == "docker"
        assert sandbox.configured_backend("fuzz") == "docker"

    def test_docker_available_probe_cached(self, monkeypatch):
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return SimpleNamespace(returncode=0)

        monkeypatch.setattr(docker_backend.shutil, "which",
                            lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr(docker_backend.subprocess, "run", fake_run)
        monkeypatch.setattr(docker_backend, "_DOCKER_OK", None)
        assert docker_backend.docker_available() is True
        assert docker_backend.docker_available() is True
        assert calls == [["docker", "info"]]

    def test_image_present(self, monkeypatch):
        monkeypatch.setattr(
            docker_backend.subprocess, "run",
            lambda cmd, **kw: SimpleNamespace(
                returncode=0 if "img-good" in cmd else 1))
        assert sandbox.sandbox_image_present("img-good") is True
        assert sandbox.sandbox_image_present("img-bad") is False


# ---------------------------------------------------------------------------
# fuzz runner：docker 后端选中 / 回退
# ---------------------------------------------------------------------------

def _mk_job(tmp_path):
    """与 test_dyn 一致的最小 job 树：manifest + 一个 ARM ELF + rootfs。"""
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
    return data_dir, md5, rootfs


def _write_afl_stats(cmd):
    out = Path(cmd[cmd.index("-o") + 1]) / "default"
    (out / "crashes").mkdir(parents=True)
    (out / "fuzzer_stats").write_text(
        "execs_done : 10\nexecs_per_sec : 1.0\npaths_total : 2\n")


class TestFuzzSandbox:
    def test_docker_backend_wraps_afl(self, tmp_path, monkeypatch):
        data_dir, md5, rootfs = _mk_job(tmp_path)
        monkeypatch.setenv("FUZZ_AFL_QEMU", "/bin/true")
        monkeypatch.setattr(docker_backend, "_DOCKER_OK", True)
        monkeypatch.setattr(sandbox, "sandbox_image_present", lambda _i: True)
        seen = {}

        def fake_popen(cmd, **kw):
            seen["cmd"] = list(cmd)
            _write_afl_stats(cmd)
            return _FakeProc()

        monkeypatch.setattr(fuzz_runner.subprocess, "Popen", fake_popen)
        summary = fuzz_runner.run_job("job1", data_dir, md5, argv=["@@"],
                                      seconds=5)
        cmd = seen["cmd"]
        assert cmd[:2] == ["docker", "run"]
        assert cmd[cmd.index("--network") + 1] == "none"
        assert fuzz_runner.SANDBOX_AFL_FUZZ in cmd  # 容器内 afl-fuzz 路径
        assert "-Q" in cmd
        vols = [cmd[i + 1] for i, v in enumerate(cmd) if v == "-v"]
        assert f"{rootfs}:{rootfs}:ro" in vols      # rootfs 同路径只读
        work = data_dir / "fuzz" / "job1" / summary["run_id"]
        assert f"{work}:{work}:rw" in vols          # 输出目录读写
        qemu_real = str(Path("/bin/true").resolve())
        assert f"{qemu_real}:{qemu_real}:ro" in vols
        envs = [cmd[i + 1] for i, v in enumerate(cmd) if v == "--env"]
        assert f"QEMU_LD_PREFIX={rootfs}" in envs
        assert not any(e.startswith("HOME=") for e in envs)  # 不带宿主环境
        assert summary["status"] == "ok"
        assert summary["sandbox_backend"] == "docker"
        assert summary["sandbox_image"] == sandbox.SANDBOX_IMAGE
        assert summary["sandbox_limits"] == dict(sandbox.DEFAULT_LIMITS)
        assert "sandbox_warning" not in summary

    def test_image_missing_falls_back_to_host(self, tmp_path, monkeypatch):
        data_dir, md5, _ = _mk_job(tmp_path)
        monkeypatch.setenv("FUZZ_AFL_QEMU", "/bin/true")
        monkeypatch.setattr(docker_backend, "_DOCKER_OK", True)
        monkeypatch.setattr(sandbox, "sandbox_image_present", lambda _i: False)
        seen = {}

        def fake_popen(cmd, **kw):
            seen["cmd"] = list(cmd)
            out = Path(kw["cwd"]) / "afl_out" / "default"
            (out / "crashes").mkdir(parents=True)
            (out / "fuzzer_stats").write_text("execs_done : 1\n")
            return _FakeProc()

        monkeypatch.setattr(fuzz_runner.subprocess, "Popen", fake_popen)
        summary = fuzz_runner.run_job("job1", data_dir, md5, argv=["@@"],
                                      seconds=5)
        assert seen["cmd"][0] == "afl-fuzz"  # 原生命令，不经 docker
        assert summary["sandbox_backend"] == "none"
        assert "警告" in summary["sandbox_warning"]
        assert "镜像" in summary["sandbox_warning"]

    def test_docker_unavailable_falls_back_to_host(self, tmp_path,
                                                   monkeypatch):
        data_dir, md5, _ = _mk_job(tmp_path)
        monkeypatch.setenv("FUZZ_AFL_QEMU", "/bin/true")
        monkeypatch.setattr(docker_backend, "_DOCKER_OK", False)
        seen = {}

        def fake_popen(cmd, **kw):
            seen["cmd"] = list(cmd)
            (Path(kw["cwd"]) / "afl_out" / "default").mkdir(parents=True)
            return _FakeProc()

        monkeypatch.setattr(fuzz_runner.subprocess, "Popen", fake_popen)
        summary = fuzz_runner.run_job("job1", data_dir, md5, argv=["@@"],
                                      seconds=5)
        assert seen["cmd"][0] == "afl-fuzz"
        assert summary["sandbox_backend"] == "none"
        assert "docker 不可用" in summary["sandbox_warning"]

    def test_backend_none_no_warning(self, tmp_path, monkeypatch):
        data_dir, md5, _ = _mk_job(tmp_path)
        monkeypatch.setenv("FUZZ_AFL_QEMU", "/bin/true")
        monkeypatch.setenv("SANDBOX_BACKEND", "none")

        def fake_popen(cmd, **kw):
            (Path(kw["cwd"]) / "afl_out" / "default").mkdir(parents=True)
            return _FakeProc()

        monkeypatch.setattr(fuzz_runner.subprocess, "Popen", fake_popen)
        summary = fuzz_runner.run_job("job1", data_dir, md5, argv=["@@"],
                                      seconds=5)
        assert summary["sandbox_backend"] == "none"
        assert "sandbox_warning" not in summary


# ---------------------------------------------------------------------------
# trace（qemu_cov）：docker 覆盖路径
# ---------------------------------------------------------------------------

class TestTraceDocker:
    def _setup(self, tmp_path, monkeypatch):
        monkeypatch.setattr(docker_backend, "_DOCKER_OK", True)
        monkeypatch.setattr(sandbox, "sandbox_image_present", lambda _i: True)
        rootfs = tmp_path / "rootfs"
        for d in ("bin", "etc", "tmp"):
            (rootfs / d).mkdir(parents=True)
        rm_calls = []
        monkeypatch.setattr(
            qemu_cov.subprocess, "run",
            lambda cmd, **kw: (rm_calls.append(list(cmd)),
                               SimpleNamespace(returncode=0))[1])
        return rootfs, rm_calls

    def _fake_run_sandboxed(self, seen):
        def fake(cmd, **kw):
            seen["cmd"] = list(cmd)
            seen["kw"] = kw
            out_host = next(h for h, c, _m in kw["mounts"] if c == "/out")
            seen["out_dir"] = out_host
            log_rel = cmd[cmd.index("-D") + 1]          # /out/<run>.log
            (Path(out_host) / Path(log_rel).name).write_text(
                "Trace 0x1 [0x400290]\n", encoding="utf-8")
            return _FakeProc()
        return fake

    def test_one_shot_docker(self, tmp_path, monkeypatch):
        rootfs, rm_calls = self._setup(tmp_path, monkeypatch)
        seen = {}
        monkeypatch.setattr(qemu_cov.sandbox, "run_sandboxed",
                            self._fake_run_sandboxed(seen))
        addrs, meta = qemu_cov.run_coverage(
            rootfs, "/usr/bin/qemu-arm", ["/bin/hello"], "dockertest01",
            run_timeout=1.0)
        assert addrs == [0x400290]
        kw = seen["kw"]
        assert kw["network"] == "none"
        assert kw["ports"] is None
        assert kw["name"] == "fwgraph-trace-dockertest01"
        assert kw["image"] == sandbox.SANDBOX_IMAGE
        mounts = [(h, c, m) for h, c, m in kw["mounts"]]
        assert (str(rootfs), str(rootfs), "ro") in mounts
        assert (str(rootfs / "bin"), "/bin", "ro") in mounts
        assert (str(rootfs / "etc"), "/etc", "ro") in mounts
        assert (seen["out_dir"], "/out", "rw") in mounts
        cmd = seen["cmd"]
        assert cmd[0] == "/usr/bin/qemu-arm"
        assert cmd[cmd.index("-L") + 1] == str(rootfs)
        assert cmd[cmd.index("-D") + 1].startswith("/out/")
        assert ["docker", "rm", "-f", "fwgraph-trace-dockertest01"] in rm_calls
        assert not Path(seen["out_dir"]).exists()  # 取回日志后已清理
        assert meta["sandbox"] == "docker"
        assert meta["sandbox_backend"] == "docker"
        assert meta["sandbox_image"] == sandbox.SANDBOX_IMAGE
        assert meta["sandbox_limits"] == dict(sandbox.DEFAULT_LIMITS)

    def test_service_docker_publishes_loopback(self, tmp_path, monkeypatch):
        rootfs, _ = self._setup(tmp_path, monkeypatch)
        seen = {}
        monkeypatch.setattr(qemu_cov.sandbox, "run_sandboxed",
                            self._fake_run_sandboxed(seen))
        _addrs, meta = qemu_cov.run_coverage(
            rootfs, "/usr/bin/qemu-arm", ["/bin/svc"], "dockertest02",
            port=8080, probe_port=False, hold_seconds=0.01, run_timeout=1.0)
        assert seen["kw"]["network"] == "bridge"
        assert seen["kw"]["ports"] == [8080]
        assert meta["sandbox_backend"] == "docker"

    def test_image_missing_keeps_userns_path(self, tmp_path, monkeypatch):
        """镜像未构建：回退原有 userns 裁决，行为不变。"""
        monkeypatch.setattr(docker_backend, "_DOCKER_OK", True)
        monkeypatch.setattr(sandbox, "sandbox_image_present", lambda _i: False)
        monkeypatch.setattr(qemu_cov, "_USERNS_OK", True)
        assert qemu_cov.trace_exec_mode() == "userns"
        monkeypatch.setattr(qemu_cov, "_USERNS_OK", False)
        monkeypatch.setenv("TRACE_ALLOW_ROOT_CHROOT", "1")
        assert qemu_cov.trace_exec_mode() == "root"


# ---------------------------------------------------------------------------
# frida runner：本地 docker 沙箱
# ---------------------------------------------------------------------------

def _fake_frida_module(record):
    class _Script:
        def on(self, *_a): pass

        def load(self): pass

        def unload(self): pass

    class _Session:
        def create_script(self, _js): return _Script()

        def detach(self): pass

    class _Device:
        def spawn(self, argv):
            record["spawn"] = list(argv)
            return 4321

        def attach(self, _p): return _Session()

        def resume(self, _pid): pass

    class _Mgr:
        def add_remote_device(self, host, timeout=10):
            record["remote_host"] = host
            return _Device()

    fake = SimpleNamespace()
    fake.ProcessNotFoundError = type("ProcessNotFoundError", (Exception,), {})
    fake.get_device_manager = lambda: _Mgr()
    fake.get_local_device = lambda: (record.__setitem__("local", True)
                                     or _Device())
    return fake


class TestFridaSandbox:
    def test_local_docker_container(self, tmp_path, monkeypatch):
        monkeypatch.setattr(docker_backend, "_DOCKER_OK", True)
        monkeypatch.setattr(sandbox, "sandbox_image_present", lambda _i: True)
        record = {}
        monkeypatch.setitem(__import__("sys").modules, "frida",
                            _fake_frida_module(record))
        monkeypatch.setattr(frida_runner.time, "sleep", lambda _s: None)
        docker_calls = []

        def fake_run(cmd, **kw):
            docker_calls.append(list(cmd))
            if cmd[:2] == ["docker", "run"]:
                return SimpleNamespace(returncode=0, stdout="cid123\n",
                                       stderr="")
            if cmd[:2] == ["docker", "inspect"]:
                return SimpleNamespace(returncode=0, stdout="172.17.0.2\n",
                                       stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(frida_runner.subprocess, "run", fake_run)
        target = tmp_path / "httpd"
        target.write_bytes(b"\x7fELF")
        summary = frida_runner.run_job("job1", tmp_path, "", str(target),
                                       [{"symbol": "main"}], seconds=5,
                                       spawn=True)
        run_cmd = next(c for c in docker_calls if c[:2] == ["docker", "run"])
        assert "-d" in run_cmd and "--read-only" in run_cmd
        assert run_cmd[run_cmd.index("--cap-drop") + 1] == "ALL"
        assert run_cmd[run_cmd.index("--cap-add") + 1] == "SYS_PTRACE"
        assert f"{tmp_path}:{tmp_path}:ro" in \
            [run_cmd[i + 1] for i, v in enumerate(run_cmd) if v == "-v"]
        assert "frida-server" in run_cmd
        # 经容器 bridge IP 连接，spawn 逻辑复用
        assert record["remote_host"] == "172.17.0.2"
        assert record["spawn"] == [str(target)]
        name = f"fwgraph-frida-{summary['run_id']}"
        assert ["docker", "rm", "-f", name] in docker_calls
        assert summary["sandbox_backend"] == "docker"
        assert summary["sandbox_image"] == sandbox.SANDBOX_IMAGE

    def test_local_fallback_warns(self, tmp_path, monkeypatch):
        monkeypatch.setattr(docker_backend, "_DOCKER_OK", True)
        monkeypatch.setattr(sandbox, "sandbox_image_present", lambda _i: False)
        record = {}
        monkeypatch.setitem(__import__("sys").modules, "frida",
                            _fake_frida_module(record))
        monkeypatch.setattr(frida_runner.time, "sleep", lambda _s: None)
        summary = frida_runner.run_job("job1", tmp_path, "local", "httpd",
                                       [{"symbol": "main"}], seconds=5)
        assert record.get("local") is True  # get_local_device 原路径
        assert summary["sandbox_backend"] == "none"
        assert "警告" in summary["sandbox_warning"]

    def test_remote_mode_untouched(self, tmp_path, monkeypatch):
        monkeypatch.setattr(docker_backend, "_DOCKER_OK", True)
        monkeypatch.setattr(sandbox, "sandbox_image_present", lambda _i: True)
        record = {}
        monkeypatch.setitem(__import__("sys").modules, "frida",
                            _fake_frida_module(record))
        monkeypatch.setattr(frida_runner.time, "sleep", lambda _s: None)
        called = []
        monkeypatch.setattr(frida_runner.subprocess, "run",
                            lambda cmd, **kw: called.append(list(cmd)))
        summary = frida_runner.run_job("job1", tmp_path, "192.0.2.1", "httpd",
                                       [{"symbol": "main"}], seconds=5)
        assert record["remote_host"] == "192.0.2.1"
        assert not called  # 远程模式完全不碰 docker
        assert summary["sandbox_backend"] == "remote"


# ---------------------------------------------------------------------------
# 镜像检查提示
# ---------------------------------------------------------------------------

class TestEnsureImage:
    def test_missing_image_hints_build(self, monkeypatch, capsys):
        monkeypatch.setattr(docker_backend, "_DOCKER_OK", True)
        monkeypatch.setattr(sandbox, "sandbox_image_present", lambda _i: False)
        monkeypatch.setattr("pipeline.sandbox.image.sandbox_image_present",
                            lambda _i: False)
        assert sandbox.ensure_image() is False
        assert "docker build -f deploy/docker/Dockerfile.sandbox" in \
            capsys.readouterr().err

    def test_present(self, monkeypatch):
        monkeypatch.setattr(docker_backend, "_DOCKER_OK", True)
        monkeypatch.setattr("pipeline.sandbox.image.sandbox_image_present",
                            lambda _i: True)
        monkeypatch.setattr("pipeline.sandbox.image.docker_available",
                            lambda: True)
        assert sandbox.ensure_image() is True
