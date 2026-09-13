"""Function-level fuzzing with AFL++ QEMU persistent mode (arm/mips/...).

Design contract (per product decision):
  * x86 targets  -> use the frida stage (native instrumentation), not here
  * arm/mips/etc -> THIS stage: only the target FUNCTION executes —
    AFL_ENTRYPOINT + AFL_QEMU_PERSISTENT_ADDR jump straight to the function,
    the generic fw_fuzzhook.c hook places the mutated input into argument
    registers (per-arch ABI) and on the guest stack, and the link register
    points at the persistent-RET sentinel. The firmware is never fully
    emulated.
  * the whole-binary stdin/@@ mode remains for binaries that already read
    input from a file argument or stdin

Artifacts under data/fuzz/<job>/<run_id>/: afl_out/, fuzz.json (summary).
"""

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from pipeline import sandbox
from pipeline.trace import qemu_cov

FWGRAPH_ROOT = Path(__file__).resolve().parents[2]

_RUN_ID_RE = re.compile(r"^fz-[0-9a-f]{8}$")
HOOK_SRC = Path(__file__).with_name("fw_fuzzhook.c")

# 容器内 AFL++ 路径（镜像构建期编译，见 deploy/docker/Dockerfile.sandbox）
SANDBOX_AFL_FUZZ = "/opt/AFLplusplus/afl-fuzz"


def _max_seconds() -> int:
    """FUZZ_MAX_SECONDS（默认 600）；函数内 lazy 读取，不在 import 时固化。"""
    return int(os.getenv("FUZZ_MAX_SECONDS", "600"))


def _afl_repo() -> Path:
    """AFL++ 仓库路径（AFL_REPO，默认 ~/AFLplusplus）；lazy 读取。"""
    return Path(os.getenv("AFL_REPO", str(Path.home() / "AFLplusplus")))

_ARCH_MAP = {
    "arm": ("arm", "__FWHOOK_ARM__"),
    "arm64": ("aarch64", "__FWHOOK_ARM64__"),
    "aarch64": ("aarch64", "__FWHOOK_ARM64__"),
    "mips": ("mips", "__FWHOOK_MIPS__"),
    "mipsel": ("mipsel", "__FWHOOK_MIPS__"),
    "x86_64": ("x86_64", "__FWHOOK_X86_64__"),
    "i386": ("i386", "__FWHOOK_X86_64__"),
}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _afl_qemu_trace(arch=None):
    """Instrumented qemu runtime; per-arch builds (afl-qemu-trace-<arch>)
    preferred, generic afl-qemu-trace as fallback."""
    cand = os.getenv("FUZZ_AFL_QEMU")
    if cand and Path(cand).is_file():
        return cand
    afl_repo = _afl_repo()
    qemu_arch = _ARCH_MAP.get((arch or "").lower(), (None, None))[0]
    if qemu_arch:
        per_arch = afl_repo / f"afl-qemu-trace-{qemu_arch}"
        if per_arch.is_file():
            return str(per_arch)
    found = shutil.which("afl-qemu-trace")
    if found:
        return found
    default = afl_repo / "afl-qemu-trace"
    if default.is_file():
        return str(default)
    return None


def _afl_fuzz_bin():
    """宿主 afl-fuzz：AFL_FUZZ → PATH → $AFL_REPO/afl-fuzz。

    systemd 用户服务的 PATH 通常不含 ~/AFLplusplus，bare ``afl-fuzz``
    会 FileNotFoundError。沙箱路径仍用 SANDBOX_AFL_FUZZ。
    """
    explicit = os.getenv("AFL_FUZZ", "").strip()
    if explicit:
        p = Path(explicit)
        if p.is_file() and os.access(p, os.X_OK):
            return str(p.resolve())
        found = shutil.which(explicit)
        if found:
            return found
    found = shutil.which("afl-fuzz")
    if found:
        return found
    repo_bin = _afl_repo() / "afl-fuzz"
    if repo_bin.is_file() and os.access(repo_bin, os.X_OK):
        return str(repo_bin)
    raise RuntimeError(
        "afl-fuzz not found (PATH, AFL_FUZZ, or "
        f"{_afl_repo()}/afl-fuzz). Install AFL++ or set AFL_REPO / AFL_FUZZ.")


def _load_manifest_binary(data_dir, job_id, md5):
    manifest = json.loads((Path(data_dir) / "extracted" / job_id
                           / "manifest.json").read_text(encoding="utf-8"))
    for b in manifest.get("binaries", []):
        if b.get("md5") == md5:
            return b
    raise KeyError(f"binary md5 not in manifest: {md5}")


def _elf_entry(path):
    try:
        from elftools.elf.elffile import ELFFile
        with open(path, "rb") as fh:
            return ELFFile(fh).header.e_entry
    except Exception:
        return None


def _hook_for(arch, work_cache):
    """Compile (once) the generic persistent hook for this arch."""
    qemu_arch, macro = _ARCH_MAP.get((arch or "").lower(), (None, None))
    if qemu_arch is None:
        raise RuntimeError(f"unsupported fuzz arch: {arch}")
    hook = work_cache / f"fw_fuzzhook_{qemu_arch}.so"
    src_mtime = HOOK_SRC.stat().st_mtime if HOOK_SRC.is_file() else 0
    if hook.is_file() and hook.stat().st_mtime >= src_mtime:
        return hook
    work_cache.mkdir(parents=True, exist_ok=True)
    afl_repo = _afl_repo()
    inc = afl_repo / "qemu_mode" / "qemuafl"
    if not (inc / "qemuafl" / "api.h").is_file():
        raise RuntimeError(f"AFL++ checkout not found at {afl_repo}")
    cmd = ["cc", "-fPIC", "-shared", f"-D{macro}", "-I", str(inc),
           str(HOOK_SRC), "-o", str(hook)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(f"hook compile failed: {proc.stderr[-300:]}")
    return hook


def _seed_dir(work):
    seeds = work / "seeds"
    seeds.mkdir(parents=True, exist_ok=True)
    (seeds / "seed0").write_bytes(b"GET / HTTP/1.0\r\n\r\n")
    (seeds / "seed1").write_bytes(b"\x00" * 64)
    return seeds


_GLIBC_DOCKER_OK = {}


def _docker_can_exec_host_bin(path: str) -> bool:
    """宿主编译的 afl-qemu-trace 能否在沙箱镜像里跑（glibc 版本）。"""
    path = str(Path(path).resolve())
    cached = _GLIBC_DOCKER_OK.get(path)
    if cached is not None:
        return cached
    try:
        proc = subprocess.run(
            ["docker", "run", "--rm", "--network", "none",
             "-v", f"{path}:{path}:ro", sandbox.SANDBOX_IMAGE, path, "-h"],
            capture_output=True, timeout=25)
        blob = (proc.stdout or b"") + (proc.stderr or b"")
        ok = b"GLIBC_" not in blob
    except Exception:
        ok = False
    _GLIBC_DOCKER_OK[path] = ok
    return ok


def _sandbox_fallback_warning(backend):
    """配置了 docker 但无法进容器时的中文警告（落 fuzz.json，仿 trace 做法）。"""
    if backend != "docker":
        if sandbox.configured_backend("fuzz") == "docker":
            return ("警告：SANDBOX_BACKEND=docker 但 docker 不可用，本次 fuzz "
                    "在宿主机直接运行不可信固件代码。")
        return None
    return (f"警告：沙箱镜像 {sandbox.SANDBOX_IMAGE} 未构建，本次 fuzz 在宿主机"
            f"直接运行不可信固件代码。构建：{sandbox.BUILD_HINT}")


def _spawn_afl_docker(cmd, env, rootfs, work, trace_dir, qemu_trace, hook,
                      seconds):
    """把 afl-fuzz 包装进沙箱容器执行。所有路径宿主/容器同路径挂载，
    QEMU_LD_PREFIX / AFL_PATH / hook 等 env 原样生效；断网 + 只读 rootfs。

    已知边界：afl-qemu-trace 与 fw_fuzzhook_*.so 仍在宿主编译后挂载进容器，
    容器 glibc（ubuntu:24.04）与宿主差距过大时需按宿主工具链重建镜像。
    """
    # 编排器自身容器化运行时（Phase 3）work 由容器 root 创建；
    # 沙箱内 sandbox 用户（uid 1000）需要可写
    work.chmod(0o777)
    mounts = [(str(rootfs), str(rootfs), "ro"),      # job rootfs（QEMU_LD_PREFIX）
              (str(work), str(work), "rw"),          # seeds + afl_out
              (str(trace_dir), str(trace_dir), "ro")]  # AFL_PATH
    # AFL_PATH 里的 afl-qemu-trace 是指向宿主绝对路径的软链，目标也得进容器
    qemu_real = str(Path(qemu_trace).resolve())
    mounts.append((qemu_real, qemu_real, "ro"))
    if hook is not None:
        mounts.append((str(hook.parent), str(hook.parent), "ro"))
    # 只把 AFL/QEMU 相关变量带进容器，不泄漏宿主环境
    sandbox_env = {k: v for k, v in env.items()
                   if k.startswith(("AFL_", "QEMU_", "FUZZHOOK_"))}
    return sandbox.run_sandboxed(
        [SANDBOX_AFL_FUZZ] + cmd[1:], image=sandbox.SANDBOX_IMAGE,
        mounts=mounts, workdir=str(work), network="none", env=sandbox_env,
        timeout=seconds + 120)


def run_job(job_id, data_dir, binary_md5, function=None, args=None,
            argv=None, seconds=60, run_id=None):
    """Fuzz one function (function=hex addr, args=reg spec list) or a whole
    binary (argv with @@ / stdin). Returns the run summary dict."""
    data_dir = Path(data_dir)
    seconds = max(5, min(int(seconds), _max_seconds()))
    info = _load_manifest_binary(data_dir, job_id, binary_md5)
    extracted = data_dir / "extracted" / job_id
    rootfs, rel_in_rootfs = qemu_cov.find_rootfs(extracted, info["path"])
    target = rootfs / rel_in_rootfs.lstrip("/")
    arch = (info.get("arch") or "").lower()

    qemu_trace = _afl_qemu_trace(arch)
    if not qemu_trace:
        raise RuntimeError(
            "afl-qemu-trace not found (build AFLplusplus qemu_mode or set "
            "FUZZ_AFL_QEMU); refusing to fuzz without instrumentation")

    run_id = run_id or f"fz-{os.urandom(4).hex()}"
    work = data_dir / "fuzz" / job_id / run_id
    work.mkdir(parents=True, exist_ok=True)
    out_dir = work / "afl_out"
    seeds = _seed_dir(work)

    env = dict(os.environ)
    # qemu-user honors QEMU_LD_PREFIX for the dynamic loader path
    env["QEMU_LD_PREFIX"] = str(rootfs)
    env["AFL_QEMU_LD_PREFIX"] = str(rootfs)
    env["AFL_SKIP_CPUFREQ"] = "1"
    env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
    env["AFL_NO_UI"] = "1"
    env.setdefault("AFL_NO_AFFINITY", "1")
    # afl-fuzz resolves "afl-qemu-trace" by NAME inside AFL_PATH — point it
    # at a per-arch directory whose afl-qemu-trace is a link to the right
    # arch build (afl-qemu-trace-arm / -mipsel / ...)
    trace_dir = data_dir / "fuzz" / "aflrt" / (arch or "unknown")
    trace_dir.mkdir(parents=True, exist_ok=True)
    trace_link = trace_dir / "afl-qemu-trace"
    if not trace_link.exists() or Path(trace_link).resolve() !=             Path(qemu_trace).resolve():
        trace_link.unlink(missing_ok=True)
        trace_link.symlink_to(qemu_trace)
    env["AFL_PATH"] = str(trace_dir)

    mode = "binary"
    func_addr = None
    hook = None
    if function:
        # function-level persistent mode: enter at the function, mutate arg
        # registers via the generic hook, end iteration at the sentinel
        mode = "function"
        func_addr = int(str(function), 16) if isinstance(function, str) \
            else int(function)
        hook = _hook_for(arch, data_dir / "fuzz" / "hooks")
        env["AFL_QEMU_PERSISTENT_ADDR"] = hex(func_addr)
        # forkserver starts at the function; otherwise qemu must execute
        # through startup until this BB (firmware daemons rarely do).
        env["AFL_ENTRYPOINT"] = hex(func_addr)
        env["AFL_QEMU_PERSISTENT_GPR"] = "1"
        env["AFL_QEMU_PERSISTENT_EXITS"] = "1"
        env["AFL_QEMU_PERSISTENT_HOOK"] = str(hook)
        env["FUZZHOOK_ARGS"] = ",".join(args or ["buf", "len"])
        env["FUZZHOOK_FUNC_ADDR"] = hex(func_addr)
        # CTOR-heavy firmware ELFs often need a larger coverage map or the
        # forkserver handshake dies before the first persistent iteration.
        env.setdefault("AFL_MAP_SIZE", os.getenv("AFL_MAP_SIZE", "10000000"))

    cmd = ["afl-fuzz", "-Q", "-i", str(seeds), "-o", str(out_dir),
           "-V", str(seconds), "--", str(target)]
    if mode == "binary":
        cmd += list(argv or [])

    backend = sandbox.backend_for("fuzz")
    use_docker = backend == "docker" and \
        sandbox.sandbox_image_present(sandbox.SANDBOX_IMAGE)
    sandbox_warning = None if use_docker else _sandbox_fallback_warning(backend)
    if use_docker and not _docker_can_exec_host_bin(qemu_trace):
        use_docker = False
        sandbox_warning = (
            "警告：沙箱镜像 glibc 低于宿主 afl-qemu-trace 所需，本次 fuzz "
            "在宿主机直接运行不可信固件代码。重建匹配镜像或设 "
            "FUZZ_SANDBOX_BACKEND=none。"
        )

    started = time.time()
    if use_docker:
        proc = _spawn_afl_docker(cmd, env, rootfs, work, trace_dir,
                                 qemu_trace, hook, seconds)
    else:
        cmd[0] = _afl_fuzz_bin()
        try:
            proc = subprocess.Popen(cmd, cwd=str(work), env=env,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True,
                                    start_new_session=True)
        except FileNotFoundError as exc:
            raise RuntimeError(
                f"afl-fuzz not executable at {cmd[0]}: {exc}") from exc
    try:
        # host: stdout=PIPE + stderr=STDOUT so AFL_NO_UI 日志在 stdout
        out, err = proc.communicate(timeout=seconds + 120)
        stderr = out or err or ""
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass  # docker 看门狗可能已先一步清理
        proc.wait()
        rc = -signal.SIGKILL

    stats = {}
    stats_file = out_dir / "default" / "fuzzer_stats"
    if stats_file.is_file():
        for line in stats_file.read_text(errors="replace").splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                stats[k.strip()] = v.strip()

    def _count(sub):
        d = out_dir / "default" / sub
        if not d.is_dir():
            return 0
        return len([f for f in d.iterdir() if f.name.startswith("id:")])

    detail = None
    if rc not in (0, -signal.SIGKILL) and "handshake" in (stderr or ""):
        if "GLIBC_" in (stderr or ""):
            detail = ("afl-qemu-trace 无法在沙箱内启动（glibc 版本不够）；"
                      "应回退宿主运行")
        elif mode == "function":
            detail = ("forkserver handshake failed — AFL++ qemu persistent "
                      "官方只保证 x86/arm/aarch64，MIPS 函数级常在 handshake "
                      "阶段崩。请改整二进制（fw_request_fuzz 只传 binary_md5，"
                      "不要 function）；若 stderr 提到 AFL_MAP_SIZE 再加大 map")
        else:
            detail = ("forkserver handshake failed — 检查 afl-qemu-trace 能否"
                      "运行该架构目标")
    summary = {
        "run_id": run_id, "job_id": job_id, "engine": "afl-qemu",
        "mode": mode,
        "binary_md5": binary_md5, "binary_path": info["path"],
        "arch": info.get("arch"),
        "function": hex(func_addr) if func_addr is not None else None,
        "args": list(args or []) if mode == "function" else None,
        "argv": list(argv or []) if mode == "binary" else None,
        "seconds": seconds, "started_at": _now(),
        "status": "ok" if rc in (0, -signal.SIGKILL) else "error",
        "returncode": rc,
        "execs": int(float(stats.get("execs_done", 0) or 0)),
        "execs_per_sec": float(stats.get("execs_per_sec", 0) or 0),
        "crashes": _count("crashes"),
        "hangs": _count("hangs"),
        "paths": int(float(stats.get("paths_total", 0) or 0)),
        "crashes_dir": str(out_dir / "default" / "crashes"),
        "detail": detail,
        "stderr_tail": (stderr or "")[-400:],
        "elapsed_seconds": round(time.time() - started, 2),
        "sandbox_backend": "docker" if use_docker else "none",
    }
    if use_docker:
        summary["sandbox_image"] = sandbox.SANDBOX_IMAGE
        summary["sandbox_limits"] = dict(sandbox.DEFAULT_LIMITS)
    if sandbox_warning:
        summary["sandbox_warning"] = sandbox_warning
    (work / "fuzz.json").write_text(json.dumps(summary, indent=2),
                                    encoding="utf-8")
    return summary


def list_runs(job_id, data_dir):
    base = Path(data_dir) / "fuzz" / job_id
    out = []
    if base.is_dir():
        for d in sorted(base.iterdir(), reverse=True):
            f = d / "fuzz.json"
            if f.is_file():
                out.append(json.loads(f.read_text(encoding="utf-8")))
    return out


def get_run(job_id, data_dir, run_id):
    if not _RUN_ID_RE.match(run_id):
        raise ValueError("bad run id")
    f = Path(data_dir) / "fuzz" / job_id / run_id / "fuzz.json"
    if not f.is_file():
        raise KeyError(run_id)
    return json.loads(f.read_text(encoding="utf-8"))
