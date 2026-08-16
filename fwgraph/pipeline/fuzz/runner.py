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

from pipeline.trace import qemu_cov

FWGRAPH_ROOT = Path(__file__).resolve().parents[2]

MAX_SECONDS = int(os.getenv("FUZZ_MAX_SECONDS", "600"))
_RUN_ID_RE = re.compile(r"^fz-[0-9a-f]{8}$")
AFL_REPO = Path(os.getenv("AFL_REPO", str(Path.home() / "AFLplusplus")))
HOOK_SRC = Path(__file__).with_name("fw_fuzzhook.c")

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
    qemu_arch = _ARCH_MAP.get((arch or "").lower(), (None, None))[0]
    if qemu_arch:
        per_arch = AFL_REPO / f"afl-qemu-trace-{qemu_arch}"
        if per_arch.is_file():
            return str(per_arch)
    found = shutil.which("afl-qemu-trace")
    if found:
        return found
    default = AFL_REPO / "afl-qemu-trace"
    if default.is_file():
        return str(default)
    return None


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
    if hook.is_file():
        return hook
    work_cache.mkdir(parents=True, exist_ok=True)
    inc = AFL_REPO / "qemu_mode" / "qemuafl"
    if not (inc / "qemuafl" / "api.h").is_file():
        raise RuntimeError(f"AFL++ checkout not found at {AFL_REPO}")
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


def run_job(job_id, data_dir, binary_md5, function=None, args=None,
            argv=None, seconds=60, run_id=None):
    """Fuzz one function (function=hex addr, args=reg spec list) or a whole
    binary (argv with @@ / stdin). Returns the run summary dict."""
    data_dir = Path(data_dir)
    seconds = max(5, min(int(seconds), MAX_SECONDS))
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
    if function:
        # function-level persistent mode: enter at the function, mutate arg
        # registers via the generic hook, end iteration at the sentinel
        mode = "function"
        func_addr = int(str(function), 16) if isinstance(function, str) \
            else int(function)
        hook = _hook_for(arch, data_dir / "fuzz" / "hooks")
        env["AFL_QEMU_PERSISTENT_ADDR"] = hex(func_addr)
        env["AFL_QEMU_PERSISTENT_GPR"] = "1"
        env["AFL_QEMU_PERSISTENT_EXITS"] = "1"
        env["AFL_QEMU_PERSISTENT_HOOK"] = str(hook)
        env["FUZZHOOK_ARGS"] = ",".join(args or ["buf", "len"])

    cmd = ["afl-fuzz", "-Q", "-i", str(seeds), "-o", str(out_dir),
           "-V", str(seconds), "--", str(target)]
    if mode == "binary":
        cmd += list(argv or [])

    started = time.time()
    proc = subprocess.Popen(cmd, cwd=str(work), env=env,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE, text=True,
                            start_new_session=True)
    try:
        _, stderr = proc.communicate(timeout=seconds + 120)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
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
        detail = ("forkserver handshake failed — 目标函数在正常启动流程中"
                  "未被到达（qemu 的 persistent 模式要求执行自然经过该函数"
                  "入口）；请换启动可达的函数，或改用 frida/整机 trace")
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
    }
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
