"""Decompilation executor for the fwgraph orchestrator (M2).

For every ELF in data/extracted/<job>/manifest.json, run the rootfs_elf
IDA worker (tools/ida-no-mcp/rootfs_elf/ida_worker.py, idalib) with a
concurrency cap of IDA_WORKERS and a per-binary timeout of IDA_TIMEOUT
seconds. Raw/PX4 images still use idat + pipeline/decompile/ida_export.py
because rootfs_elf only opens ELF databases.

Layout:
  data/idb/<job>/<md5>.i64          IDB for raw images (idat path)
  data/pseudocode/<job>/<md5>/      rootfs_elf export + adapted functions/
  data/pseudocode/<job>/symbols.json
      merged export grouped by md5, annotated in place by
      pipeline.decompile.annotate (tags + rule names)
  data/pseudocode/<job>/decompile_summary.json

Config (.env): IDA_DIR, IDA_WORKERS (3), IDA_TIMEOUT (1800).
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from pipeline.decompile import annotate
from pipeline.decompile.rootfs_elf_adapt import adapt_rootfs_elf_outdir

from . import config

# fwgraph/orchestrator/app/decompiler.py -> ../../.. = fwgraph/
FWGRAPH_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = Path(__file__).resolve().parents[3]
EXPORT_SCRIPT = FWGRAPH_ROOT / "pipeline" / "decompile" / "ida_export.py"
ROOTFS_ELF_WORKER = (
    REPO_ROOT / "tools" / "ida-no-mcp" / "rootfs_elf" / "ida_worker.py")


def _cfg(name: str, default: str) -> str:
    return os.getenv(name, default)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def rootfs_elf_worker() -> Path:
    override = os.getenv("ROOTFS_ELF_WORKER", "").strip()
    return Path(override) if override else ROOTFS_ELF_WORKER


def _ida_libdir(ida_root: Path) -> Path | None:
    if (ida_root / "libidalib.so").is_file():
        return ida_root
    for base, _, files in os.walk(ida_root):
        if "libidalib.so" in files:
            return Path(base)
    return None


def _rootfs_elf_command(elf: Path, outdir: Path) -> list[str]:
    worker = rootfs_elf_worker()
    cmd = [
        sys.executable,
        str(worker),
        "--elf", str(elf),
        "--out-dir", str(outdir),
        "--skip-memory",
        "--log-path", str(outdir / "idat.log"),
    ]
    ida = config.ida_dir()
    if ida is not None:
        cmd.extend(["--ida-dir", str(ida)])
    return cmd


def _rootfs_elf_environment() -> dict[str, str]:
    env = dict(os.environ, TVHEADLESS="1")
    ida = config.ida_dir()
    if ida is None:
        return env
    env.setdefault("IDADIR", str(ida))
    libdir = _ida_libdir(ida)
    if libdir is not None:
        existing = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = (
            f"{libdir}:{existing}" if existing else str(libdir))
    return env


def _ida_command(idat: Path, input_path: Path, outdir: Path, binary: dict) -> list[str]:
    """Build an IDA command, applying raw-loader options only when verified."""
    cmd = [str(idat), "-A"]
    if binary.get("file_format") == "raw":
        loader = binary.get("loader") or {}
        processor = str(loader.get("ida_processor") or "")
        base = loader.get("image_base")
        entrypoint = loader.get("entrypoint")
        if processor != "ARM" or not isinstance(base, int) or base <= 0:
            raise ValueError("raw binary is missing a supported verified IDA profile")
        if base % 16:
            raise ValueError("raw binary image base must be 16-byte aligned")
        if not isinstance(entrypoint, int) or entrypoint < base:
            raise ValueError("raw binary is missing a verified entrypoint")
        if binary.get("bits") != 32 or binary.get("endianness") != "le":
            raise ValueError("raw ARM loader currently requires 32-bit little endian")
        if input_path.suffix.lower() != ".i64":
            # IDA's -b argument is expressed in 16-byte paragraphs, while the
            # manifest stores the real byte address used by vectors/xrefs.
            cmd.extend([f"-p{processor}:ARMv7-M", f"-b{base >> 4:X}",
                        "-TBinary file"])
        script_arg = f"-S{EXPORT_SCRIPT} {outdir} --raw-entry={entrypoint:#x}"
    else:
        script_arg = f"-S{EXPORT_SCRIPT} {outdir}"
    cmd.extend([script_arg, str(input_path)])
    return cmd


def _ida_environment(binary: dict) -> dict[str, str]:
    env = dict(os.environ, TVHEADLESS="1")
    if binary.get("file_format") == "raw" and binary.get("arch") == "arm":
        # IDA otherwise defaults raw ARM images to a generic architecture and
        # can terminate Cortex-M functions at valid M-profile instructions.
        env["ARM_DEFAULT_ARCHITECTURE"] = "ARMv7-M"
    return env


def _wait_process(proc, timeout: int) -> str | None:
    """None if the process exited, or 'timeout' after SIGKILL."""
    deadline = time.monotonic() + timeout
    while proc.poll() is None:
        if time.monotonic() > deadline:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
            return "timeout"
        time.sleep(2)
    return None


def _decompile_binary_idat(job_id: str, binary: dict, data_dir: Path,
                           timeout: int) -> dict:
    """Run one headless IDA export for raw images; never raises."""
    md5 = binary["md5"]
    result = {"md5": md5, "path": binary["path"], "status": "failed",
              "error": None, "idb_reused": False, "elapsed_seconds": 0.0,
              "exporter": "ida_export"}
    t0 = time.time()
    try:
        elf = data_dir / "extracted" / job_id / binary["path"]
        if not elf.is_file():
            result["error"] = f"extracted file missing: {elf}"
            return result
        idb_dir = data_dir / "idb" / job_id
        outdir = data_dir / "pseudocode" / job_id / md5
        idb_dir.mkdir(parents=True, exist_ok=True)
        outdir.mkdir(parents=True, exist_ok=True)
        idb = idb_dir / f"{md5}.i64"
        if idb.is_file():
            input_path = idb
            result["idb_reused"] = True
        else:
            input_path = idb_dir / md5
            if not input_path.exists():
                shutil.copy2(elf, input_path)

        idat = config.ida_dir() / "idat"
        cmd = _ida_command(idat, input_path, outdir, binary)
        env = _ida_environment(binary)
        (outdir / "export_done.json").unlink(missing_ok=True)
        with open(outdir / "idat.log", "wb") as logf:
            proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT,
                                    env=env, start_new_session=True)
            if _wait_process(proc, timeout) == "timeout":
                result["status"] = "timeout"
                result["error"] = f"killed after {timeout}s"
                return result

        done_file = outdir / "export_done.json"
        if not done_file.is_file():
            result["error"] = (f"idat exited rc={proc.returncode}, "
                               f"no export_done.json (see idat.log)")
            return result
        done = json.loads(done_file.read_text(encoding="utf-8"))
        if done.get("status") != "ok":
            result["error"] = str(done.get("error") or "export failed")[:300]
            return result
        if binary.get("file_format") == "raw" and done.get("functions", 0) <= 0:
            result["error"] = "raw IDA analysis produced zero functions"
            return result
        result["status"] = "ok"
        result["functions"] = done.get("functions", 0)
        result["decompiled"] = done.get("decompiled", 0)
        result["export_errors"] = done.get("export_errors", 0)
        result["naming"] = done.get("naming")
        if done.get("flirt"):
            result["flirt_named_delta"] = done["flirt"].get("named_delta")
        return result
    except Exception as exc:  # noqa: BLE001 - per-binary failure is not fatal
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result
    finally:
        result["elapsed_seconds"] = round(time.time() - t0, 2)


def _decompile_binary_rootfs_elf(job_id: str, binary: dict, data_dir: Path,
                                 timeout: int) -> dict:
    """Run rootfs_elf ida_worker.py (idalib) on one ELF; never raises."""
    md5 = binary["md5"]
    result = {"md5": md5, "path": binary["path"], "status": "failed",
              "error": None, "idb_reused": False, "elapsed_seconds": 0.0,
              "exporter": "rootfs_elf"}
    t0 = time.time()
    try:
        elf = data_dir / "extracted" / job_id / binary["path"]
        if not elf.is_file():
            result["error"] = f"extracted file missing: {elf}"
            return result
        worker = rootfs_elf_worker()
        if not worker.is_file():
            result["error"] = f"rootfs_elf worker missing: {worker}"
            return result
        outdir = data_dir / "pseudocode" / job_id / md5
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / "export_done.json").unlink(missing_ok=True)
        (outdir / "symbols_raw.json").unlink(missing_ok=True)

        cmd = _rootfs_elf_command(elf, outdir)
        env = _rootfs_elf_environment()
        with open(outdir / "idat.log", "wb") as logf:
            proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT,
                                    env=env, start_new_session=True)
            if _wait_process(proc, timeout) == "timeout":
                result["status"] = "timeout"
                result["error"] = f"killed after {timeout}s"
                return result

        if proc.returncode != 0:
            result["error"] = (
                f"rootfs_elf ida_worker exited rc={proc.returncode} "
                f"(see idat.log)")
            return result

        done = adapt_rootfs_elf_outdir(outdir, binary)
        if done.get("status") != "ok":
            result["error"] = str(done.get("error") or "rootfs_elf adapt failed")[:300]
            return result
        result["status"] = "ok"
        result["functions"] = done.get("functions", 0)
        result["decompiled"] = done.get("decompiled", 0)
        result["export_errors"] = done.get("export_errors", 0)
        result["naming"] = None
        return result
    except Exception as exc:  # noqa: BLE001 - per-binary failure is not fatal
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result
    finally:
        result["elapsed_seconds"] = round(time.time() - t0, 2)


def _decompile_binary(job_id: str, binary: dict, data_dir: Path, timeout: int) -> dict:
    """Run one export; ELF goes through rootfs_elf, raw images through idat."""
    if binary.get("file_format") == "raw":
        return _decompile_binary_idat(job_id, binary, data_dir, timeout)
    return _decompile_binary_rootfs_elf(job_id, binary, data_dir, timeout)


def run_job(job_id: str, data_dir, only_md5s=None) -> dict:
    """Decompile binaries of a job, merge + annotate, write summary.

    With only_md5s (targeted mode) only manifest binaries with those md5s are
    decompiled and their entries are merged into any existing symbols.json;
    without it every binary is decompiled and symbols.json is rewritten.
    """
    data_dir = Path(data_dir)
    if config.ida_dir() is None:
        # 启动 decompile job 前 fail-fast：错误会经 _decompile_worker 落入 job.error
        raise RuntimeError(
            "未配置 IDA_DIR：请在 fwgraph/.env 或环境变量中设置 IDA 安装目录")
    t0 = time.time()
    manifest_path = data_dir / "extracted" / job_id / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    out_root = data_dir / "pseudocode" / job_id
    out_root.mkdir(parents=True, exist_ok=True)

    timeout = int(_cfg("IDA_TIMEOUT", "1800"))
    workers = max(1, int(_cfg("IDA_WORKERS", "3")))

    manifest_binaries = manifest.get("binaries", [])
    if only_md5s is not None:
        only_md5s = set(only_md5s)
        manifest_binaries = [b for b in manifest_binaries
                             if b["md5"] in only_md5s]

    # one idat/ida_worker run per md5: identical binaries share the export
    binaries, seen, aliases = [], set(), {}
    for b in manifest_binaries:
        if b["md5"] in seen:
            aliases.setdefault(b["md5"], []).append(b["path"])
            continue
        seen.add(b["md5"])
        binaries.append(b)

    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_decompile_binary, job_id, b, data_dir, timeout)
                   for b in binaries]
        for fut in as_completed(futures):
            results.append(fut.result())

    symbols = {"job_id": job_id, "created_at": _now(), "binaries": {}}
    symbols_path = out_root / "symbols.json"
    if only_md5s is not None and symbols_path.is_file():
        # targeted run: keep entries of binaries outside this run
        try:
            prev = json.loads(symbols_path.read_text(encoding="utf-8"))
            if isinstance(prev.get("binaries"), dict):
                symbols["binaries"] = prev["binaries"]
        except (OSError, json.JSONDecodeError):
            pass
    for b in binaries:
        md5 = b["md5"]
        raw_path = out_root / md5 / "symbols_raw.json"
        if not raw_path.is_file():
            continue
        raw = json.loads(raw_path.read_text(encoding="utf-8"))
        symbols["binaries"][md5] = {
            "path": b["path"],
            "arch": b.get("arch"),
            "bits": b.get("bits"),
            "endianness": b.get("endianness"),
            "sha256": b.get("sha256"),
            "checksec": b.get("checksec"),
            "file_format": b.get("file_format", "elf"),
            "rtos": b.get("rtos"),
            "board_id": b.get("board_id"),
            "board": b.get("board"),
            "soc": b.get("soc"),
            "loader": b.get("loader"),
            "md5": md5,
            "aliases": aliases.get(md5, []),
            "meta": raw.get("meta", {}),
            "functions": raw.get("functions", []),
        }
    symbols_path.write_text(json.dumps(symbols, indent=1), encoding="utf-8")
    annotate_stats = annotate.annotate_file(symbols_path)

    ok = [r for r in results if r["status"] == "ok"]
    summary = {
        "job_id": job_id,
        "created_at": _now(),
        "exporter": "rootfs_elf",
        "only_md5s": sorted(only_md5s) if only_md5s is not None else None,
        "total_binaries": len(results),
        "succeeded": len(ok),
        "failed": sum(1 for r in results if r["status"] == "failed"),
        "timed_out": sum(1 for r in results if r["status"] == "timeout"),
        "total_functions": sum(r.get("functions", 0) for r in ok),
        "total_decompiled": sum(r.get("decompiled", 0) for r in ok),
        "workers": workers,
        "binaries": sorted(results, key=lambda r: r["path"]),
        "annotate": annotate_stats,
        "elapsed_seconds": round(time.time() - t0, 2),
    }
    (out_root / "decompile_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")
    return summary
