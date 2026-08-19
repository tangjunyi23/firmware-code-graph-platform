"""Decompilation executor for the fwgraph orchestrator (M2).

For every ELF in data/extracted/<job>/manifest.json, run IDA headless
(pipeline/decompile/ida_export.py) with a concurrency cap of IDA_WORKERS and a
per-binary timeout of IDA_TIMEOUT seconds.

Layout:
  data/idb/<job>/<md5>.i64          IDB; reused on re-runs. If absent, the ELF
                                    is copied to data/idb/<job>/<md5> and IDA
                                    creates the .i64 next to it.
  data/pseudocode/<job>/<md5>/      ida_export.py output (+ idat.log)
  data/pseudocode/<job>/symbols.json
      merged export grouped by md5, annotated in place by
      pipeline.decompile.annotate (tags + rule names)
  data/pseudocode/<job>/decompile_summary.json

Config (.env): IDA_DIR, IDA_WORKERS (3), IDA_TIMEOUT (1800).

M2b: LUMINA_ENABLED and FLIRT_SIGS (see .env.example) are not parsed here;
the idat subprocess inherits this process's environment, so they reach
ida_export.py directly.
"""

import json
import os
import shutil
import signal
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from pipeline.decompile import annotate

from . import config

# fwgraph/orchestrator/app/decompiler.py -> ../../.. = fwgraph/
FWGRAPH_ROOT = Path(__file__).resolve().parents[2]
EXPORT_SCRIPT = FWGRAPH_ROOT / "pipeline" / "decompile" / "ida_export.py"


def _cfg(name: str, default: str) -> str:
    return os.getenv(name, default)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def _decompile_binary(job_id: str, binary: dict, data_dir: Path, timeout: int) -> dict:
    """Run one headless IDA export; never raises (errors land in result)."""
    md5 = binary["md5"]
    result = {"md5": md5, "path": binary["path"], "status": "failed",
              "error": None, "idb_reused": False, "elapsed_seconds": 0.0}
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

        idat = config.ida_dir() / "idat"  # run_job 已保证 IDA_DIR 已配置
        # The outdir rides inside the -S argument: a trailing token after the
        # input file never reaches idc.ARGV on IDA 9.1 (probe-verified).
        cmd = _ida_command(idat, input_path, outdir, binary)
        env = _ida_environment(binary)
        # A prior marker must never make a failed retry look successful.
        (outdir / "export_done.json").unlink(missing_ok=True)
        with open(outdir / "idat.log", "wb") as logf:
            proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT,
                                    env=env, start_new_session=True)
            deadline = time.monotonic() + timeout
            while proc.poll() is None:
                if time.monotonic() > deadline:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    proc.wait()
                    result["status"] = "timeout"
                    result["error"] = f"killed after {timeout}s"
                    return result
                time.sleep(2)

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
        # M2b: naming-recovery stats for the summary (None when steps were off)
        result["naming"] = done.get("naming")
        if done.get("flirt"):
            result["flirt_named_delta"] = done["flirt"].get("named_delta")
        return result
    except Exception as exc:  # noqa: BLE001 - per-binary failure is not fatal
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result
    finally:
        result["elapsed_seconds"] = round(time.time() - t0, 2)


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

    # one idat run per md5: identical binaries share the IDB and the export
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
        "only_md5s": sorted(only_md5s) if only_md5s is not None else None,
        "total_binaries": len(results),
        "succeeded": len(ok),
        "failed": sum(1 for r in results if r["status"] == "failed"),
        "timed_out": sum(1 for r in results if r["status"] == "timeout"),
        "total_functions": sum(r.get("functions", 0) for r in ok),
        "total_decompiled": sum(r.get("decompiled", 0) for r in ok),
        "binaries": sorted(results, key=lambda r: r["path"]),
        "annotate": annotate_stats,
        "elapsed_seconds": round(time.time() - t0, 2),
    }
    (out_root / "decompile_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")
    return summary
