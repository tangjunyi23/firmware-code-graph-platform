from __future__ import annotations
import argparse
import os
from typing import Optional

from .analyzer import RootfsAnalyzer
from .config import ensure_ida_env, get_default_out_base
from .model_types import RootfsAnalyzeOptions


def build_default_out_dir(rootfs_dir: str) -> str:
    base = get_default_out_base()
    name = os.path.basename(os.path.abspath(rootfs_dir)) or "rootfs"
    return os.path.join(base, name)


def run_cli(
    rootfs_dir: str,
    out_dir: Optional[str],
    workers: int,
    resume: bool,
    force: bool,
    only_failed: bool,
    timeout: int,
    retry: int,
    only_exec: bool,
    include_so: bool,
    exclude: Optional[str],
    skip_memory: bool,
    no_decompile_funcs: bool,
    no_function_index: bool,
    max_bytes: Optional[int],
    progress: bool,
    progress_every: int,
    checksec_dump: bool,
    run_ida: bool,
    ida_log: bool,
) -> dict:
    resolved_out_dir = out_dir or build_default_out_dir(rootfs_dir)
    options = RootfsAnalyzeOptions(
        out_dir=resolved_out_dir,
        workers=workers,
        resume=resume,
        force=force,
        only_failed=only_failed,
        timeout=timeout,
        retry=retry,
        only_exec=only_exec,
        include_so=include_so,
        exclude=exclude,
        skip_memory=skip_memory,
        no_decompile_funcs=no_decompile_funcs,
        no_function_index=no_function_index,
        max_bytes=max_bytes,
        progress=progress,
        progress_every=progress_every,
        checksec_dump=checksec_dump,
        run_ida=run_ida,
        ida_log=ida_log,
    )
    analyzer = RootfsAnalyzer(rootfs_dir, options)
    return analyzer.run()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rootfs_elf",
        description="Scan a RootFS directory, collect ELF metadata, and optionally export IDA artifacts.",
    )
    parser.add_argument("rootfs_dir", help="RootFS directory to scan")
    parser.add_argument("-o", "--out-dir", help="Output directory")
    parser.add_argument("-j", "--workers", type=int, default=1, help="Parallel IDA workers")
    parser.add_argument("--resume", action="store_true", default=True, help="Keep completed results")
    parser.add_argument("--force", action="store_true", help="Re-run all ELFs even if completed")
    parser.add_argument("--only-failed", action="store_true", help="Re-run only failed ELFs")
    parser.add_argument("--timeout", type=int, default=0, help="Per-ELF timeout in seconds, 0 disables")
    parser.add_argument("--retry", type=int, default=0, help="Retry count for failed IDA jobs")
    parser.add_argument("--only-exec", action="store_true", help="Analyze ET_EXEC only")
    parser.add_argument(
        "--include-so",
        action="store_true",
        default=True,
        help="Include shared libraries and PIE executables (ET_DYN); enabled by default",
    )
    parser.add_argument("--exclude", help="Regex for relative paths to skip")
    parser.add_argument("--skip-memory", action="store_true", help="Do not dump memory segments")
    parser.add_argument("--no-decompile-funcs", action="store_true", help="Do not export per-function decompilation")
    parser.add_argument("--no-function-index", action="store_true", help="Do not export function_index.jsonl")
    parser.add_argument("--max-bytes", type=int, help="Skip files larger than this size")
    parser.add_argument("--progress", action="store_true", help="Print scan/IDA progress")
    parser.add_argument("--progress-every", type=int, default=1000, help="Progress reporting interval")
    parser.add_argument("--checksec-dump", action="store_true", help="Store raw checksec stdout/stderr in metadata")
    parser.add_argument("--run-ida", action="store_true", help="Run IDA exporter for queued ELFs")
    parser.add_argument("--ida-log", action="store_true", help="Write per-ELF ida.log files")
    return parser


def main() -> int:
    ensure_ida_env()
    parser = build_parser()
    args = parser.parse_args()

    summary = run_cli(
        rootfs_dir=args.rootfs_dir,
        out_dir=args.out_dir,
        workers=args.workers,
        resume=args.resume,
        force=args.force,
        only_failed=args.only_failed,
        timeout=args.timeout,
        retry=args.retry,
        only_exec=args.only_exec,
        include_so=args.include_so,
        exclude=args.exclude,
        skip_memory=args.skip_memory,
        no_decompile_funcs=args.no_decompile_funcs,
        no_function_index=args.no_function_index,
        max_bytes=args.max_bytes,
        progress=args.progress,
        progress_every=args.progress_every,
        checksec_dump=args.checksec_dump,
        run_ida=args.run_ida,
        ida_log=args.ida_log,
    )
    print(f"analysis complete: {summary['out_dir']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
