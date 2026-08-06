from __future__ import annotations
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import threading
from typing import Dict, Any, Optional, List, Tuple

from .checksec import run_checksec, ChecksecError
from .config import ensure_ida_env, get_tools_path
from .scanner import scan_rootfs
from .model_types import RootfsAnalyzeOptions, ElfInfo
from .utils import append_jsonl, ensure_dir, iter_files, sanitize_rel_path, write_json


class RootfsAnalyzer:
    def __init__(self, rootfs_dir: str, options: RootfsAnalyzeOptions):
        self.rootfs_dir = os.path.abspath(rootfs_dir)
        self.options = options
        self.tools_path = get_tools_path()

        self.out_dir = os.path.abspath(options.out_dir)
        self.by_elf_dir = os.path.join(self.out_dir, "by_elf")
        self.index_dir = os.path.join(self.out_dir, "indexes")
        self.manifest_path = os.path.join(self.out_dir, "manifest.jsonl")
        self.errors_path = os.path.join(self.out_dir, "errors.jsonl")
        self.summary_path = os.path.join(self.out_dir, "summary.json")

        self.stats: Dict[str, int] = {
            "total_elf": 0,
            "queued": 0,
            "skipped": 0,
            "failed": 0,
        }
        self._running: Dict[str, Dict[str, Any]] = {}
        self._running_lock = threading.Lock()

    def _ensure_layout(self) -> None:
        ensure_dir(self.out_dir)
        ensure_dir(self.by_elf_dir)
        ensure_dir(self.index_dir)

    def _reset_run_artifacts(self) -> None:
        for path in (self.manifest_path, self.errors_path):
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError:
                pass

    def _elf_id(self, elf: ElfInfo) -> str:
        suffix = sanitize_rel_path(elf.rel_path)
        return f"{suffix}__{elf.sha256[:8]}"

    def _meta_path(self, elf_id: str) -> str:
        return os.path.join(self.by_elf_dir, elf_id, "meta.json")

    def _should_skip(self, elf_id: str) -> bool:
        meta_path = self._meta_path(elf_id)
        if not os.path.exists(meta_path):
            return False

        if self.options.force:
            return False

        try:
            with open(meta_path, "r", encoding="utf-8", errors="ignore") as f:
                meta = json.load(f)
        except Exception:
            return False

        status = meta.get("status")
        if self.options.only_failed:
            return status != "failed"

        if self.options.resume and status in ("done", "pending"):
            return True

        return status == "done"

    def _write_meta(self, elf_id: str, meta: Dict[str, Any]) -> None:
        elf_dir = os.path.join(self.by_elf_dir, elf_id)
        ensure_dir(elf_dir)
        write_json(os.path.join(elf_dir, "meta.json"), meta)

    def _record_error(self, elf: ElfInfo, elf_id: str, reason: str) -> None:
        entry = {
            "elf_id": elf_id,
            "path": elf.path,
            "rel_path": elf.rel_path,
            "reason": reason,
            "timestamp": int(time.time()),
        }
        append_jsonl(self.errors_path, entry)
        self.stats["failed"] += 1

    def _queue_task(self, elf: ElfInfo) -> Optional[str]:
        elf_id = self._elf_id(elf)
        if self._should_skip(elf_id):
            self.stats["skipped"] += 1
            return None

        meta: Dict[str, Any] = {
            "status": "pending",
            "path": elf.path,
            "rel_path": elf.rel_path,
            "size": elf.size,
            "sha256": elf.sha256,
            "arch": elf.arch,
            "bits": elf.bits,
            "endian": elf.endian,
            "elf_type": elf.elf_type,
            "checksec": None,
            "created_at": int(time.time()),
            "updated_at": int(time.time()),
        }

        try:
            raw, normalized, dump = run_checksec(
                elf.path,
                self.tools_path,
                capture_output=self.options.checksec_dump,
            )
            meta["checksec"] = {
                "raw": raw,
                "normalized": normalized,
            }
            if dump:
                meta["checksec"]["dump"] = dump
        except ChecksecError as exc:
            if self.options.checksec_dump and getattr(exc, "dump", None):
                meta["checksec"] = {
                    "error": str(exc),
                    "dump": exc.dump,
                }
            self._record_error(elf, elf_id, f"checksec: {exc}")

        self._write_meta(elf_id, meta)
        append_jsonl(self.manifest_path, {"elf_id": elf_id, "status": "pending"})
        self.stats["queued"] += 1
        return elf_id

    def _update_meta_status(self, elf_id: str, status: str, error: Optional[str] = None) -> None:
        meta_path = self._meta_path(elf_id)
        try:
            with open(meta_path, "r", encoding="utf-8", errors="ignore") as f:
                meta = json.load(f)
        except Exception:
            meta = {}
        meta["status"] = status
        if error:
            meta["error"] = error
        meta["updated_at"] = int(time.time())
        self._write_meta(elf_id, meta)

    def _run_worker(self, elf: ElfInfo, elf_id: str) -> None:
        out_dir = os.path.join(self.by_elf_dir, elf_id)
        
        # Cleanup if retrying failed task to avoid stale files
        if os.path.exists(out_dir) and (self.options.force or self.options.only_failed):
             # Don't remove directory itself to keep it atomic if possible, but maybe safer to clear contents
             # or just overwrite. IDA worker overwrites files. 
             # But if we have resume logic, we might want to start fresh.
             # Let's remove key files to ensure clean state.
             for f in os.listdir(out_dir):
                 if f == "meta.json": continue
                 path = os.path.join(out_dir, f)
                 try:
                     if os.path.isfile(path):
                         os.unlink(path)
                     # Directory removal (like decompile/)
                     elif os.path.isdir(path):
                         import shutil
                         shutil.rmtree(path)
                 except OSError:
                     pass

        ida_dir, ida_lib_dir = self._resolve_ida_dirs()
        worker_script = os.path.join(os.path.dirname(__file__), "ida_worker.py")
        cmd = [
            sys.executable,
            worker_script,
            "--elf",
            elf.path,
            "--out-dir",
            out_dir,
        ]
        if self.options.ida_log:
            cmd.extend(["--log-path", os.path.join(out_dir, "ida.log")])
        if ida_dir:
            cmd.extend(["--ida-dir", ida_dir])
        if self.options.skip_memory:
            cmd.append("--skip-memory")
        if self.options.no_decompile_funcs:
            cmd.append("--no-decompile-funcs")
        if self.options.no_function_index:
            cmd.append("--no-function-index")
        env = os.environ.copy()
        if ida_dir:
            env["IDADIR"] = ida_dir
        if ida_lib_dir:
            existing = env.get("LD_LIBRARY_PATH", "")
            env["LD_LIBRARY_PATH"] = (
                f"{ida_lib_dir}:{existing}" if existing else ida_lib_dir
            )

        attempt = 0
        with self._running_lock:
            self._running[elf_id] = {
                "path": elf.path,
                "start": time.time(),
            }
        try:
            while True:
                try:
                    self._update_meta_status(elf_id, "running")
                    timeout = self.options.timeout if self.options.timeout > 0 else None
                    subprocess.run(cmd, check=True, timeout=timeout, env=env)
                    self._update_meta_status(elf_id, "done")
                    return
                except subprocess.TimeoutExpired:
                    attempt += 1
                    if attempt > self.options.retry:
                        self._update_meta_status(elf_id, "failed", "timeout")
                        self.stats["failed"] += 1
                        return
                except Exception as exc:
                    attempt += 1
                    if attempt > self.options.retry:
                        self._update_meta_status(elf_id, "failed", str(exc))
                        self.stats["failed"] += 1
                        return
        finally:
            with self._running_lock:
                self._running.pop(elf_id, None)

    def _generate_global_indexes(self) -> None:
        """Generates global CSV/JSONL indexes and evidence-based labels."""
        if self.options.progress:
            print("[rootfs_elf] Generating global indexes...", flush=True)

        elf_index_path = os.path.join(self.index_dir, "elf_index.csv")
        strings_global_path = os.path.join(self.index_dir, "strings_global.jsonl")
        imports_global_path = os.path.join(self.index_dir, "imports_global.jsonl")
        exports_global_path = os.path.join(self.index_dir, "exports_global.jsonl")
        entry_candidates_path = os.path.join(self.index_dir, "entry_candidates.jsonl")
        label_evidence_path = os.path.join(self.index_dir, "label_evidence.jsonl")

        # Prepare files
        with open(elf_index_path, "w", encoding="utf-8", errors="ignore") as f_elf:
            f_elf.write("elf_id,path,rel_path,arch,bits,endian,type,size,status,nx,canary,relro,pie\n")

        # Iterators for large files (append mode) - but we open them fresh here
        # We will open them in append mode inside the loop or keep open? 
        # Keeping open is better for performance.
        f_strings = open(strings_global_path, "w", encoding="utf-8", errors="ignore")
        f_imports = open(imports_global_path, "w", encoding="utf-8", errors="ignore")
        f_exports = open(exports_global_path, "w", encoding="utf-8", errors="ignore")
        f_entry = open(entry_candidates_path, "w", encoding="utf-8", errors="ignore")
        f_label = open(label_evidence_path, "w", encoding="utf-8", errors="ignore")

        try:
            # Iterate over all ELFs in manifest
            if not os.path.exists(self.manifest_path):
                return
            
            # Read manifest to get all elf_ids. 
            # Note: manifest might have duplicates if queued multiple times? 
            # Ideally we iterate by_elf dir, but manifest order is nice.
            # Let's iterate by_elf dir to be sure we get latest state.
            
            processed_ids = set()
            
            for elf_id in os.listdir(self.by_elf_dir):
                if elf_id in processed_ids:
                    continue
                processed_ids.add(elf_id)
                
                elf_dir = os.path.join(self.by_elf_dir, elf_id)
                meta_path = os.path.join(elf_dir, "meta.json")
                if not os.path.exists(meta_path):
                    continue
                
                try:
                    with open(meta_path, "r", encoding="utf-8", errors="ignore") as f:
                        meta = json.load(f)
                except Exception:
                    continue

                # 1. ELF Index CSV
                # Extract checksec info
                checksec_info = meta.get("checksec") or {}
                # Handle cases where checksec is None or dict
                if checksec_info is None:
                    checksec_info = {}
                
                # Check if "checksec" is a dict and has "normalized" key
                if isinstance(checksec_info, dict):
                    cs = checksec_info.get("normalized", {})
                else:
                    cs = {}
                
                # Ensure cs is a dict before calling .get()
                if not isinstance(cs, dict):
                    cs = {}

                # Direct access to normalized values (they are int or str, not dicts)
                nx = str(cs.get("nx", "unknown"))
                canary = str(cs.get("canary", "unknown"))
                relro = str(cs.get("relro", "unknown"))
                pie = str(cs.get("pie", "unknown"))
                
                row = [
                    elf_id,
                    f'"{meta.get("path", "")}"', # Quote path for CSV
                    f'"{meta.get("rel_path", "")}"',
                    meta.get("arch", ""),
                    str(meta.get("bits", "")),
                    meta.get("endian", ""),
                    meta.get("elf_type", ""),
                    str(meta.get("size", 0)),
                    meta.get("status", "unknown"),
                    str(nx),
                    str(canary),
                    str(relro),
                    str(pie),
                ]
                with open(elf_index_path, "a", encoding="utf-8", errors="ignore") as f_elf:
                    f_elf.write(",".join(row) + "\n")

                # Labels Evidence
                labels = set()
                # Label: unsafe
                # Rule: nx=no/disabled AND canary=no/disabled
                is_nx_off = str(nx).lower() in ["no", "disabled", "false", "0"]
                is_canary_off = str(canary).lower() in ["no", "disabled", "false", "0"]
                if is_nx_off and is_canary_off:
                    labels.add("unsafe")
                    f_label.write(json.dumps({
                        "elf_id": elf_id,
                        "label": "unsafe",
                        "reason": "nx=0 and canary=0",
                        "source": "checksec"
                    }, ensure_ascii=False) + "\n")

                # 2. Strings (Global) - limit to interesting ones? Or all?
                # User asked for "strings_global.jsonl". Writing ALL strings from thousands of binaries is huge.
                # But let's assume we want to aggregate them.
                # Optimization: Maybe only write if < 100MB total? Or just write them.
                # Let's stream them.
                strings_txt = os.path.join(elf_dir, "strings.txt")
                if os.path.exists(strings_txt):
                    with open(strings_txt, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if line.startswith("#"): continue
                            parts = line.strip().split(" | ")
                            if len(parts) >= 4:
                                # addr | length | type | content
                                content = parts[3]
                                # Check for labels in strings
                                if "OpenSSL" in content or "SSLeay" in content or "libssl" in content:
                                    if "crypto" not in labels:
                                        labels.add("crypto")
                                        f_label.write(json.dumps({
                                            "elf_id": elf_id,
                                            "label": "crypto",
                                            "reason": f"string match: {content[:50]}",
                                            "source": "strings"
                                        }, ensure_ascii=False) + "\n")
                                
                                # Write to global strings (structure: elf_id, addr, string)
                                f_strings.write(json.dumps({
                                    "elf_id": elf_id,
                                    "addr": parts[0],
                                    "str": content
                                }, ensure_ascii=False) + "\n")

                # 3. Imports (Global)
                imports_txt = os.path.join(elf_dir, "imports.txt")
                if os.path.exists(imports_txt):
                    with open(imports_txt, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if line.startswith("#"): continue
                            if ":" in line:
                                addr, name = line.strip().split(":", 1)
                                # Label: service (bind/listen/accept)
                                if name in ["bind", "listen", "accept", "socket"]:
                                    if "service" not in labels:
                                        labels.add("service")
                                        f_label.write(json.dumps({
                                            "elf_id": elf_id,
                                            "label": "service",
                                            "reason": f"import match: {name}",
                                            "source": "imports"
                                        }, ensure_ascii=False) + "\n")
                                # Label: crypto (SSL_*)
                                if name.startswith("SSL_") or name.startswith("EVP_"):
                                    if "crypto" not in labels:
                                        labels.add("crypto")
                                        f_label.write(json.dumps({
                                            "elf_id": elf_id,
                                            "label": "crypto",
                                            "reason": f"import match: {name}",
                                            "source": "imports"
                                        }, ensure_ascii=False) + "\n")

                                f_imports.write(json.dumps({
                                    "elf_id": elf_id,
                                    "addr": addr,
                                    "func": name
                                }, ensure_ascii=False) + "\n")

                # 4. Exports (Global)
                exports_txt = os.path.join(elf_dir, "exports.txt")
                if os.path.exists(exports_txt):
                    with open(exports_txt, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if line.startswith("#"): continue
                            if ":" in line:
                                addr, name = line.strip().split(":", 1)
                                f_exports.write(json.dumps({
                                    "elf_id": elf_id,
                                    "addr": addr,
                                    "func": name
                                }, ensure_ascii=False) + "\n")

                # 5. Entry Candidates
                func_index = os.path.join(elf_dir, "function_index.jsonl")
                if os.path.exists(func_index):
                    with open(func_index, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            try:
                                obj = json.loads(line)
                                if obj.get("is_entry_candidate"):
                                    obj["elf_id"] = elf_id
                                    f_entry.write(json.dumps(obj, ensure_ascii=False) + "\n")
                            except Exception:
                                pass

        finally:
            f_strings.close()
            f_imports.close()
            f_exports.close()
            f_entry.close()
            f_label.close()

    def run(self) -> Dict[str, Any]:
        self._ensure_layout()
        if self.options.force:
            self._reset_run_artifacts()
        total_files = None
        if self.options.progress:
            total_files = sum(1 for _ in iter_files(self.rootfs_dir))

        def progress_cb(scanned: int, total: Optional[int], found: int) -> None:
            if not self.options.progress:
                return
            if total and total > 0:
                percent = (scanned / total) * 100
                print(
                    f"[rootfs_elf] scan {scanned}/{total} ({percent:.1f}%) | elf={found}",
                    flush=True,
                )
            else:
                print(f"[rootfs_elf] scan {scanned} files | elf={found}", flush=True)

        elf_list = scan_rootfs(
            self.rootfs_dir,
            self.options,
            total_files=total_files,
            progress_cb=progress_cb,
        )
        self.stats["total_elf"] = len(elf_list)

        tasks: List[Tuple[ElfInfo, str]] = []
        queued = 0
        for idx, elf in enumerate(elf_list):
            elf_id = self._queue_task(elf)
            if elf_id:
                tasks.append((elf, elf_id))
                queued += 1
            if self.options.progress and (idx + 1) % 100 == 0:
                print(
                    f"[rootfs_elf] queue {idx + 1}/{len(elf_list)} | new={queued} skipped={idx + 1 - queued}",
                    flush=True,
                )
        if self.options.progress:
            print(
                f"[rootfs_elf] queue done {len(elf_list)} elfs | new={queued} skipped={len(elf_list) - queued}",
                flush=True,
            )

        # On resume, also collect previously pending ELFs that were not re-queued
        if self.options.resume and self.options.run_ida:
            queued_ids = {elf_id for _, elf_id in tasks}
            for elf_id in os.listdir(self.by_elf_dir):
                if elf_id in queued_ids:
                    continue
                meta_path = self._meta_path(elf_id)
                if not os.path.exists(meta_path):
                    continue
                try:
                    with open(meta_path, "r", encoding="utf-8", errors="ignore") as f:
                        meta = json.load(f)
                except Exception:
                    continue
                if meta.get("status") == "pending":
                    elf_info = ElfInfo(
                        path=meta.get("path", ""),
                        rel_path=meta.get("rel_path", ""),
                        size=meta.get("size", 0),
                        sha256=meta.get("sha256", ""),
                        arch=meta.get("arch", ""),
                        bits=meta.get("bits", 0),
                        endian=meta.get("endian", ""),
                        elf_type=meta.get("elf_type", ""),
                    )
                    tasks.append((elf_info, elf_id))
            if self.options.progress:
                print(
                    f"[rootfs_elf] resume: total ida tasks={len(tasks)}",
                    flush=True,
                )

        if tasks and self.options.run_ida:
            worker_count = self.options.workers if self.options.workers > 0 else 1
            total = len(tasks)
            if self.options.progress:
                print(
                    f"[rootfs_elf] ida start total={total} workers={worker_count}",
                    flush=True,
                )
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                futures = [executor.submit(self._run_worker, elf, elf_id) for elf, elf_id in tasks]
                done = set()
                last_heartbeat = time.time()
                heartbeat_interval = 10
                last_reported = 0
                if self.options.progress:
                    print(
                        f"[rootfs_elf] ida running {total - len(done)} | done {len(done)}/{total}",
                        flush=True,
                    )
                while len(done) < total:
                    done_now, _ = wait(
                        futures,
                        timeout=heartbeat_interval,
                        return_when=FIRST_COMPLETED,
                    )
                    if done_now:
                        done.update(done_now)
                        completed = len(done)
                        if self.options.progress:
                            if completed == total or completed - last_reported >= self.options.progress_every:
                                percent = (completed / total) * 100 if total else 100
                                print(
                                    f"[rootfs_elf] ida {completed}/{total} ({percent:.1f}%)",
                                    flush=True,
                                )
                                last_reported = completed
                    if self.options.progress and time.time() - last_heartbeat >= heartbeat_interval:
                        completed = len(done)
                        running = total - completed
                        samples = ""
                        with self._running_lock:
                            if self._running:
                                items = list(self._running.items())[:2]
                                parts = []
                                for _, info in items:
                                    elapsed = int(time.time() - info["start"])
                                    parts.append(f"{os.path.basename(info['path'])}({elapsed}s)")
                                samples = " | " + ", ".join(parts)
                        print(
                            f"[rootfs_elf] ida running {running} | done {completed}/{total}{samples}",
                            flush=True,
                        )
                        last_heartbeat = time.time()

        summary = {
            "rootfs": self.rootfs_dir,
            "out_dir": self.out_dir,
            "stats": self.stats,
            "timestamp": int(time.time()),
        }
        write_json(self.summary_path, summary)

        self._generate_global_indexes()
        return summary

    def _resolve_ida_dirs(self) -> tuple[Optional[str], Optional[str]]:
        env_ida = ensure_ida_env()
        if env_ida and os.path.isdir(env_ida):
            lib_dir = self._find_ida_libdir(env_ida)
            return env_ida, lib_dir

        home_dir = os.path.expanduser("~")
        try:
            for name in sorted(os.listdir(home_dir), reverse=True):
                if not name.startswith("ida-pro-"):
                    continue
                path = os.path.join(home_dir, name)
                if not os.path.isdir(path):
                    continue
                lib_dir = self._find_ida_libdir(path)
                if lib_dir:
                    return path, lib_dir
        except OSError:
            pass

        candidate = os.path.join(self.tools_path, "ida")
        if os.path.isdir(candidate):
            lib_dir = self._find_ida_libdir(candidate)
            return candidate, lib_dir

        # fall back: search tools/ida* for libidalib.so
        for name in os.listdir(self.tools_path):
            if not name.startswith("ida"):
                continue
            path = os.path.join(self.tools_path, name)
            if not os.path.isdir(path):
                continue
            lib_dir = self._find_ida_libdir(path)
            if lib_dir:
                return path, lib_dir

        return None, None

    @staticmethod
    def _find_ida_libdir(ida_root: str) -> Optional[str]:
        for base, _, files in os.walk(ida_root):
            if "libidalib.so" in files:
                return base
        return None
