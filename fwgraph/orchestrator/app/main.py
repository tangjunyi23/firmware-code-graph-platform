"""FastAPI orchestrator for the fwgraph unpack + decompile subsystems.

Endpoints:
  POST /firmware                  upload firmware (multipart), start extraction
  POST /jobs/{job_id}/decompile   (re)run headless IDA decompilation (M2)
  POST /jobs/{job_id}/graph       build the CBM code graph (M4)
  GET  /jobs/{job_id}/graph       M4 graph_done.json summary
  POST /jobs/{job_id}/trace       M7 qemu-user differential coverage trace
  GET  /jobs/{job_id}/traces      M7 trace list (summaries)
  GET  /jobs/{job_id}/traces/{trace_id}  M7 full trace.json
  POST /graph/query               graph检索 entry point for the vuln-hunting AI:
                                  {job_id, op: search|cypher|trace|snippet|
                                   dangerous|trace_flow, ...}
  GET  /jobs                      list jobs (newest first; non-admin: own only)
  GET  /jobs/{job_id}             job status + log tail + manifest summary
  DELETE /jobs/{job_id}           remove a job and all its artifacts (owner/admin)
  GET  /jobs/{job_id}/manifest    full manifest.json
  GET  /jobs/{job_id}/functions   flattened symbols.json for the web UI (M5)
  GET  /jobs/{job_id}/functions/{md5}/{addr}/source  pseudo-C of one function
  GET  /cbmui/*                   reverse proxy to the CBM web UI (M5, see webui.py)
  GET  /healthz                   liveness (no auth)

Job state is persisted to data/firmware/<job_id>/job.json so history survives
restarts. Extraction artifacts live in data/extracted/<job_id>/ (EMBA log dir)
plus data/extracted/<job_id>.emba.log (EMBA stdout/stderr). Decompilation
artifacts live in data/idb/<job_id>/ and data/pseudocode/<job_id>/.
Graph artifacts live in data/cbm/<job_id>/ (CBM-friendly tree + git repo +
graph_done.json); the CBM index DB is ~/.cache/codebase-memory-mcp/.

Status machine: pending -> decrypting -> extracting -> parsing -> done ->
decompiling -> decompiled -> graphing -> graphed (upload always fingerprints
and unwraps vendor containers first; decompiling starts automatically after
extraction unless AUTO_DECOMPILE=0; auto jobs continue decompiled -> graph
which chains attack/routes/surfaces; any failure ends in "failed").
"""

import hashlib
import json
import logging
import os
import re
import shutil
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import Body, Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import httpx

from . import accounts, admin_api, config, decompiler, extractor, protofuzz_api, vulnagent_api, vulnlib_api, webui
from pipeline import backdoor as backdoor_scan
from pipeline import evidence as ev
from pipeline import sca as sca_scan
from pipeline import vulnlib as vulnlib_store
from pipeline import profiles as analysis_profiles
from pipeline import report
from pipeline.attack import runner as attack_runner
from pipeline.graph import ingest as graph_ingest
from pipeline.graph import query as graph_query
from pipeline.fuzz import runner as fuzz_runner
from pipeline.graphext import runner as graphext_runner
from pipeline.inputs import runner as inputs_runner
from pipeline.frida import runner as frida_runner
from pipeline.surfaces import runner as surfaces_runner
from pipeline.routes import runner as route_runner
from pipeline import fwdecrypt, protocol_reverse
from pipeline.extract import px4 as px4_extractor
from pipeline.extract import moria as moria_scan
from pipeline.backdoor import find_rootfs
from pipeline.trace import qemu_exec, tracer

# 路径推导集中在 orchestrator.app.config（fwgraph/orchestrator/app/ -> fwgraph/）
FWGRAPH_ROOT = config.FWGRAPH_ROOT
load_dotenv(FWGRAPH_ROOT / ".env")

DATA_DIR = config.data_dir()
FIRMWARE_DIR = DATA_DIR / "firmware"
EXTRACTED_DIR = DATA_DIR / "extracted"
PSEUDOCODE_DIR = DATA_DIR / "pseudocode"
CBM_DIR = DATA_DIR / "cbm"
TRACES_DIR = DATA_DIR / "traces"
ATTACK_DIR = DATA_DIR / "attack"
ROUTES_DIR = DATA_DIR / "routes"
INPUTS_DIR = DATA_DIR / "inputs"
FUZZ_DIR = DATA_DIR / "fuzz"
EXEC_DIR = DATA_DIR / "qemu_exec"
FRIDA_DIR = DATA_DIR / "frida"
GRAPHEXT_DIR = DATA_DIR / "graphext"
SURFACES_DIR = DATA_DIR / "surfaces"
DECRYPT_DIR = DATA_DIR / "decrypt"

STATUS_RUNNING = {"pending", "decrypting", "extracting", "parsing", "decompiling",
                  "ailifting", "graphing", "attacking", "routing",
                  "identifying", "surfacing"}
LOG_TAIL_LINES = 30

app = FastAPI(title="fwgraph orchestrator", version="0.1.0")


@app.middleware("http")
async def security_headers(request, call_next):
    """Baseline hardening headers on every response (S2).

    setdefault() so proxied upstream headers (the /cbmui proxy forwards the
    CBM UI's own headers) always win. No global CSP on purpose: the SPA
    embeds /cbmui in an iframe, and a frame-ancestors/CSP here would break
    that embedding — the proxy rewrites the upstream CSP itself instead
    (webui._rewrite_csp).
    """
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp

_security = HTTPBearer(auto_error=False)
_jobs: dict = {}
_jobs_lock = threading.Lock()


def require_token(cred: HTTPAuthorizationCredentials | None = Depends(_security)):
    """Resolve the bearer credential to a principal dict.

    Empty ORCH_TOKEN keeps the historical dev/test behavior (auth disabled,
    anon admin). A Bearer equal to ORCH_TOKEN is the legacy token admin.
    Anything else is looked up in the accounts session table.
    """
    token = os.getenv("ORCH_TOKEN", "")
    if not token:
        return {"username": "anon", "role": "admin", "legacy": True}
    if cred is not None and cred.credentials == token:
        return {"username": "token-admin", "role": "admin", "legacy": True}
    if cred is not None:
        session = accounts.resolve_session(cred.credentials)
        if session is not None:
            return {"username": session["username"], "role": session["role"],
                    "legacy": False, "token": cred.credentials}
    raise HTTPException(status_code=401, detail="invalid or missing bearer token")


def require_admin(principal: dict = Depends(require_token)):
    """require_token plus an admin role gate (403 for plain users)."""
    if principal.get("role") != "admin":
        raise HTTPException(status_code=403, detail="admin role required")
    return principal


def _can_access(principal: dict, owner) -> bool:
    """Owner check per the accounts.can_access contract: admin, matching
    owner, or a legacy owner-less job. Falls back to a local copy until the
    accounts side lands the function (concurrent rollout)."""
    fn = getattr(accounts, "can_access", None)
    if fn is not None:
        return bool(fn(principal, owner))
    if principal.get("role") == "admin":
        return True
    if not owner:
        return True
    return principal.get("username") == owner


def _check_quota(job_id: str, kind: str):
    """accounts.check_quota contract (raises 429 when the job exceeds its
    per-kind quota); a no-op until the accounts side lands it."""
    fn = getattr(accounts, "check_quota", None)
    if fn is not None:
        fn(job_id, kind)


def job_guard(request: Request, principal: dict = Depends(require_token)):
    """Access gate mounted on every /jobs/{job_id}/... endpoint (S3).

    Unknown jobs and jobs owned by someone else both answer 404 — the
    existence of another user's job is never leaked."""
    job_id = request.path_params.get("job_id", "")
    job = _jobs.get(job_id)
    if job is None or not _can_access(principal, job.get("owner")):
        raise HTTPException(status_code=404, detail="job not found")
    return job


class _TokenRedactFilter(logging.Filter):
    """uvicorn.access logs the raw request line, query string included; a
    ?token= credential would otherwise land in data/orchestrator.log (S1)."""
    _pattern = re.compile(r"([?&]token=)[^&\s\"']+")

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001 - never break logging
            return True
        if "token=" in msg:
            record.msg = self._pattern.sub(r"\1***", msg)
            record.args = ()
        return True


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _job_path(job_id: str) -> Path:
    return FIRMWARE_DIR / job_id / "job.json"


def _save_job(job: dict):
    """Persist job.json atomically (tmp + rename, like accounts._write_json).
    A full disk must not crash the request path: OSError (e.g. ENOSPC) is
    logged to the orchestrator log instead of being re-raised (M9)."""
    job["updated_at"] = _now()
    path = _job_path(job["job_id"])
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(job, indent=2, ensure_ascii=False),
                       encoding="utf-8")
        os.replace(tmp, path)
    except OSError as exc:
        print(f"[orchestrator] job {job.get('job_id')} persist failed: "
              f"{type(exc).__name__}: {exc}", flush=True)


def _set_status(job: dict, status: str, error: str | None = None):
    with _jobs_lock:
        if status == "failed":
            # 记录失败时正在运行的阶段，供前端定位失败步骤与重试
            job["failed_from"] = job.get("status")
        job["status"] = status
        job["error"] = error
        _save_job(job)


def _load_jobs():
    """Load persisted jobs; anything left running by a previous instance is
    marked failed (EMBA itself is gone after a restart). Jobs persisted
    before per-user ownership get owner "admin" backfilled (S3); both fixes
    are written back to disk once here."""
    if not FIRMWARE_DIR.is_dir():
        return
    for job_file in sorted(FIRMWARE_DIR.glob("*/job.json")):
        try:
            job = json.loads(job_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        dirty = False
        if job.get("status") in STATUS_RUNNING:
            job["status"] = "failed"
            job["error"] = "interrupted by service restart"
            dirty = True
        if not job.get("owner"):
            job["owner"] = "admin"
            dirty = True
        if dirty:
            _save_job(job)
        _jobs[job["job_id"]] = job


def _log_tail(job_id: str) -> list:
    log_file = EXTRACTED_DIR / f"{job_id}.emba.log"
    if not log_file.is_file():
        return []
    with open(log_file, "rb") as fh:
        fh.seek(0, 2)
        size = fh.tell()
        fh.seek(max(0, size - 65536))
        lines = fh.read().decode("utf-8", errors="replace").splitlines()
    return lines[-LOG_TAIL_LINES:]


def _resolve_job_md5(job_id: str, raw: str) -> str:
    """Accept a full md5 or a unique prefix from the job manifest."""
    md5 = str(raw or "").strip().lower()
    manifest_file = EXTRACTED_DIR / job_id / "manifest.json"
    if not manifest_file.is_file():
        raise HTTPException(status_code=409,
                            detail="extraction not complete (no manifest.json)")
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=409, detail="manifest unreadable") from exc
    bins = [str(b.get("md5") or "").lower()
            for b in (manifest.get("binaries") or []) if b.get("md5")]
    if re.fullmatch(r"[0-9a-f]{32}", md5):
        if md5 not in bins:
            raise HTTPException(status_code=404,
                                detail=f"binary {md5} not in manifest")
        return md5
    if re.fullmatch(r"[0-9a-f]{8,31}", md5):
        hits = [item for item in bins if item.startswith(md5)]
        if len(hits) == 1:
            return hits[0]
        if not hits:
            raise HTTPException(status_code=404,
                                detail=f"binary {md5} not in manifest")
        raise HTTPException(
            status_code=400,
            detail=f"ambiguous md5 prefix {md5}: {', '.join(hits[:6])}")
    raise HTTPException(status_code=400,
                        detail="binary_md5 must be a 32-char lowercase md5")


def _manifest_summary(job_id: str):
    manifest_file = EXTRACTED_DIR / job_id / "manifest.json"
    if not manifest_file.is_file():
        return None
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    stats = dict(manifest.get("stats") or {})
    packed = sum(1 for b in manifest.get("binaries") or []
                 if b.get("packed"))
    if packed:
        stats["packed_binaries"] = packed
    return stats


# M6 concurrency gates: every decompile job spawns IDA_WORKERS idat
# processes, so N uncapped jobs meant 3N IDAs fighting over the box. The
# semaphores are created lazily so admin_api.apply_settings() (startup) and
# tests can still override the limits via env.
_sem_init_lock = threading.Lock()
_decompile_sem: threading.Semaphore | None = None


def _decompile_semaphore() -> threading.Semaphore:
    global _decompile_sem
    with _sem_init_lock:
        if _decompile_sem is None:
            _decompile_sem = threading.Semaphore(
                int(os.getenv("DECOMPILE_MAX_JOBS", "2")))
        return _decompile_sem


def _decompile_worker(job_id: str, only_md5s=None):
    job = _jobs[job_id]
    # gate acquired at worker entry; released before the auto chain so a
    # chained graph does not occupy a decompile slot
    with _decompile_semaphore():
        try:
            _set_status(job, "decompiling")
            summary = decompiler.run_job(job_id, DATA_DIR, only_md5s=only_md5s)
            if summary.get("total_binaries", 0) == 0:
                _set_status(job, "failed",
                             extractor.empty_firmware_message(
                                 EXTRACTED_DIR / job_id))
            elif summary["succeeded"] > 0:
                _set_status(job, "decompiled")
            else:
                nfail = summary.get("failed") or 0
                _set_status(job, "failed",
                             f"反编译全部失败（{nfail} 个二进制，"
                             "详见 decompile_summary.json）")
        except Exception as exc:  # noqa: BLE001 - any failure must end as 'failed'
            _set_status(job, "failed", f"decompile: {type(exc).__name__}: {exc}")
    # one-shot auto chain (AUTO_FULL=1 or per-job auto): continue graph in
    # this thread; graph chains attack/routes/surfaces.
    if job.get("status") == "decompiled" \
            and (job.get("auto") or os.getenv("AUTO_FULL", "0") == "1"):
        _graph_worker(job_id)


def _graph_worker(job_id: str):
    job = _jobs[job_id]
    try:
        _set_status(job, "graphing")
        graph_ingest.run_job(job_id, DATA_DIR)
        # CFG before attack so path BFS can union address-level call edges.
        spec = analysis_profiles.spec(job.get("profile"))
        if spec.get("graphext") and os.getenv("AUTO_GRAPHEXT", "1") != "0":
            try:
                graphext_runner.run_job(job_id, DATA_DIR)
            except Exception:  # noqa: BLE001 - graphext is best-effort
                pass
        final_status = "graphed"
        if os.getenv("AUTO_ATTACK", "1") != "0":
            _set_status(job, "attacking")
            attack_runner.run_job(job_id, DATA_DIR)
            final_status = "attacked"
        if os.getenv("AUTO_ROUTES", "1") != "0":
            _set_status(job, "routing")
            route_runner.run_job(job_id, DATA_DIR)
            final_status = "routed"
        _set_status(job, final_status)
    except Exception as exc:  # noqa: BLE001 - any failure must end as 'failed'
        _set_status(job, "failed", f"graph: {type(exc).__name__}: {exc}")
    else:
        # M6b: per-input surface export needs graph/attack/routes artifacts;
        # run it after the chain settles (never flips the job to failed)
        if os.getenv("AUTO_SURFACES", "1") != "0":
            try:
                surfaces_runner.run_job(job_id, DATA_DIR)
            except Exception:  # noqa: BLE001 - surfaces are best-effort
                pass
        # auto jobs: deterministic综合报告 (best-effort, never fails the job)
        if job.get("auto"):
            try:
                report.generate_job_report(job_id, DATA_DIR)
            except Exception:  # noqa: BLE001 - report is best-effort
                pass


def _attack_worker(job_id: str):
    job = _jobs[job_id]
    try:
        _set_status(job, "attacking")
        attack_runner.run_job(job_id, DATA_DIR)
        _set_status(job, "attacked")
    except Exception as exc:  # noqa: BLE001 - persist every worker failure
        _set_status(job, "failed", f"attack: {type(exc).__name__}: {exc}")


def _route_worker(job_id: str):
    job = _jobs[job_id]
    try:
        _set_status(job, "routing")
        route_runner.run_job(job_id, DATA_DIR)
        _set_status(job, "routed")
    except Exception as exc:  # noqa: BLE001 - persist every worker failure
        _set_status(job, "failed", f"routes: {type(exc).__name__}: {exc}")


def _inputs_worker(job_id: str):
    job = _jobs[job_id]
    try:
        _set_status(job, "identifying")
        inputs_runner.run_job(job_id, DATA_DIR)
        _set_status(job, "done")
    except Exception as exc:  # noqa: BLE001 - persist every worker failure
        _set_status(job, "failed", f"inputs: {type(exc).__name__}: {exc}")


def _surfaces_worker(job_id: str):
    job = _jobs[job_id]
    try:
        _set_status(job, "surfacing")
        surfaces_runner.run_job(job_id, DATA_DIR)
        _set_status(job, "surfaced")
    except Exception as exc:  # noqa: BLE001 - persist every worker failure
        _set_status(job, "failed", f"surfaces: {type(exc).__name__}: {exc}")


def _should_mark_unpack_done(job: dict) -> bool:
    """True when unpack is the last automatic step (no decompile chain)."""
    if job.get("auto"):
        return False
    return os.getenv("AUTO_DECOMPILE", "1") == "0"


def _moria_tree(log_dir) -> dict | None:
    try:
        return json.loads((Path(log_dir) / "moria-tree.json")
                          .read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _save_moria_tree(log_dir, tree) -> None:
    """落盘 moria 结构树；必须在提取器返回后调用。

    EMBA 启动时会清空 log_dir（"Delete content of log directory"），
    提前写入的文件会被删掉，故 identify 的结果先留在内存。
    """
    if not tree:
        return
    try:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        (Path(log_dir) / "moria-tree.json").write_text(
            json.dumps(tree, ensure_ascii=False, indent=1),
            encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        print(f"[orchestrator] moria tree save failed: {exc}", flush=True)

def _extract_ubifs_residuals(job_id: str, log_dir) -> int:
    """binwalk 切出但未解包的 UBIFS 镜像（*_ubifs.raw）→ ubireader 解包
    并入主 rootfs（2026-09-23：R15A1 模拟实测，/var/config 的 csman 配置
    库 pre4/pre7/reset.dat 全在未解包 UBIFS 里——httpd/csmanttp HNAP 分发
    在缺 mib 时 501/Bus error，模拟链路断在数据缺失而非代码）。
    主 rootfs 已有的文件不覆盖（squashfs 优先，UBIFS 是增量配置/数据）。
    """
    import shutil as _sh
    import subprocess as _sp
    log_dir = Path(log_dir)
    ubir = _sh.which("ubireader_extract_files")
    if not ubir:
        venv_ubir = Path(__file__).resolve().parents[2] / ".venv" / "bin" \
            / "ubireader_extract_files"
        ubir = str(venv_ubir) if venv_ubir.is_file() else None
    if not ubir:
        print("[orchestrator] ubifs residuals: ubi_reader 未安装，跳过",
              flush=True)
        return 0
    rootfs = find_rootfs(log_dir)
    if not rootfs:
        return 0
    merged = 0
    for raw in log_dir.rglob("*_ubifs.raw"):
        try:
            if raw.stat().st_size < 256 * 1024:
                continue
        except OSError:
            continue
        out = log_dir / "ubifs-residual" / raw.stem
        if not (out / ".done").is_file():
            try:
                _sp.run([ubir, "-k", "-o", str(out), str(raw)],
                        capture_output=True, timeout=600)
                (out / ".done").write_text("", encoding="utf-8")
            except Exception as exc:  # noqa: BLE001
                print(f"[orchestrator] ubifs residual {raw.name} 解包失败:"
                      f" {exc}", flush=True)
                continue
        for src in out.rglob("*"):
            if not src.is_file() or src.name == ".done":
                continue
            rel = src.relative_to(out)
            dst = Path(rootfs) / rel
            if dst.exists():
                continue
            try:
                dst.parent.mkdir(parents=True, exist_ok=True)
                _sh.copy2(src, dst)
                merged += 1
            except OSError:
                continue
    if merged:
        print(f"[orchestrator] ubifs residuals: {merged} 个文件并入主 "
              f"rootfs（配置/数据分区）", flush=True)
    return merged


def _moria_degraded_manifest(job_id: str, job: dict, log_dir) -> dict:
    """降级模式：moria 产物直接构建 manifest（无 EMBA p99 CSV）。"""
    out_dir = Path(log_dir) / "moria_extracted"
    from pipeline.extract.checksec import checksec
    binaries = []
    for p in sorted(out_dir.rglob("*")) if out_dir.is_dir() else []:
        if not p.is_file() or p.is_symlink():
            continue
        with open(p, "rb") as fh:
            if fh.read(4) != b"\x7fELF":
                continue
        rec = moria_scan._binrec(p, out_dir)
        if rec:
            binaries.append(rec)
    manifest = {
        "firmware": job.get("firmware") or "",
        "job_id": job_id,
        "unpack_mode": "moria-degraded",
        "binaries": binaries,
        "stats": {"total_binaries": len(binaries),
                  "extracted_files": sum(
                      len(f) for _, _, f in os.walk(out_dir)),
                  "by_arch": {}},
    }
    (Path(log_dir) / "manifest.json").write_text(
        json.dumps(manifest, indent=1), encoding="utf-8")
    return manifest


def _extract_worker(job_id: str):
    job = _jobs[job_id]
    fw_path = FIRMWARE_DIR / job_id / "firmware.bin"
    log_dir = EXTRACTED_DIR / job_id
    emba_log = EXTRACTED_DIR / f"{job_id}.emba.log"
    try:
        _set_status(job, "decrypting")
        decrypt_dir = DATA_DIR / "decrypt" / job_id
        try:
            report = fwdecrypt.run_job(
                job_id, job.get("firmware") or "", fw_path, decrypt_dir)
            out = report.get("output")
            if out and Path(out).is_file():
                fw_path = Path(out)
        except Exception:  # noqa: BLE001 - decrypt must not abort extract
            pass
        # moria 结构快诊（纯识别，秒级）：加密/炸弹结构在这里提前暴露；
        # 结果暂存内存，提取器返回后再落盘（EMBA 启动会清空 log_dir）。
        moria_tree = None
        if moria_scan.enabled():
            try:
                moria_tree = moria_scan.identify(fw_path)
            except Exception as exc:  # noqa: BLE001
                print(f"[orchestrator] moria quick-scan failed: {exc}",
                      flush=True)
        _set_status(job, "extracting")
        if px4_extractor.looks_like_px4(fw_path, job["firmware"]):
            _set_status(job, "parsing")
            px4_extractor.extract_px4(job_id, job["firmware"], fw_path, log_dir)
            emba_log.write_text(
                "[extractor] PX4FWv1 container decoded with a linker-verified "
                "raw-image profile\n",
                encoding="utf-8",
            )
        else:
            rc, timed_out = extractor.run_emba(fw_path, log_dir, emba_log)
            _save_moria_tree(log_dir, moria_tree)
            rescued = False
            if (timed_out or rc != 0) and moria_scan.enabled():
                # EMBA 失败/超时 → moria 全量降级解包（degraded_unpack）
                try:
                    tree = _moria_tree(log_dir)
                    rr = moria_scan.rescue_extract(fw_path, log_dir, tree)
                    if rr["done"] and rr["binaries"]:
                        rescued = True
                        job["unpack_mode"] = "moria-degraded"
                        print(f"[orchestrator] moria 降级解包："
                              f"{len(rr['binaries'])} 个二进制", flush=True)
                except Exception as exc:  # noqa: BLE001
                    print(f"[orchestrator] moria rescue failed: {exc}",
                          flush=True)
            if timed_out and not rescued:
                _set_status(job, "failed", f"EMBA timeout after {extractor._cfg('EMBA_TIMEOUT', '7200')}s")
                return
            if rc != 0 and not rescued:
                _set_status(job, "failed", f"EMBA exited with code {rc} (see {emba_log.name})")
                return
            _set_status(job, "parsing")
            if rescued:
                _moria_degraded_manifest(job_id, job, log_dir)
            else:
                extractor.build_manifest(job_id, job["firmware"], log_dir)
            # moria 目录扫描：UPX 加壳 ELF 打 packed 标记（反编译盲区显式化）
            # + 对账补刀：快诊树里有文件系统结构、EMBA 却没解出产物时定点提取
            if moria_scan.enabled():
                try:
                    rootfs = find_rootfs(log_dir)
                    if rootfs:
                        marked = moria_scan.annotate_manifest(
                            log_dir / "manifest.json", Path(rootfs))
                        if marked:
                            print(f"[orchestrator] moria: {marked} 个加壳"
                                  f"二进制已标记 packed", flush=True)
                    uncovered = moria_scan.fs_findings_uncovered(
                        _moria_tree(log_dir), log_dir)
                    if uncovered:
                        rr = moria_scan.rescue_extract(fw_path, log_dir)
                        if rr["done"]:
                            added = moria_scan.merge_into_manifest(
                                log_dir / "manifest.json", rr["binaries"])
                            if added:
                                print(f"[orchestrator] moria 对账补刀："
                                      f"{added} 个二进制并入", flush=True)
                except Exception as exc:  # noqa: BLE001
                    print(f"[orchestrator] moria post-scan failed: {exc}",
                          flush=True)
        # UBIFS 残留分区（/var 配置数据）并入主 rootfs——mib/NVRAM 数据源，
        # 模拟环境 csman/httpd 依赖（2026-09-23 R15A1 HNAP 链修复）
        try:
            _extract_ubifs_residuals(job_id, log_dir)
        except Exception as exc:  # noqa: BLE001
            print(f"[orchestrator] ubifs residual pass failed: {exc}",
                  flush=True)
        manifest_file = log_dir / "manifest.json"
        binaries = []
        if manifest_file.is_file():
            try:
                binaries = (json.loads(manifest_file.read_text(encoding="utf-8"))
                            .get("binaries") or [])
            except (OSError, json.JSONDecodeError):
                binaries = []
        if not binaries:
            _set_status(job, "failed", extractor.empty_firmware_message(log_dir))
            return
        # Auto-chain continues into inputs/decompile. "done" here would let
        # the homepage poller treat unpack as the whole pipeline.
        if _should_mark_unpack_done(job):
            _set_status(job, "done")
    except Exception as exc:  # noqa: BLE001 - any failure must end as 'failed'
        _set_status(job, "failed", f"{type(exc).__name__}: {exc}")
        return
    # M6a: external-input identification right after extraction
    # (best-effort — never flips the job to failed)
    if os.getenv("AUTO_INPUTS", "1") != "0":
        try:
            inputs_runner.run_job(job_id, DATA_DIR)
        except Exception:  # noqa: BLE001
            pass
    # SCA（Trivy 0.74.0）：解包完成即自动扫描（best-effort——缺 trivy/失败
    # 都不影响主链，结果落 data/sca/<job>.json，漏洞库页查看）
    if os.getenv("AUTO_SCA", "1") != "0":
        try:
            _bin, _sca_err = sca_scan.check_trivy()
            if not _sca_err:
                _start_analysis("sca", job_id, sca_scan.scan_sca,
                                job.get("owner") or "admin")
            else:
                print(f"[orchestrator] AUTO_SCA skipped for {job_id}: "
                      f"{_sca_err}", flush=True)
        except Exception:  # noqa: BLE001
            pass
    if os.getenv("AUTO_DECOMPILE", "1") != "0":
        only_md5s = None
        if job.get("auto"):
            only_md5s = analysis_profiles.select_decompile_targets(
                job_id, DATA_DIR, job.get("profile"))
        _decompile_worker(job_id, only_md5s)


@app.on_event("startup")
def startup():
    FIRMWARE_DIR.mkdir(parents=True, exist_ok=True)
    EXTRACTED_DIR.mkdir(parents=True, exist_ok=True)
    admin_api.apply_settings()  # data/settings.json overrides .env/env
    accounts.ensure_initial_admin()
    _load_jobs()
    # S1: keep ?token= credentials out of data/orchestrator.log
    logging.getLogger("uvicorn.access").addFilter(_TokenRedactFilter())


@app.get("/healthz")
def healthz():
    return {"status": "ok", "jobs": len(_jobs)}


# M5: uploads are streamed with a hard byte cap (default 2 GiB, env
# MAX_FIRMWARE_BYTES) and refused up front when the disk cannot hold the
# file plus 10 GiB of headroom (extraction multiplies the footprint).
MIN_FREE_BYTES = 10 * 1024**3


def _max_firmware_bytes() -> int:
    return int(os.getenv("MAX_FIRMWARE_BYTES", str(2 * 1024**3)))


def _disk_free_bytes(path) -> int:
    return shutil.disk_usage(path).free


@app.get("/analysis-profiles")
def list_analysis_profiles(principal: dict = Depends(require_token)):
    """Homepage gears: low / high / xhigh. Auth required, no side effects."""
    return {"default": analysis_profiles.DEFAULT,
            "profiles": analysis_profiles.public_list()}


@app.post("/firmware", status_code=201)
def upload_firmware(request: Request, file: UploadFile = File(...),
                    auto: bool = False, profile: str = analysis_profiles.DEFAULT,
                    task: str = Form(""),
                    principal: dict = Depends(require_token)):
    max_bytes = _max_firmware_bytes()
    # Pre-flight checks need the advertised size; chunked multipart may omit
    # Content-Length, in which case only the streaming cap below applies.
    length = request.headers.get("content-length")
    if length and length.isdigit():
        if int(length) > max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"固件大小超过上限（{max_bytes // 1024**3}GB）")
        free = _disk_free_bytes(DATA_DIR)
        if free < int(length) + MIN_FREE_BYTES:
            raise HTTPException(
                status_code=507,
                detail=f"磁盘剩余空间不足：仅剩 {free // 1024**3}GB，"
                       "上传需预留文件本身外加 10GB 余量")
    try:
        spec = analysis_profiles.spec(profile)
    except analysis_profiles.UnknownProfile as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    job_id = uuid.uuid4().hex[:12]
    job_dir = FIRMWARE_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    fw_path = job_dir / "firmware.bin"
    written = 0
    try:
        with open(fw_path, "wb") as fh:
            while True:
                chunk = file.file.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=f"固件大小超过上限（{max_bytes // 1024**3}GB）")
                fh.write(chunk)
    except BaseException:
        shutil.rmtree(job_dir, ignore_errors=True)  # never keep partial uploads
        raise

    job = {
        "job_id": job_id,
        "firmware": file.filename or "firmware.bin",
        "status": "pending",
        "error": None,
        "auto": auto,
        "profile": spec["id"],
        "owner": principal.get("username") or "admin",
        "created_at": _now(),
        "updated_at": _now(),
        "firmware_path": str(fw_path),
        "log_dir": str(EXTRACTED_DIR / job_id),
        "size_bytes": fw_path.stat().st_size,
        "task": (task or "").strip()[:4000],
    }
    with _jobs_lock:
        _jobs[job_id] = job
        _save_job(job)
    accounts.audit(principal["username"], "firmware_upload",
                   f"{job_id} {job['firmware']} auto={auto} "
                   f"profile={spec['id']}")
    threading.Thread(target=_extract_worker, args=(job_id,), daemon=True).start()
    return {"job_id": job_id, "status": "pending", "profile": spec["id"]}


@app.post("/jobs/{job_id}/decompile", status_code=202, dependencies=[Depends(require_token), Depends(job_guard)])
def trigger_decompile(job_id: str, body: dict | None = Body(None)):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    only_md5s = None
    if body:
        raw = body.get("binary_md5s")
        if raw is not None:
            if (not isinstance(raw, list) or not raw
                    or not all(isinstance(m, str) for m in raw)):
                raise HTTPException(
                    status_code=400,
                    detail="binary_md5s must be a non-empty list of md5 strings")
            only_md5s = set(raw)
    with _jobs_lock:
        if job["status"] in STATUS_RUNNING:
            raise HTTPException(status_code=409,
                                detail=f"job is {job['status']}, wait for it to finish")
        manifest_path = EXTRACTED_DIR / job_id / "manifest.json"
        if not manifest_path.is_file():
            raise HTTPException(status_code=409,
                                detail="extraction not complete (no manifest.json)")
        if only_md5s is not None:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            known = {b["md5"] for b in manifest.get("binaries", [])}
            unknown = sorted(only_md5s - known)
            if unknown:
                raise HTTPException(
                    status_code=400,
                    detail=f"binary_md5s not in manifest: {', '.join(unknown)}")
        job["status"] = "decompiling"
        job["error"] = None
        _save_job(job)
    threading.Thread(target=_decompile_worker, args=(job_id, only_md5s),
                     daemon=True).start()
    return {"job_id": job_id, "status": "decompiling",
            "only_md5s": sorted(only_md5s) if only_md5s is not None else None}


@app.post("/jobs/{job_id}/graph", status_code=202, dependencies=[Depends(require_token), Depends(job_guard)])
def trigger_graph(job_id: str):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    with _jobs_lock:
        if job["status"] in STATUS_RUNNING:
            raise HTTPException(status_code=409,
                                detail=f"job is {job['status']}, wait for it to finish")
        if not (PSEUDOCODE_DIR / job_id / "symbols.json").is_file():
            raise HTTPException(status_code=409,
                                detail="job not decompiled yet (no symbols.json)")
        job["status"] = "graphing"
        job["error"] = None
        _save_job(job)
    threading.Thread(target=_graph_worker, args=(job_id,), daemon=True).start()
    return {"job_id": job_id, "status": "graphing"}


@app.get("/jobs/{job_id}/graph", dependencies=[Depends(require_token), Depends(job_guard)])
def get_graph(job_id: str):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    done_file = CBM_DIR / job_id / "graph_done.json"
    if not done_file.is_file() and job["status"] != "graphing":
        raise HTTPException(status_code=404, detail="graph not built yet")
    out = {"job_id": job_id, "status": job["status"], "error": job["error"],
           "project": graph_ingest.project_name(job_id)}
    if done_file.is_file():
        out["summary"] = json.loads(done_file.read_text(encoding="utf-8"))
    return out


@app.get("/jobs/{job_id}/graph/layout", dependencies=[Depends(require_token), Depends(job_guard)])
def get_graph_layout(job_id: str):
    """Node/edge layout for the SPA's own graph canvas (M5 native graph view).

    Served by the orchestrator so the frontend never talks to the CBM daemon
    directly; only the fields the canvas needs are passed through.
    """
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    project = graph_ingest.project_name(job_id)
    if not graph_ingest.db_path(project).is_file():
        raise HTTPException(status_code=409, detail="job not graphed yet")
    try:
        resp = httpx.get(f"{webui.CBM_UI_URL}/api/layout",
                         params={"project": project}, timeout=60.0)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502,
                            detail=f"layout upstream unreachable: {exc}") from exc
    if resp.status_code != 200:
        raise HTTPException(status_code=502,
                            detail=f"layout upstream returned {resp.status_code}")
    data = resp.json()
    return {"job_id": job_id,
            "total_nodes": data.get("total_nodes", 0),
            "nodes": data.get("nodes", []),
            "edges": data.get("edges", [])}


@app.post("/jobs/{job_id}/attack", status_code=202,
          dependencies=[Depends(require_token), Depends(job_guard)])
def trigger_attack(job_id: str):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    with _jobs_lock:
        if job["status"] in STATUS_RUNNING:
            raise HTTPException(
                status_code=409,
                detail=f"job is {job['status']}, wait for it to finish")
        if not (CBM_DIR / job_id / "graph_done.json").is_file():
            raise HTTPException(status_code=409, detail="job not graphed yet")
        job["status"] = "attacking"
        job["error"] = None
        _save_job(job)
    threading.Thread(target=_attack_worker, args=(job_id,), daemon=True).start()
    return {"job_id": job_id, "status": "attacking"}


@app.get("/jobs/{job_id}/attack", dependencies=[Depends(require_token), Depends(job_guard)])
def get_attack(job_id: str):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    done_file = ATTACK_DIR / job_id / "attack_done.json"
    if not done_file.is_file() and job["status"] != "attacking":
        raise HTTPException(status_code=404, detail="attack analysis not run yet")
    out = {"job_id": job_id, "status": job["status"],
           "error": job["error"]}
    if done_file.is_file():
        out["summary"] = json.loads(done_file.read_text(encoding="utf-8"))
    return out


def _attack_ai_worker(job_id: str):
    from pipeline.attack import ai_review as _ai_review
    try:
        _ai_review.review_artifact(job_id, DATA_DIR)
    except Exception:  # noqa: BLE001 - overlay is best-effort
        pass


@app.post("/jobs/{job_id}/attack-ai", status_code=202,
          dependencies=[Depends(job_guard)])
def trigger_attack_ai(job_id: str, principal: dict = Depends(require_token)):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    if not (ATTACK_DIR / job_id / "attack_paths.json").is_file():
        raise HTTPException(status_code=409, detail="attack analysis not run yet")
    if not os.getenv("LLM_API_KEY", "").strip():
        raise HTTPException(status_code=409, detail="LLM_API_KEY is not set")
    _check_quota(job_id, "attack_ai")
    accounts.audit(principal["username"], "attack_ai_trigger", job_id)
    threading.Thread(target=_attack_ai_worker, args=(job_id,),
                     daemon=True).start()
    return {"job_id": job_id, "status": "reviewing"}


@app.post("/jobs/{job_id}/routes", status_code=202,
          dependencies=[Depends(require_token), Depends(job_guard)])
def trigger_routes(job_id: str):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    with _jobs_lock:
        if job["status"] in STATUS_RUNNING:
            raise HTTPException(
                status_code=409,
                detail=f"job is {job['status']}, wait for it to finish")
        if not (CBM_DIR / job_id / "graph_done.json").is_file():
            raise HTTPException(status_code=409, detail="job not graphed yet")
        job["status"] = "routing"
        job["error"] = None
        _save_job(job)
    threading.Thread(target=_route_worker, args=(job_id,), daemon=True).start()
    return {"job_id": job_id, "status": "routing"}


@app.get("/jobs/{job_id}/routes", dependencies=[Depends(require_token), Depends(job_guard)])
def get_routes(job_id: str):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    done_file = ROUTES_DIR / job_id / "routes_done.json"
    if not done_file.is_file() and job["status"] != "routing":
        raise HTTPException(status_code=404, detail="route analysis not run yet")
    out = {"job_id": job_id, "status": job["status"], "error": job["error"]}
    if done_file.is_file():
        out["summary"] = json.loads(done_file.read_text(encoding="utf-8"))
    return out


# ---------------------------------------------------------------------------
# M6a: external-input identification (identification.json)
# ---------------------------------------------------------------------------


@app.post("/jobs/{job_id}/inputs", status_code=202,
          dependencies=[Depends(require_token), Depends(job_guard)])
def trigger_inputs(job_id: str):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    with _jobs_lock:
        if job["status"] in STATUS_RUNNING:
            raise HTTPException(
                status_code=409,
                detail=f"job is {job['status']}, wait for it to finish")
        if not (EXTRACTED_DIR / job_id / "manifest.json").is_file():
            raise HTTPException(status_code=409, detail="job not extracted yet")
        job["status"] = "identifying"
        job["error"] = None
        _save_job(job)
    threading.Thread(target=_inputs_worker, args=(job_id,),
                     daemon=True).start()
    return {"job_id": job_id, "status": "identifying"}


@app.get("/jobs/{job_id}/inputs", dependencies=[Depends(require_token), Depends(job_guard)])
def get_inputs(job_id: str):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    done_file = INPUTS_DIR / job_id / "inputs_done.json"
    if not done_file.is_file() and job["status"] != "identifying":
        raise HTTPException(status_code=404,
                            detail="input identification not run yet")
    out = {"job_id": job_id, "status": job["status"], "error": job["error"]}
    if done_file.is_file():
        out["summary"] = json.loads(done_file.read_text(encoding="utf-8"))
    return out


_MD5_HEX = re.compile(r"^[0-9a-f]{32}$")


def _md5_file(path: Path) -> str | None:
    try:
        digest = hashlib.md5()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def annotate_identification_md5(job_id: str, doc: dict) -> dict:
    """Join identification entry files onto manifest md5s.

    identification.json 只记路径（usr/bin/dropbear），manifest 按内容去重
    （同一 ELF 的 scp/dropbear 硬链接只留一条 path）。挖掘 agent 拿不到
    binary_md5 就会停。GET 时按路径/basename/文件内容补上 md5，并写入
    input_types 的 binary_md5= 标签（旧插件压缩视图也会带出来）。
    """
    man_file = EXTRACTED_DIR / job_id / "manifest.json"
    if not man_file.is_file():
        return doc
    try:
        manifest = json.loads(man_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return doc
    by_path: dict[str, str] = {}
    by_base: dict[str, set[str]] = {}
    known: set[str] = set()
    for binary in manifest.get("binaries") or []:
        md5 = str(binary.get("md5") or "").lower()
        if not _MD5_HEX.match(md5):
            continue
        known.add(md5)
        raw = str(binary.get("path") or "").replace("\\", "/").lstrip("./")
        if not raw:
            continue
        by_path[raw] = md5
        by_base.setdefault(raw.rsplit("/", 1)[-1], set()).add(md5)

    extracted = EXTRACTED_DIR / job_id
    hashed: dict[str, str | None] = {}

    def resolve(rel: str) -> str | None:
        if not rel:
            return None
        norm = rel.replace("\\", "/").lstrip("./")
        if norm in by_path:
            return by_path[norm]
        for man_path, md5 in by_path.items():
            if norm.endswith("/" + man_path) or man_path.endswith("/" + norm):
                return md5
        base = norm.rsplit("/", 1)[-1]
        hits = by_base.get(base) or set()
        if len(hits) == 1:
            return next(iter(hits))
        if rel in hashed:
            return hashed[rel]
        md5 = None
        cand = extracted / norm
        if cand.is_file():
            digest = _md5_file(cand)
            if digest and digest in known:
                md5 = digest
        hashed[rel] = md5
        return md5

    out = dict(doc)
    annotated = []
    for item in doc.get("inputs") or []:
        row = dict(item)
        files = list(row.get("entry_files") or [])
        entry_md5s = [{"path": path, "md5": resolve(path)} for path in files]
        chain = []
        for proc in row.get("processing_chain") or []:
            pc = dict(proc)
            md5 = resolve(str(pc.get("file") or ""))
            if md5:
                pc["md5"] = md5
            chain.append(pc)
        row["processing_chain"] = chain
        md5s = []
        for rec in entry_md5s:
            if rec.get("md5") and rec["md5"] not in md5s:
                md5s.append(rec["md5"])
        for pc in chain:
            if pc.get("md5") and pc["md5"] not in md5s:
                md5s.append(pc["md5"])
        if md5s:
            row["binary_md5"] = md5s[0]
            row["entry_md5s"] = entry_md5s
            types = list(row.get("input_types") or [])
            for md5 in md5s:
                tag = f"binary_md5={md5}"
                if tag not in types:
                    types.append(tag)
            row["input_types"] = types
        annotated.append(row)
    out["inputs"] = annotated
    return out


@app.get("/jobs/{job_id}/identification", dependencies=[Depends(require_token), Depends(job_guard)])
def get_identification(job_id: str):
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail="job not found")
    doc = INPUTS_DIR / job_id / "identification.json"
    if not doc.is_file():
        raise HTTPException(status_code=404,
                            detail="identification.json not built yet")
    return annotate_identification_md5(
        job_id, json.loads(doc.read_text(encoding="utf-8")))


# ---------------------------------------------------------------------------
# M6b: per-input attack-surface export (information/AS-*.json)
# ---------------------------------------------------------------------------

_SURFACE_ID_RE = re.compile(
    r"^AS-(AUTH-)?[0-9A-Za-z]{1,8}$")


@app.post("/jobs/{job_id}/surfaces", status_code=202,
          dependencies=[Depends(require_token), Depends(job_guard)])
def trigger_surfaces(job_id: str):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    with _jobs_lock:
        if job["status"] in STATUS_RUNNING:
            raise HTTPException(
                status_code=409,
                detail=f"job is {job['status']}, wait for it to finish")
        if not (INPUTS_DIR / job_id / "identification.json").is_file():
            raise HTTPException(status_code=409,
                                detail="job has no identification.json — "
                                       "run the inputs stage first")
        job["status"] = "surfacing"
        job["error"] = None
        _save_job(job)
    threading.Thread(target=_surfaces_worker, args=(job_id,),
                     daemon=True).start()
    return {"job_id": job_id, "status": "surfacing"}


@app.get("/jobs/{job_id}/surfaces", dependencies=[Depends(require_token), Depends(job_guard)])
def get_surfaces(job_id: str):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    done_file = SURFACES_DIR / job_id / "surfaces_done.json"
    if not done_file.is_file() and job["status"] != "surfacing":
        raise HTTPException(status_code=404,
                            detail="surface export not run yet")
    out = {"job_id": job_id, "status": job["status"], "error": job["error"]}
    if done_file.is_file():
        out["summary"] = json.loads(done_file.read_text(encoding="utf-8"))
    info_dir = SURFACES_DIR / job_id / "information"
    if info_dir.is_dir():
        out["files"] = sorted(f.name for f in info_dir.glob("*.json"))
    return out


@app.get("/jobs/{job_id}/surfaces/{surface_id}",
         dependencies=[Depends(require_token), Depends(job_guard)])
def get_surface(job_id: str, surface_id: str):
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail="job not found")
    if not _SURFACE_ID_RE.match(surface_id):
        raise HTTPException(status_code=400, detail="bad surface id")
    doc = SURFACES_DIR / job_id / "information" / f"{surface_id}.json"
    if not doc.is_file():
        raise HTTPException(status_code=404, detail="surface not found")
    return json.loads(doc.read_text(encoding="utf-8"))

# ---------------------------------------------------------------------------
# Dynamic analysis engines: AFL++ fuzz (device-free) + frida (live device)
# ---------------------------------------------------------------------------

_FUZZ_RUN_RE = re.compile(r"^fz-[0-9a-f]{8}$")
_EXEC_RUN_RE = re.compile(r"^qe-[0-9a-f]{8}$")
_FRIDA_RUN_RE = re.compile(r"^fs-[0-9a-f]{8}$")
_FUZZ_LOCK = threading.Lock()
_EXEC_LOCK = threading.Lock()
_FRIDA_LOCK = threading.Lock()


def _dyn_worker(kind, job_id, run_dir, run_file, fn):
    """Run a dynamic-analysis job; placeholder -> result, errors captured."""
    try:
        summary = fn()
        run_file.write_text(json.dumps(summary, indent=2),
                            encoding="utf-8")
    except Exception as exc:  # noqa: BLE001 - surface as run-level error
        summary = {"run_id": run_dir.name, "job_id": job_id, "engine": kind,
                   "status": "error", "detail": f"{type(exc).__name__}: {exc}"}
        run_file.write_text(json.dumps(summary, indent=2),
                            encoding="utf-8")


@app.post("/jobs/{job_id}/fuzz", status_code=202,
          dependencies=[Depends(job_guard)])
def trigger_fuzz(job_id: str, payload: dict = Body(...),
                 principal: dict = Depends(require_token)):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    md5 = str(payload.get("binary_md5") or "")
    if not re.fullmatch(r"[0-9a-f]{32}", md5):
        raise HTTPException(status_code=400,
                            detail="binary_md5 must be 32 lowercase hex")
    argv = payload.get("argv") or []
    if not isinstance(argv, list) or len(argv) > 16:
        raise HTTPException(status_code=400, detail="argv must be a list <= 16")
    function = payload.get("function")
    if function is not None and not re.fullmatch(
            r"(0x)?[0-9a-fA-F]{1,12}", str(function)):
        raise HTTPException(status_code=400,
                            detail="function must be a hex address")
    args = payload.get("args") or []
    if not isinstance(args, list) or len(args) > 8:
        raise HTTPException(status_code=400,
                            detail="args like [\"buf\",\"len\"] (<= 8)")
    seconds = int(payload.get("seconds") or 60)
    _check_quota(job_id, "fuzz")
    accounts.audit(principal["username"], "fuzz_trigger", job_id)
    run_id = f"fz-{uuid.uuid4().hex[:8]}"
    run_dir = FUZZ_DIR / job_id / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    run_file = run_dir / "fuzz.json"
    run_file.write_text(json.dumps(
        {"run_id": run_id, "job_id": job_id, "engine": "afl-qemu",
         "status": "running", "binary_md5": md5,
         "function": str(function) if function else None}),
        encoding="utf-8")

    def _go():
        with _FUZZ_LOCK:
            _dyn_worker(
                "afl-qemu", job_id, run_dir, run_file,
                lambda: fuzz_runner.run_job(
                    job_id, DATA_DIR, md5, function=function, args=args,
                    argv=argv, seconds=seconds, run_id=run_id))
    threading.Thread(target=_go, daemon=True).start()
    return {"job_id": job_id, "run_id": run_id, "status": "running"}


@app.get("/jobs/{job_id}/fuzz", dependencies=[Depends(require_token), Depends(job_guard)])
def list_fuzz(job_id: str):
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail="job not found")
    return {"job_id": job_id, "runs": fuzz_runner.list_runs(job_id, DATA_DIR)}


@app.post("/jobs/{job_id}/qemu-exec", status_code=202,
          dependencies=[Depends(job_guard)])
def trigger_qemu_exec(job_id: str, payload: dict = Body(...),
                      principal: dict = Depends(require_token)):
    """One-shot qemu-user PoC run: stdin or /tmp file, report crash/rc."""
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    md5 = _resolve_job_md5(job_id, payload.get("binary_md5") or "")
    argv = payload.get("argv") or []
    if not isinstance(argv, list) or len(argv) > 16:
        raise HTTPException(status_code=400, detail="argv must be a list <= 16")
    try:
        stdin = qemu_exec.decode_bytes(
            payload.get("stdin"), payload.get("stdin_hex"), "stdin")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    input_path = payload.get("input_path")
    if input_path is not None and not isinstance(input_path, str):
        raise HTTPException(status_code=400, detail="input_path must be a string")
    seconds = int(payload.get("seconds") or 8)
    _check_quota(job_id, "exec")
    accounts.audit(principal["username"], "qemu_exec", job_id)
    run_id = f"qe-{uuid.uuid4().hex[:8]}"
    run_dir = EXEC_DIR / job_id / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    run_file = run_dir / "exec.json"
    run_file.write_text(json.dumps(
        {"run_id": run_id, "job_id": job_id, "engine": "qemu-user",
         "status": "running", "binary_md5": md5}), encoding="utf-8")

    def _go():
        with _EXEC_LOCK:
            _dyn_worker(
                "qemu-user", job_id, run_dir, run_file,
                lambda: qemu_exec.run_job(
                    job_id, DATA_DIR, md5, argv=argv,
                    argv0=payload.get("argv0"), stdin=stdin,
                    input_path=input_path, seconds=seconds, run_id=run_id))
    threading.Thread(target=_go, daemon=True).start()
    return {"job_id": job_id, "run_id": run_id, "status": "running",
            "next": "poll GET /jobs/{id}/qemu-exec/{run_id} until status is not running"}


@app.get("/jobs/{job_id}/qemu-exec/{run_id}",
         dependencies=[Depends(require_token), Depends(job_guard)])
def get_qemu_exec(job_id: str, run_id: str):
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail="job not found")
    if not _EXEC_RUN_RE.match(run_id):
        raise HTTPException(status_code=400, detail="bad run id")
    try:
        return qemu_exec.get_run(job_id, DATA_DIR, run_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="exec run not found")


@app.get("/jobs/{job_id}/fuzz/{run_id}", dependencies=[Depends(require_token), Depends(job_guard)])
def get_fuzz(job_id: str, run_id: str):
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail="job not found")
    if not _FUZZ_RUN_RE.match(run_id):
        raise HTTPException(status_code=400, detail="bad run id")
    try:
        return fuzz_runner.get_run(job_id, DATA_DIR, run_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="fuzz run not found")


@app.post("/jobs/{job_id}/frida", status_code=202,
          dependencies=[Depends(job_guard)])
def trigger_frida(job_id: str, payload: dict = Body(...),
                  principal: dict = Depends(require_token)):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    try:
        import frida  # noqa: F401
    except ImportError:
        raise HTTPException(status_code=503,
                            detail="frida-tools not installed on the host")
    host = str(payload.get("host") or "")
    if not re.fullmatch(r"[\w.:-]{1,64}", host):
        raise HTTPException(status_code=400,
                            detail="host like 192.168.1.10 or 192.168.1.10:27042")
    process = str(payload.get("process") or "")
    if not process or len(process) > 128:
        raise HTTPException(status_code=400, detail="process required")
    functions = payload.get("functions") or []
    if not isinstance(functions, list) or not 1 <= len(functions) <= 32:
        raise HTTPException(status_code=400,
                            detail="functions must be a list of 1..32")
    seconds = int(payload.get("seconds") or 60)
    spawn = bool(payload.get("spawn"))
    _check_quota(job_id, "frida")
    accounts.audit(principal["username"], "frida_trigger", job_id)
    run_id = f"fs-{uuid.uuid4().hex[:8]}"
    run_dir = FRIDA_DIR / job_id / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    run_file = run_dir / "frida.json"
    run_file.write_text(json.dumps(
        {"run_id": run_id, "job_id": job_id, "engine": "frida",
         "status": "running", "host": host, "process": process}),
        encoding="utf-8")

    def _go():
        with _FRIDA_LOCK:
            _dyn_worker(
                "frida", job_id, run_dir, run_file,
                lambda: frida_runner.run_job(
                    job_id, DATA_DIR, host, process, functions,
                    seconds=seconds, spawn=spawn, run_id=run_id))
    threading.Thread(target=_go, daemon=True).start()
    return {"job_id": job_id, "run_id": run_id, "status": "running"}


@app.get("/jobs/{job_id}/frida", dependencies=[Depends(require_token), Depends(job_guard)])
def list_frida(job_id: str):
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail="job not found")
    return {"job_id": job_id, "runs": frida_runner.list_runs(job_id, DATA_DIR)}


@app.get("/jobs/{job_id}/frida/{run_id}", dependencies=[Depends(require_token), Depends(job_guard)])
def get_frida(job_id: str, run_id: str):
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail="job not found")
    if not _FRIDA_RUN_RE.match(run_id):
        raise HTTPException(status_code=400, detail="bad run id")
    try:
        return frida_runner.get_run(job_id, DATA_DIR, run_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="frida run not found")


# ---------------------------------------------------------------------------
# M4b: CFG / AST graph extensions
# ---------------------------------------------------------------------------

_GRAPHEXT_LOCK = threading.Lock()


# ---- 固件后门专项检测 & SCA（Trivy） --------------------------------------

BACKDOOR_DIR = DATA_DIR / "backdoor"
SCA_DIR = DATA_DIR / "sca"
_ANALYSIS_JOBS: dict[str, dict] = {}
_analysis_lock = threading.Lock()


def _analysis_path(kind: str, job_id: str) -> Path:
    d = BACKDOOR_DIR if kind == "backdoor" else SCA_DIR
    return d / f"{job_id}.json"


def _analysis_state(kind: str, job_id: str) -> dict | None:
    path = _analysis_path(kind, job_id)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _run_analysis(kind: str, job_id: str, fn, principal: str):
    path = _analysis_path(kind, job_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    state = {"kind": kind, "job_id": job_id, "status": "running",
             "started_at": _now(), "error": None, "result": None}
    path.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
    try:
        result = fn(job_id, DATA_DIR)
        if kind == "sca":
            # SCA 发现自动入漏洞库（统一严重度体系；失败不影响扫描结果）
            try:
                if result.get("cve_total"):
                    job = _jobs.get(job_id) or {}
                    result["vulnlib_sync"] = vulnlib_store.upsert_sca_findings(
                        job_id, job.get("firmware") or "", result, principal)
            except Exception as exc:  # noqa: BLE001
                print(f"[orchestrator] sca->vulnlib {job_id} failed: {exc}",
                      flush=True)
            # mithril CVE（版本区间+EPSS/KEV）同样入库
            try:
                mcves = ((result.get("mithril") or {}).get("cves")) or []
                if mcves:
                    job = _jobs.get(job_id) or {}
                    result["mithril_sync"] = vulnlib_store.upsert_mithril_findings(
                        job_id, job.get("firmware") or "", mcves, principal)
            except Exception as exc:  # noqa: BLE001
                print(f"[orchestrator] mithril->vulnlib {job_id} failed: {exc}",
                      flush=True)
        state.update(status="done", finished_at=_now(), result=result)
        accounts.audit(principal, f"{kind}_done", job_id)
    except BaseException as exc:  # noqa: BLE001 - 状态必须落盘
        state.update(status="failed", finished_at=_now(),
                     error=f"{type(exc).__name__}: {exc}")
        print(f"[orchestrator] {kind} {job_id} failed: {exc}", flush=True)
    finally:
        path.write_text(json.dumps(state, ensure_ascii=False, indent=1),
                        encoding="utf-8")
        with _analysis_lock:
            _ANALYSIS_JOBS.pop(f"{kind}:{job_id}", None)


def _start_analysis(kind: str, job_id: str, fn, principal: str):
    key = f"{kind}:{job_id}"
    with _analysis_lock:
        if key in _ANALYSIS_JOBS:
            raise HTTPException(
                409, detail=f"{kind} 扫描正在运行，请稍候")
        _ANALYSIS_JOBS[key] = True
    threading.Thread(target=_run_analysis,
                     args=(kind, job_id, fn, principal),
                     daemon=True).start()


def _require_extracted(job_id: str):
    if not (EXTRACTED_DIR / job_id / "manifest.json").is_file():
        raise HTTPException(
            409, detail="该任务尚未完成解包（正在排队或失败），请稍后再试")


@app.post("/jobs/{job_id}/backdoor", status_code=202,
          dependencies=[Depends(require_token), Depends(job_guard)])
def trigger_backdoor(job_id: str,
                     principal: dict = Depends(require_token)):
    if _jobs.get(job_id) is None:
        raise HTTPException(404, detail="job not found")
    _require_extracted(job_id)
    _start_analysis("backdoor", job_id, backdoor_scan.scan_backdoor,
                    principal.get("username") or "admin")
    return {"job_id": job_id, "status": "running"}


@app.get("/jobs/{job_id}/backdoor",
         dependencies=[Depends(require_token), Depends(job_guard)])
def get_backdoor(job_id: str):
    state = _analysis_state("backdoor", job_id)
    if state is None:
        return {"status": "never"}
    return state


@app.post("/jobs/{job_id}/sca", status_code=202,
          dependencies=[Depends(require_token), Depends(job_guard)])
def trigger_sca(job_id: str,
                principal: dict = Depends(require_token)):
    if _jobs.get(job_id) is None:
        raise HTTPException(404, detail="job not found")
    _require_extracted(job_id)
    binpath, err = sca_scan.check_trivy()
    if err:
        raise HTTPException(503, detail=err)
    _start_analysis("sca", job_id, sca_scan.scan_sca,
                    principal.get("username") or "admin")
    return {"job_id": job_id, "status": "running"}


@app.get("/jobs/{job_id}/sca",
         dependencies=[Depends(require_token), Depends(job_guard)])
def get_sca(job_id: str):
    state = _analysis_state("sca", job_id)
    if state is None:
        return {"status": "never"}
    return state


@app.get("/jobs/{job_id}/moria-tree",
         dependencies=[Depends(require_token), Depends(job_guard)])
def get_moria_tree(job_id: str):
    """moria 结构快诊树（上传时生成；旧任务无此文件返回 404 语义的空态）。"""
    path = EXTRACTED_DIR / job_id / "moria-tree.json"
    if not path.is_file():
        return {"findings": [], "unidentified": [],
                "note": "该任务早于结构快诊上线或快诊被禁用"}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"findings": [], "unidentified": [], "note": "快诊结果损坏"}


@app.get("/jobs/{job_id}/sbom/{fmt}",
         dependencies=[Depends(require_token), Depends(job_guard)])
def get_sbom(job_id: str, fmt: str):
    """SBOM 下载（CycloneDX/SPDX，mithril 产出，SCA 完成后可下载）。"""
    if fmt not in ("cdx", "spdx"):
        raise HTTPException(status_code=400, detail="fmt 需为 cdx 或 spdx")
    name = "sbom.cdx.json" if fmt == "cdx" else "sbom.spdx.json"
    path = DATA_DIR / "sbom" / job_id / name
    if not path.is_file():
        raise HTTPException(status_code=404, detail="SBOM 尚未生成（先跑 SCA）")
    return JSONResponse(json.loads(path.read_text(encoding="utf-8")))


@app.post("/jobs/{job_id}/graphext", status_code=202,
          dependencies=[Depends(require_token), Depends(job_guard)])
def trigger_graphext(job_id: str):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    if not (PSEUDOCODE_DIR / job_id / "symbols.json").is_file():
        raise HTTPException(status_code=409, detail="job not decompiled yet")

    def _go():
        with _GRAPHEXT_LOCK:
            try:
                graphext_runner.run_job(job_id, DATA_DIR)
            except Exception as exc:  # noqa: BLE001
                done = GRAPHEXT_DIR / job_id
                done.mkdir(parents=True, exist_ok=True)
                (done / "graphext_done.json").write_text(json.dumps(
                    {"job_id": job_id, "status": "error",
                     "detail": f"{type(exc).__name__}: {exc}"}),
                    encoding="utf-8")
    threading.Thread(target=_go, daemon=True).start()
    return {"job_id": job_id, "status": "extending"}


@app.get("/jobs/{job_id}/graphext", dependencies=[Depends(require_token), Depends(job_guard)])
def get_graphext(job_id: str):
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail="job not found")
    done = GRAPHEXT_DIR / job_id / "graphext_done.json"
    if not done.is_file():
        raise HTTPException(status_code=404, detail="graphext not run yet")
    return json.loads(done.read_text(encoding="utf-8"))


_TRACE_ID_RE = re.compile(r"^[0-9a-f]{12}$")
# One trace at a time: qemu -d exec is heavy and ports could collide.
TRACE_LOCK = threading.Lock()


def _trace_worker(job_id: str, trace_id: str, req: dict):
    # cbm hand-off only makes sense once the graph exists
    project = graph_ingest.project_name(job_id) \
        if (CBM_DIR / job_id / "graph_done.json").is_file() else None
    refresh = False
    try:
        trace = tracer.run_trace(
            job_id, DATA_DIR, req["binary_md5"], req["argv"],
            port=req.get("port"), request_path=req.get("request_path"),
            trace_id=trace_id, cbm_project=project, argv0=req.get("argv0"),
            payload=req.get("payload"), via=req.get("via"),
            input_path=req.get("input_path"))
        # empty-diff traces do not add request-handling functions; reloading
        # 28MB symbols.json after every ok_empty_diff balloons RSS.
        status = str(trace.get("status") or "")
        refresh = status in ("ok", "ok_trigger_error") \
            and (ATTACK_DIR / job_id / "attack_paths.json").is_file()
    except Exception:  # noqa: BLE001 - run_trace persists its own failure
        pass
    finally:
        TRACE_LOCK.release()
    # 攻击路径刷新可能很久，绝不能占着 TRACE_LOCK，否则后续 fw_request_trace 全 409
    if refresh:
        try:
            attack_runner.run_job(job_id, DATA_DIR)
        except Exception:
            pass


def _reap_stale_running_trace(trace: dict, trace_file: Path) -> dict:
    """编排器重启会把 running 的 worker 杀掉，trace.json 会一直 running。
    GET/LIST 时若超过 2*TRACE_RUN_TIMEOUT+30s 仍 running，标 failed 让
    挖掘 agent 停止空转轮询并重试 fw_request_trace。"""
    if not isinstance(trace, dict) or trace.get("status") != "running":
        return trace
    created = str(trace.get("created_at") or "")
    try:
        t0 = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError:
        return trace
    limit = 2 * float(os.getenv("TRACE_RUN_TIMEOUT", "60")) + 30.0
    age = (datetime.now(timezone.utc) - t0).total_seconds()
    if age < limit:
        return trace
    trace = dict(trace)
    trace["status"] = "failed"
    trace["error"] = (
        f"QemuError: trace worker lost after {int(age)}s "
        "(orchestrator restart or hung qemu); retry fw_request_trace"
    )
    trace["finished_at"] = _now()
    trace["elapsed_seconds"] = round(age, 2)
    try:
        tmp = trace_file.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(trace, indent=2), encoding="utf-8")
        tmp.replace(trace_file)
    except OSError:
        pass
    return trace


def _trace_summary(trace: dict) -> dict:
    return {
        "trace_id": trace.get("trace_id"),
        "status": trace.get("status"),
        "error": trace.get("error"),
        "created_at": trace.get("created_at"),
        "elapsed_seconds": trace.get("elapsed_seconds"),
        "binary_md5": (trace.get("binary") or {}).get("md5"),
        "binary_path": (trace.get("binary") or {}).get("path"),
        "argv": trace.get("argv"),
        "request": trace.get("request"),
        "trigger_result": (trace.get("trigger") or {}).get("trigger_result"),
        "baseline_functions": (trace.get("baseline") or {}).get("functions"),
        "trigger_functions": (trace.get("trigger") or {}).get("functions"),
        "diff_functions": (trace.get("diff") or {}).get("function_count"),
    }


@app.post("/jobs/{job_id}/trace", status_code=202,
          dependencies=[Depends(job_guard)])
def trigger_trace(job_id: str, payload: dict = Body(...),
                  principal: dict = Depends(require_token)):
    """M7: run a baseline/trigger differential coverage trace.

    Body: {binary_md5, argv=[...], port?, request_path?, argv0?,
    payload?, payload_hex?, payloads_hex?, via?, input_path?}.
    via=stdin feeds payload on qemu stdin (parsers/CLI) instead of a
    listen port. input_path=/tmp/<name> drops the bytes as a guest file.
    payload/payload_hex is one blob; payloads_hex is a same-connection
    conversation. Omit both to use the per-port default probe.
    The job's main status is untouched; trace status lives in trace.json
    (running -> ok | ok_empty_diff | failed). Typical wall time is
    2x(ready+hold) plus qemu overhead, well under 5 minutes
    (TRACE_RUN_TIMEOUT per run, default 60s).
    """
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    md5 = _resolve_job_md5(job_id, payload.get("binary_md5") or "")
    argv = payload.get("argv")
    if argv is None:
        argv = []
    if not isinstance(argv, list) \
            or not all(isinstance(a, (str, int)) for a in argv):
        raise HTTPException(status_code=400,
                            detail="argv must be a list of strings "
                                   "(empty = run the binary with no extra args)")
    port = payload.get("port")
    if port is not None and not (isinstance(port, int)
                                 and 1 <= port <= 65535):
        raise HTTPException(status_code=400, detail="port must be 1..65535")
    if not (PSEUDOCODE_DIR / job_id / "symbols.json").is_file():
        raise HTTPException(status_code=409,
                            detail="job not decompiled yet (no symbols.json)")
    try:
        chunks = tracer.decode_payloads(
            payload.get("payload"), payload.get("payload_hex"),
            payload.get("payloads_hex"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    raw_payload = None if not chunks else (
        chunks[0] if len(chunks) == 1 else chunks)
    via = str(payload.get("via") or "").strip().lower() or None
    if via and via not in ("net", "stdin"):
        raise HTTPException(status_code=400, detail="via 必须是 net 或 stdin")
    input_path = payload.get("input_path")
    if input_path is not None:
        input_path = str(input_path)
        if not tracer._INPUT_PATH_RE.match(input_path):
            raise HTTPException(status_code=400,
                                detail="input_path 必须是 /tmp/<简单文件名>")
    if not TRACE_LOCK.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="another trace is running")
    try:
        _check_quota(job_id, "trace")
    except HTTPException:
        TRACE_LOCK.release()
        raise
    accounts.audit(principal["username"], "trace_trigger", job_id)
    trace_id = tracer.new_trace_id()
    req = {"binary_md5": md5, "argv": argv, "port": port,
           "request_path": payload.get("request_path"),
           "argv0": payload.get("argv0"),
           "payload": raw_payload, "via": via, "input_path": input_path}
    threading.Thread(target=_trace_worker, args=(job_id, trace_id, req),
                     daemon=True).start()
    return {"job_id": job_id, "trace_id": trace_id, "status": "running"}


@app.get("/jobs/{job_id}/traces", dependencies=[Depends(require_token), Depends(job_guard)])
def list_traces(job_id: str, limit: int | None = Query(default=None, ge=1, le=500)):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    root = TRACES_DIR / job_id
    traces = []
    if root.is_dir():
        for tf in root.glob("*/trace.json"):
            try:
                traces.append(_trace_summary(_reap_stale_running_trace(
                    json.loads(tf.read_text(encoding="utf-8")), tf)))
            except (OSError, json.JSONDecodeError):
                continue
    traces.sort(key=lambda t: t.get("created_at") or "", reverse=True)
    total = len(traces)
    if limit is not None:
        traces = traces[:limit]
    return {"job_id": job_id, "total": total, "traces": traces}


@app.get("/jobs/{job_id}/traces/{trace_id}",
         dependencies=[Depends(require_token), Depends(job_guard)])
def get_trace(job_id: str, trace_id: str):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    if not _TRACE_ID_RE.match(trace_id):
        raise HTTPException(status_code=400, detail="bad trace_id format")
    trace_file = TRACES_DIR / job_id / trace_id / "trace.json"
    if not trace_file.is_file():
        raise HTTPException(status_code=404, detail="trace not found")
    return _reap_stale_running_trace(
        json.loads(trace_file.read_text(encoding="utf-8")), trace_file)


def _trace_flow(job_id: str, payload: dict):
    """trace_flow op: ordered request-handling path of one trace (M7).

    The sequence comes from trace.json (the authoritative store; CBM's
    ingest_traces is a stub in 0.9.0). Function display name prefers
    ai_name. Entries whose libc_equiv (or, as a fallback, name) is one of
    strcpy/sprintf/system/popen/execve are additionally listed under
    'dangerous'.
    """
    trace_id = str(payload.get("trace_id") or "")
    if not _TRACE_ID_RE.match(trace_id):
        raise HTTPException(status_code=400,
                            detail="trace_flow: 'trace_id' (12 hex) required")
    trace_file = TRACES_DIR / job_id / trace_id / "trace.json"
    if not trace_file.is_file():
        raise HTTPException(status_code=404, detail="trace not found")
    trace = json.loads(trace_file.read_text(encoding="utf-8"))
    sequence = []
    dangerous = []
    for f in (trace.get("diff") or {}).get("functions", []):
        name = f.get("ai_name") or f.get("name")
        entry = {"addr": f.get("addr"), "name": name,
                 "libc_equiv": f.get("libc_equiv"),
                 "first_seen_idx": f.get("first_seen_idx")}
        sequence.append(entry)
        hit = f.get("libc_equiv") if f.get("libc_equiv") in \
            tracer.TRACE_DANGEROUS else None
        if hit is None and name in tracer.TRACE_DANGEROUS:
            hit = name
        if hit:
            dangerous.append({**entry, "matched": hit})
    md5 = (trace.get("binary") or {}).get("md5") or ""
    for entry in sequence:
        if entry.get("addr"):
            entry["evidence_address"] = ev.make_address(
                md5, entry["addr"], job_id=job_id)
    status = str(trace.get("status") or "")
    envelope = ev.wrap_envelope(
        producer="trace", view_kind="trace_flow", job_id=job_id,
        capture_id=trace_id, items=sequence,
        attribution=ev.ATTRIBUTION_OBSERVED,
        integrity="ok" if status.startswith("ok") else "degraded",
        limit=payload.get("limit"),
    )
    return {
        "job_id": job_id, "trace_id": trace_id, "status": trace.get("status"),
        "binary": trace.get("binary"), "argv": trace.get("argv"),
        "request": trace.get("request"),
        "function_count": len(sequence), "sequence": sequence,
        "dangerous_count": len(dangerous), "dangerous": dangerous,
        "attribution": ev.ATTRIBUTION_OBSERVED,
        "envelope": envelope,
    }


def _trim_cfg(cfg: dict, max_nodes: int) -> dict:
    """Cap a CFG at max_nodes blocks (0 = full). Edges are [from, to, kind]
    triples keyed by block start address."""
    blocks = cfg.get("blocks", [])
    if not max_nodes or len(blocks) <= max_nodes:
        return cfg
    kept = blocks[:max_nodes]
    keep_addrs = {b.get("start") for b in kept}
    edges = [e for e in cfg.get("edges", [])
             if isinstance(e, (list, tuple)) and len(e) >= 2
             and e[0] in keep_addrs and e[1] in keep_addrs]
    return {**cfg, "blocks": kept, "edges": edges,
            "truncated": True, "total_blocks": len(blocks)}


def _trim_ast(ast: dict, max_depth: int, max_nodes: int) -> dict:
    """Prune an AST beyond max_depth and/or max_nodes (0 = no limit)."""
    if not max_depth and not max_nodes:
        return ast
    root = ast.get("root")
    if not isinstance(root, dict):
        return ast
    budget = [max_nodes or 10**9]
    pruned = [False]

    def walk(node, depth):
        if budget[0] <= 0:
            pruned[0] = True
            return {"type": node.get("type", "?"), "pruned": True}
        budget[0] -= 1
        out = {k: v for k, v in node.items() if k != "children"}
        children = node.get("children") or []
        if children and max_depth and depth >= max_depth:
            out["children"] = [{"type": "…", "pruned": True,
                                "pruned_children": len(children)}]
            pruned[0] = True
        elif children:
            out["children"] = [walk(c, depth + 1) for c in children]
        return out

    trimmed = walk(root, 0)
    if pruned[0]:
        return {**ast, "root": trimmed, "truncated": True}
    return {**ast, "root": trimmed}


def _stamp_node(node, job_id: str, md5: str):
    """Attach Evidence Address without mutating the on-disk artifact."""
    if not isinstance(node, dict):
        return node
    out = dict(node)
    addr = out.get("addr")
    if addr:
        out["evidence_address"] = ev.make_address(
            out.get("binary_md5") or md5, addr, job_id=job_id)
    return out


def _stamp_path(path: dict, job_id: str) -> dict:
    md5 = str(path.get("binary_md5") or "")
    out = dict(path)
    out["source"] = _stamp_node(path.get("source"), job_id, md5)
    out["sink"] = _stamp_node(path.get("sink"), job_id, md5)
    chain = path.get("chain")
    if isinstance(chain, list):
        out["chain"] = [_stamp_node(n, job_id, md5) for n in chain]
    if not out.get("attribution"):
        if out.get("verified_reachable"):
            out["attribution"] = ev.ATTRIBUTION_VERIFIED
        elif out.get("observed_node_count"):
            out["attribution"] = ev.ATTRIBUTION_OBSERVED
        else:
            out["attribution"] = ev.ATTRIBUTION_STATIC
    return out


def _attack_surface(job_id: str, payload: dict):
    """Return ranked, precomputed attack paths with optional filters.

    brief=true strips each path to {path_id, score, edge_count, source, sink,
    sanitizers, verified/observed flags} — the chain node list (the bulk of
    the payload) is omitted so the upstream AI can triage cheaply and fetch
    full paths only for the interesting ones."""
    artifact = ATTACK_DIR / job_id / "attack_paths.json"
    if not artifact.is_file():
        raise HTTPException(status_code=404, detail="attack analysis not run yet")
    data = json.loads(artifact.read_text(encoding="utf-8"))
    source_filter = str(payload.get("source") or "")
    sink_filter = str(payload.get("sink") or "")
    try:
        limit = max(1, min(int(payload.get("limit", 50)), 200))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="attack_surface: bad limit") from exc
    paths = []
    for path in data.get("paths", []):
        if source_filter and source_filter not in path.get("source", {}).get("asrc", []):
            continue
        if sink_filter and sink_filter not in path.get("sink", {}).get("asink", []):
            continue
        if payload.get("verified_only") and not path.get("verified_reachable"):
            continue
        paths.append(_stamp_path(path, job_id))
        if len(paths) >= limit:
            break
    if payload.get("brief"):
        def _ep(node):
            return {k: (node or {}).get(k)
                    for k in ("addr", "name", "ai_name", "asrc", "asink",
                              "evidence_address")}
        from pipeline.attack import ai_review as _ai_review
        paths = [{
            "path_id": p.get("path_id"), "score": p.get("score"),
            "edge_count": p.get("edge_count"),
            "verified_reachable": bool(p.get("verified_reachable")),
            "observed_node_count": p.get("observed_node_count", 0),
            "attribution": p.get("attribution"),
            "entry_outdegree": p.get("entry_outdegree"),
            "danger_calls": p.get("danger_calls"),
            "source": _ep(p.get("source")), "sink": _ep(p.get("sink")),
            "sanitizers": p.get("sanitizers", []),
            "ai_review": _ai_review.compact(p.get("ai_review")),
        } for p in paths]
    return {"job_id": job_id, "generated_at": data.get("generated_at"),
            "summary": data.get("summary", {}), "total": len(paths),
            "paths": paths}


def _routes(job_id: str, payload: dict):
    """Return statically recovered URL-to-handler mappings."""
    artifact = ROUTES_DIR / job_id / "routes.json"
    if not artifact.is_file():
        raise HTTPException(status_code=404, detail="route analysis not run yet")
    data = json.loads(artifact.read_text(encoding="utf-8"))
    pattern = str(payload.get("pattern") or "").lower()
    method = str(payload.get("method") or "").upper()
    binary_md5 = str(payload.get("binary_md5") or "")
    try:
        minimum = float(payload.get("min_confidence", 0))
        limit = max(1, min(int(payload.get("limit", 50)), 500))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="routes: bad filter") from exc
    matches = []
    for route in data.get("routes", []):
        if pattern and pattern not in str(route.get("route") or "").lower():
            continue
        if method and method != str(route.get("method") or "").upper():
            continue
        if binary_md5 and binary_md5 != route.get("binary_md5"):
            continue
        if float(route.get("confidence") or 0) < minimum:
            continue
        matches.append(route)
        if len(matches) >= limit:
            break
    return {"job_id": job_id, "generated_at": data.get("generated_at"),
            "summary": data.get("summary", {}), "total": len(matches),
            "routes": matches}


# M4: the cypher op is strictly read-only — write-capable clauses are
# rejected here, before anything reaches query.py / the CBM SQLite.
_CYPHER_WRITE_RE = re.compile(
    r"\b(CREATE|SET|DELETE|REMOVE|MERGE|DROP|CALL|LOAD)\b", re.IGNORECASE)


@app.post("/graph/query")
def graph_query_endpoint(payload: dict = Body(...),
                         principal: dict = Depends(require_token)):
    """Graph检索 proxy for the upstream vuln-hunting AI.

    Body: {"job_id": ..., "op": "search"|"cypher"|"trace"|"snippet"|
           "dangerous"|"trace_flow"|"attack_surface"|"routes",
           ...op-specific args}
      search:    pattern (required), label?, limit?
      cypher:    query (required) — raw Cypher against the CBM subset,
                 READ-ONLY: CREATE/SET/DELETE/REMOVE/MERGE/DROP/CALL/LOAD
                 are rejected with 400
      trace:     name (required), direction? (both|inbound|outbound)
      snippet:   name (required) — resolves to qualified_name internally
      dangerous: functions? (defaults to query.DEFAULT_DANGEROUS), limit?
      trace_flow: trace_id (required) — M7: ordered request-handling path
                 of one coverage trace + dangerous libc_equiv highlights
      attack_surface: source?, sink?, verified_only?, limit?, brief? — ranked paths;
                 brief=true drops the per-path chain node list (triage view)
      compose_evidence: binary_md5 + addr; optional static_block /
                 decompile_text / dynamic_envelope — join already-fetched facts
      routes: pattern?, method?, binary_md5?, min_confidence?, limit?
      cfg/ast:  md5 + addr (required), max_nodes?, max_depth? — context-budget
                 truncation (0 = full)

    Job-scoped: callers only see jobs they own (admin sees all); foreign
    jobs answer 404.
    """
    job_id = payload.get("job_id")
    if not job_id or job_id not in _jobs:
        raise HTTPException(status_code=404, detail="job not found")
    if not _can_access(principal, _jobs[job_id].get("owner")):
        raise HTTPException(status_code=404, detail="job not found")
    op = payload.get("op")
    project = graph_ingest.project_name(job_id)
    try:
        if op == "search":
            pattern = payload.get("pattern")
            if not pattern:
                raise HTTPException(status_code=400,
                                    detail="search: 'pattern' required")
            return graph_query.search(project, pattern,
                                      label=payload.get("label"),
                                      limit=payload.get("limit"))
        if op == "cypher":
            q = str(payload.get("query") or "").strip()
            if not q:
                raise HTTPException(status_code=400,
                                    detail="cypher: 'query' required")
            if _CYPHER_WRITE_RE.search(q):
                raise HTTPException(
                    status_code=400,
                    detail="cypher 仅允许只读查询（MATCH/RETURN/WHERE 等）；"
                           "禁止 CREATE/SET/DELETE/REMOVE/MERGE/DROP/CALL/"
                           "LOAD 写操作")
            return graph_query.cypher(project, q)
        if op == "trace":
            name = payload.get("name")
            if not name:
                raise HTTPException(status_code=400, detail="trace: 'name' required")
            return graph_query.trace(project, name,
                                     direction=payload.get("direction", "both"))
        if op == "snippet":
            name = payload.get("name")
            if not name:
                raise HTTPException(status_code=400,
                                    detail="snippet: 'name' required")
            return graph_query.snippet(project, name)
        if op == "dangerous":
            return graph_query.dangerous_callsites(
                project, functions=payload.get("functions"),
                limit=int(payload.get("limit", 50)))
        if op == "trace_flow":
            return _trace_flow(job_id, payload)
        if op == "attack_surface":
            return _attack_surface(job_id, payload)
        if op == "compose_evidence":
            md5 = str(payload.get("binary_md5") or "")
            addr = str(payload.get("addr") or "")
            if not re.fullmatch(r"[0-9a-f]{32}", md5) or not addr:
                raise HTTPException(
                    status_code=400,
                    detail="compose_evidence: binary_md5 + addr required")
            return ev.compose(
                job_id=job_id, binary_md5=md5, addr=addr,
                static_block=payload.get("static_block"),
                decompile_text=payload.get("decompile_text"),
                dynamic_envelope=payload.get("dynamic_envelope"),
            )
        if op == "routes":
            return _routes(job_id, payload)
        if op in ("cfg", "ast"):
            md5 = str(payload.get("md5") or "")
            addr = str(payload.get("addr") or "")
            if not re.fullmatch(r"[0-9a-f]{32}", md5) or                     not re.fullmatch(r"(0x)?[0-9a-fA-F]+", addr):
                raise HTTPException(status_code=400,
                                    detail="cfg/ast need md5 + addr")
            try:
                max_nodes = max(0, int(payload.get("max_nodes") or 0))
                max_depth = max(0, int(payload.get("max_depth") or 0))
            except (TypeError, ValueError) as exc:
                raise HTTPException(status_code=400,
                                    detail="cfg/ast: bad max_nodes/max_depth") from exc
            addr_n = hex(int(addr, 16))
            try:
                if op == "cfg":
                    cfg = graphext_runner.get_cfg(job_id, DATA_DIR, md5, addr_n)
                    return {"md5": md5, "addr": addr_n,
                            "cfg": _trim_cfg(cfg, max_nodes)}
                ast = graphext_runner.get_ast(job_id, DATA_DIR, md5, addr_n)
                return {"md5": md5, "addr": addr_n,
                        "ast": _trim_ast(ast, max_depth, max_nodes)}
            except KeyError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
        raise HTTPException(status_code=400,
                            detail=f"unknown op {op!r}; expected search|cypher|"
                                   "trace|snippet|dangerous|trace_flow|"
                                   "attack_surface|compose_evidence|"
                                   "routes|cfg|ast")
    except graph_query.CBMError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/jobs")
def list_jobs(principal: dict = Depends(require_token)):
    """Newest first. Admins see everything; plain users see their own jobs
    plus legacy owner-less ones (S3)."""
    with _jobs_lock:
        jobs = sorted(_jobs.values(), key=lambda j: j["created_at"], reverse=True)
        return [{
            "job_id": j["job_id"],
            "firmware": j["firmware"],
            "status": j["status"],
            "error": j["error"],
            "failed_from": j.get("failed_from"),
            "created_at": j["created_at"],
            "updated_at": j["updated_at"],
            "auto": bool(j.get("auto")),
            "profile": j.get("profile") or analysis_profiles.DEFAULT,
            "hunt_session_id": j.get("hunt_session_id"),
            "owner": j.get("owner"),
            "task": j.get("task") or "",
        } for j in jobs if _can_access(principal, j.get("owner"))]


@app.get("/jobs/{job_id}", dependencies=[Depends(job_guard)])
def get_job(job_id: str):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return {
        **{k: job[k] for k in ("job_id", "firmware", "status", "error",
                               "created_at", "updated_at", "size_bytes")},
        "failed_from": job.get("failed_from"),
        "auto": bool(job.get("auto")),
        "profile": job.get("profile") or analysis_profiles.DEFAULT,
        "owner": job.get("owner"),
        "hunt_session_id": job.get("hunt_session_id"),
        "task": job.get("task") or "",
        "log_tail": _log_tail(job_id),
        "manifest_summary": _manifest_summary(job_id),
    }


# CSI / OSC / 2-byte ESC；EMBA 日志带颜色时浏览器会显示成乱码。
_ANSI_RE = re.compile(
    r"\x1b(?:[@-Z\\-_a-z]|\][^\x07\x1b]*(?:\x07|\x1b\\)?|\[[0-?]*[ -/]*[@-~])"
)
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_DOCKER_ID_RE = re.compile(r"\b[0-9a-f]{64}\b")
_TODO_HEAD_RE = re.compile(r"personal todo list", re.I)
_DASH_LINE_RE = re.compile(r"^[\s\-─═—_]+$")


def _clean_log_lines(text: str) -> list[str]:
    """Strip ANSI/control chars, keep the latest \\r progress frame, drop EMBA todo spam."""
    out: list[str] = []
    skip_todo = False
    skipped_modules = 0
    for raw in str(text or "").split("\n"):
        if "\r" in raw:
            raw = raw.split("\r")[-1]
        line = _ANSI_RE.sub("", raw)
        line = _CTRL_RE.sub("", line)
        line = _DOCKER_ID_RE.sub(lambda m: m.group(0)[:12] + "…", line)
        line = line.replace("\ufffd", "").rstrip()
        if _TODO_HEAD_RE.search(line):
            skip_todo = True
            continue
        if skip_todo:
            if _DASH_LINE_RE.match(line.strip()):
                skip_todo = False
            continue
        if line.strip().startswith("Blacklisted module:"):
            skipped_modules += 1
            continue
        if skipped_modules:
            out.append(f"[*] 已按策略跳过 {skipped_modules} 个模块")
            skipped_modules = 0
        if not line.strip():
            if out and out[-1] != "":
                out.append("")
            continue
        if out and out[-1] == line:
            continue
        out.append(line)
    if skipped_modules:
        out.append(f"[*] 已按策略跳过 {skipped_modules} 个模块")
    while out and out[-1] == "":
        out.pop()
    return out


def _tail_text(path: Path, max_bytes: int = 65536) -> list[str]:
    if not path.is_file():
        return []
    with open(path, "rb") as fh:
        fh.seek(0, 2)
        size = fh.tell()
        fh.seek(max(0, size - max_bytes))
        blob = fh.read().decode("utf-8", errors="replace")
    return _clean_log_lines(blob)


@app.get("/jobs/{job_id}/logs", dependencies=[Depends(require_token), Depends(job_guard)])
def get_job_logs(job_id: str, lines: int = 300):
    """Combined pipeline log for the events tab (EMBA + decompile errors)."""
    try:
        cap = max(20, min(int(lines), 2000))
    except (TypeError, ValueError):
        cap = 300
    out: list[str] = []
    out.extend(_tail_text(EXTRACTED_DIR / f"{job_id}.emba.log"))
    inner = EXTRACTED_DIR / job_id / "emba.log"
    if inner.is_file():
        out.extend(_tail_text(inner, 32768))
    summary = PSEUDOCODE_DIR / job_id / "decompile_summary.json"
    if summary.is_file():
        try:
            data = json.loads(summary.read_text(encoding="utf-8"))
            out.append(
                f"[decompile] total={data.get('total_binaries')} "
                f"ok={data.get('succeeded')} fail={data.get('failed')}"
            )
            for row in data.get("binaries") or []:
                if row.get("status") != "ok":
                    out.append(
                        f"[decompile] {row.get('path')}: "
                        f"{row.get('status')} {row.get('error') or ''}"
                    )
        except (OSError, json.JSONDecodeError):
            pass
    job = _jobs.get(job_id) or {}
    merged: list[str] = []
    for line in out:
        if merged and merged[-1] == line:
            continue
        merged.append(line)
    return {
        "job_id": job_id,
        "status": job.get("status"),
        "error": job.get("error"),
        "hunt_session_id": job.get("hunt_session_id"),
        "lines": merged[-cap:],
    }


# data/<dir>/<job_id> trees owned by a job; removed by DELETE /jobs/{job_id}.
# ("decompile"/"idb" have no module-level constant; resolved from DATA_DIR.)
_JOB_DATA_DIR_NAMES = ("decompile", "idb")


def _job_artifact_dirs(job_id: str) -> list:
    return [
        FIRMWARE_DIR / job_id, EXTRACTED_DIR / job_id, PSEUDOCODE_DIR / job_id,
        CBM_DIR / job_id, TRACES_DIR / job_id, ATTACK_DIR / job_id,
        ROUTES_DIR / job_id, INPUTS_DIR / job_id, FUZZ_DIR / job_id,
        EXEC_DIR / job_id, FRIDA_DIR / job_id, GRAPHEXT_DIR / job_id,
        SURFACES_DIR / job_id, DATA_DIR / "decrypt" / job_id,
        *[DATA_DIR / name / job_id for name in _JOB_DATA_DIR_NAMES],
    ]


@app.delete("/jobs/{job_id}", dependencies=[Depends(job_guard)])
def delete_job(job_id: str, principal: dict = Depends(require_token)):
    """Remove a job and every artifact it owns (M5). Owner or admin only
    (job_guard); a running job must settle first (409)."""
    job = _jobs.get(job_id)
    if job is None:  # unreachable once job_guard ran; kept for direct calls
        raise HTTPException(status_code=404, detail="job not found")
    if job.get("status") in STATUS_RUNNING:
        raise HTTPException(
            status_code=409,
            detail=f"任务正在运行（{job['status']}），请等待结束后再删除")
    for path in _job_artifact_dirs(job_id):
        shutil.rmtree(path, ignore_errors=True)
    try:
        (EXTRACTED_DIR / f"{job_id}.emba.log").unlink(missing_ok=True)
    except OSError:
        pass
    # the CBM index db lives outside data/ (~/.cache/codebase-memory-mcp)
    try:
        db = graph_ingest.db_path(graph_ingest.project_name(job_id))
        for suffix in ("", "-wal", "-shm"):
            Path(f"{db}{suffix}").unlink(missing_ok=True)
    except OSError:
        pass
    with _jobs_lock:
        _jobs.pop(job_id, None)
    accounts.audit(principal["username"], "job_delete", job_id)
    return {"job_id": job_id, "deleted": True}


@app.get("/jobs/{job_id}/manifest", dependencies=[Depends(require_token), Depends(job_guard)])
def get_manifest(job_id: str):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    manifest_file = EXTRACTED_DIR / job_id / "manifest.json"
    if not manifest_file.is_file():
        raise HTTPException(status_code=404, detail=f"manifest not ready (status: {job['status']})")
    return json.loads(manifest_file.read_text(encoding="utf-8"))


_MD5_RE = re.compile(r"^[0-9a-f]{32}$")
_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]+$")

# Fields the M5 functions page needs; heavy fields (calls/strings) are dropped.
_FUNCTION_FIELDS = ("addr", "name", "size", "lines", "tags", "is_exported",
                    "decompile_ok", "rule_name", "rule_confidence",
                    "ai_name", "ai_confidence", "ai_reason",
                    "libc_equiv", "domain", "asrc", "asink", "on_attack_path",
                    "path_ids", "observed_in_trace",
                    "verified_reachable", "trace_ids")


@app.get("/jobs/{job_id}/functions", dependencies=[Depends(require_token), Depends(job_guard)])
def list_functions(job_id: str, q: str | None = None,
                   limit: int | None = Query(default=None, ge=1, le=800)):
    """Flattened symbols.json for the web UI functions page (M5)."""
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    symbols_file = PSEUDOCODE_DIR / job_id / "symbols.json"
    if not symbols_file.is_file():
        raise HTTPException(status_code=404,
                            detail="job not decompiled yet (no symbols.json)")
    symbols = json.loads(symbols_file.read_text(encoding="utf-8"))
    binaries = {}
    functions = []
    needle = (q or "").strip().lower()
    for md5, info in symbols.get("binaries", {}).items():
        binaries[md5] = {k: info.get(k) for k in
                         ("path", "arch", "bits", "endianness")}
        for fn in info.get("functions", []):
            if needle:
                blob = " ".join([
                    str(fn.get("name") or ""),
                    str(fn.get("ai_name") or ""),
                    " ".join(str(s) for s in (fn.get("strings") or [])[:24]),
                    " ".join(str(t) for t in (fn.get("tags") or [])),
                ]).lower()
                if needle not in blob:
                    continue
            row = {k: fn.get(k) for k in _FUNCTION_FIELDS}
            row["binary"] = md5
            row["arch"] = info.get("arch")
            if needle:
                row["strings"] = list(fn.get("strings") or [])[:8]
            functions.append(row)
    total = len(functions)
    if limit is not None:
        functions = functions[:limit]
    return {"job_id": job_id, "binaries": binaries,
            "total": total, "functions": functions}


@app.get("/jobs/{job_id}/functions/{md5}/{addr}/source",
         dependencies=[Depends(require_token), Depends(job_guard)])
def get_function_source(job_id: str, md5: str, addr: str, asm: int = 0):
    """Decompiled pseudo-C for one function (M5 functions page viewer).

    Default is the original Hex-Rays output, which is never modified.
    asm=1 returns the function-level assembly (functions/<addr>.asm) —
    the ground truth for call-site argument recovery when Hex-Rays
    collapses arguments."""
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    if not _MD5_RE.match(md5) or not _ADDR_RE.match(addr):
        raise HTTPException(status_code=400, detail="bad md5/addr format")
    if asm:
        asm_file = PSEUDOCODE_DIR / job_id / md5 / "functions" / f"{addr}.asm"
        if not asm_file.is_file():
            asm_file = PSEUDOCODE_DIR / job_id / md5 / "functions" / f"{addr.lower()}.asm"
        if not asm_file.is_file():
            raise HTTPException(status_code=404,
                                detail="no assembly export for this function")
        return PlainTextResponse(asm_file.read_text(encoding="utf-8",
                                                    errors="replace"))
    funcs_dir = PSEUDOCODE_DIR / job_id / md5 / "functions"
    src_file = funcs_dir / f"{addr}.c"
    if not src_file.is_file():
        src_file = funcs_dir / f"{addr.lower()}.c"
    if not src_file.is_file():
        raise HTTPException(status_code=404, detail="function source not found")
    return PlainTextResponse(src_file.read_text(encoding="utf-8",
                                                errors="replace"))


# Cheap call-target scan for the brief endpoint: dangerous libc + generic
# call-site regex, both intentionally heuristic (triage aid, not evidence).
_DANGEROUS_CALLS = (
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "system", "popen",
    "execve", "execlp", "execvp", "memcpy", "memmove", "strncpy", "strncat",
    "sscanf", "scanf", "recv", "recvfrom", "read", "mktemp", "realpath",
)
_CALL_NAME_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")


@app.get("/jobs/{job_id}/functions/{md5}/{addr}/brief",
         dependencies=[Depends(require_token), Depends(job_guard)])
def get_function_brief(job_id: str, md5: str, addr: str):
    """Compact function triage card (~1-2KB instead of full pseudo-C):
    attack-surface metadata from symbols.json + pseudocode head + dangerous
    call lines + callees. The upstream AI screens with this first and only
    pulls /source for suspicious functions — the context-budget fix (P2)."""
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    if not _MD5_RE.match(md5) or not _ADDR_RE.match(addr):
        raise HTTPException(status_code=400, detail="bad md5/addr format")
    symbols_file = PSEUDOCODE_DIR / job_id / "symbols.json"
    if not symbols_file.is_file():
        raise HTTPException(status_code=404,
                            detail="job not decompiled yet (no symbols.json)")
    symbols = json.loads(symbols_file.read_text(encoding="utf-8"))
    info = (symbols.get("binaries") or {}).get(md5)
    if info is None:
        raise HTTPException(status_code=404, detail="binary not in symbols")
    want = int(addr, 16)
    fn = None
    for cand in info.get("functions", []):
        try:
            if int(str(cand.get("addr", "0")), 16) == want:
                fn = cand
                break
        except ValueError:
            continue
    if fn is None:
        raise HTTPException(status_code=404, detail="function not found")

    src_file = PSEUDOCODE_DIR / job_id / md5 / "functions" / f"{fn['addr']}.c"
    if not src_file.is_file():
        src_file = (PSEUDOCODE_DIR / job_id / md5 / "functions"
                    / f"{str(fn['addr']).lower()}.c")
    source_available = src_file.is_file()
    head, dangerous, callees = [], [], []
    if source_available:
        lines = src_file.read_text(encoding="utf-8",
                                   errors="replace").splitlines()
        head = lines[:8]
        bin_names = {f.get("name") for f in info.get("functions", [])}
        seen = set()
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            low = stripped.lower()
            if len(dangerous) < 12 and any(
                    f"{d}(" in low for d in _DANGEROUS_CALLS):
                dangerous.append({"line": lineno, "text": stripped[:160]})
            if len(callees) < 20:
                for name in _CALL_NAME_RE.findall(stripped):
                    if (name in bin_names and name != fn.get("name")
                            and name not in seen):
                        seen.add(name)
                        callees.append(name)
    return {
        "job_id": job_id, "md5": md5, "addr": fn.get("addr"),
        "evidence_address": ev.make_address(md5, fn.get("addr"), job_id=job_id),
        "binary_path": info.get("path"), "arch": info.get("arch"),
        "name": fn.get("name"), "ai_name": fn.get("ai_name"),
        "size": fn.get("size"), "lines": fn.get("lines"),
        "tags": fn.get("tags") or [], "domain": fn.get("domain"),
        "libc_equiv": fn.get("libc_equiv"),
        "asrc": fn.get("asrc") or [], "asink": fn.get("asink") or [],
        "on_attack_path": bool(fn.get("on_attack_path")),
        "path_ids": fn.get("path_ids") or [],
        "observed_in_trace": bool(fn.get("observed_in_trace")),
        "verified_reachable": bool(fn.get("verified_reachable")),
        "source_available": source_available,
        "decompile_gap": not source_available,
        "head": head, "dangerous_calls": dangerous, "callees": callees,
    }

# ---------------- 单二进制补挖能力（2026-09-23） ----------------
# 挖掘 agent 实测报告：未进代码图的产线 daemon（AX_UDPserver、csmanuds
# 等，ingest 截断预算挤出）无法静态分析；HNAP 动作表 off_4ED9B0 每项 +4
# 的鉴权字节在 .data 段，工具链读不到——"是否预认证"这个决定性字段只能
# 靠模拟环境碰运气。两个端点补齐：按 vaddr 直读任意段字节 + radare2
# 单二进制反编译（不打回全量 ingest，函数级按需拉取）。

_ELF_PHDR_CACHE: dict = {}


def _elf_loadable_segments(bin_path: Path):
    """ELF32/64 PT_LOAD 段表 [(vaddr, filesz, offset)]，进程内缓存。"""
    key = str(bin_path)
    segs = _ELF_PHDR_CACHE.get(key)
    if segs is not None:
        return segs
    segs = []
    try:
        import struct as _st
        head = bin_path.read_bytes()[:64]
        if len(head) < 52 or head[:4] != b"\x7fELF":
            raise ValueError("not ELF")
        is64, little = head[4] == 2, head[5] == 1
        end = "<" if little else ">"
        with open(bin_path, "rb") as fh:
            if is64:
                e_phoff = _st.unpack_from(end + "Q", head, 32)[0]
                e_phentsize = _st.unpack_from(end + "H", head, 54)[0]
                e_phnum = _st.unpack_from(end + "H", head, 56)[0]
            else:
                e_phoff = _st.unpack_from(end + "I", head, 28)[0]
                e_phentsize = _st.unpack_from(end + "H", head, 42)[0]
                e_phnum = _st.unpack_from(end + "H", head, 44)[0]
            fh.seek(e_phoff)
            raw = fh.read(e_phentsize * max(e_phnum, 0))
        for i in range(e_phnum):
            off = i * e_phentsize
            if is64:
                p_type = _st.unpack_from(end + "I", raw, off)[0]
                p_offset, p_vaddr = _st.unpack_from(end + "QQ", raw, off + 8)[:2]
                p_filesz = _st.unpack_from(end + "Q", raw, off + 32)[0]
            else:
                p_type, p_offset, p_vaddr, _pa, p_filesz = _st.unpack_from(
                    end + "IIIII", raw, off)
            if p_type == 1:  # PT_LOAD
                segs.append((p_vaddr, p_filesz, p_offset))
    except (OSError, ValueError, _st.error):
        segs = []
    _ELF_PHDR_CACHE[key] = segs
    return segs



def _resolve_fw_binary(job_id: str, md5: str = "", rel_path: str = "") -> Path:
    """md5 或固件内相对路径 → 解包树里的文件。两者都给时 md5 优先。

    根是 extracted/<job_id>/（manifest 的 path 字段就相对它，如
    firmware/binwalk_extracted/…/squashfs-root/bin/httpd）。"""
    root = EXTRACTED_DIR / job_id
    if md5 and _MD5_RE.match(md5):
        mf = EXTRACTED_DIR / job_id / "manifest.json"
        if mf.is_file():
            try:
                for b in json.loads(mf.read_text(encoding="utf-8")).get(
                        "binaries", []):
                    if b.get("md5") == md5:
                        return root / str(b.get("path", "")).lstrip("/")
            except (OSError, ValueError):
                pass
        raise HTTPException(status_code=404,
                            detail=f"md5 {md5} not in manifest")
    rp = str(rel_path or "").strip().lstrip("/")
    if not rp or ".." in rp.split("/"):
        raise HTTPException(status_code=400,
                            detail="需要 binary_md5 或安全的相对路径")
    return root / rp


@app.get("/jobs/{job_id}/read-bytes",
         dependencies=[Depends(require_token), Depends(job_guard)])
def read_bytes(job_id: str, vaddr: str, length: int = 32,
               binary_md5: str = "", path: str = ""):
    """按虚拟地址直读 ELF 任意段（.data/.rodata/.got…）原始字节。

    静态判定的最后一公里：鉴权开关、硬编码表项、动作函数指针等数据段
    内容无法从反编译源可靠恢复，此处按 PT_LOAD 换算文件偏移后读原文。
    返回 hex 与 ASCII 双视图。"""
    if not _ADDR_RE.match(vaddr or ""):
        raise HTTPException(status_code=400, detail="bad vaddr (0x…)")
    length = max(1, min(int(length), 512))
    bin_path = _resolve_fw_binary(job_id, binary_md5, path)
    if not bin_path.is_file():
        raise HTTPException(status_code=404,
                            detail=f"binary not found: {bin_path.name}")
    va = int(vaddr, 16)
    seg = next(((v, s, o) for v, s, o in _elf_loadable_segments(bin_path)
                if v <= va < v + s), None)
    if seg is None:
        raise HTTPException(
            status_code=404,
            detail=f"vaddr {vaddr} 不在任何 PT_LOAD 段（文件可能去段了）")
    _v, _sz, off = seg
    with open(bin_path, "rb") as fh:
        fh.seek(off + (va - _v))
        raw = fh.read(length)
    return {
        "job_id": job_id, "binary": bin_path.name,
        "binary_md5": binary_md5 or "", "path": path or "",
        "vaddr": vaddr, "length": len(raw),
        "hex": raw.hex(),
        "ascii": "".join(chr(c) if 32 <= c < 127 else "." for c in raw),
    }


_ASM_ADDR_RE = re.compile(r"^\s*([0-9a-f]+):\s", re.I)


def _asm_addr(line: str):
    """llvm-objdump 行地址（'  400b10:\taddiu …' → 0x400b10）。"""
    m = _ASM_ADDR_RE.match(line)
    try:
        return int(m.group(1), 16) if m else None
    except ValueError:
        return None


def _elf_entry(bin_path: Path) -> int:
    import struct as _st
    try:
        head = bin_path.read_bytes()[:24]
        if head[:4] != b"\x7fELF":
            return 0
        end = "<" if head[5] == 1 else ">"
        return _st.unpack_from(end + "I", head, 24)[0]
    except (OSError, _st.error):
        return 0

@app.post("/jobs/{job_id}/decompile-single",
          dependencies=[Depends(require_token), Depends(job_guard)])
def decompile_single(job_id: str, payload: dict = Body(...)):
    """未进代码图的 ELF：radare2 单独分析（函数清单 / 单函数伪 C）。

    不打回全量 ingest：无 function 参数返回函数清单（name/addr/size，
    上限 400 条）；带 function="0x…" 返回该函数 r2 伪 C（上限 64KB）。
    用于产线 daemon、被截断预算挤出图谱的二进制补挖。"""
    import subprocess as _sp
    bin_path = _resolve_fw_binary(
        job_id, str(payload.get("binary_md5") or ""),
        str(payload.get("path") or ""))
    if not bin_path.is_file():
        raise HTTPException(status_code=404,
                            detail=f"binary not found: {bin_path.name}")
    r2 = shutil.which("r2") or shutil.which("radare2")
    if not r2:
        raise HTTPException(status_code=503, detail="radare2 未安装")
    func = str(payload.get("function") or "").strip()
    if func and not _ADDR_RE.match(func):
        raise HTTPException(status_code=400, detail="bad function addr")
    cmd = [r2, "-q", "-e", "scr.color=0", "-e", "bin.relocs.apply=true",
           "-c", (f"s {func}; pdc" if func else "aa; aflj"),
           "--", str(bin_path)]
    try:
        proc = _sp.run(cmd, capture_output=True, text=True, timeout=90)
    except _sp.TimeoutExpired:
        raise HTTPException(status_code=504, detail="radare2 分析超时（90s）")
    if proc.returncode != 0:
        raise HTTPException(
            status_code=502,
            detail=f"radare2 失败: {proc.stderr.strip()[:300]}")
    out = proc.stdout or ""
    if func and out.strip():
        if len(out) > 64 * 1024:
            out = out[:64 * 1024] + "\n/* …truncated 64KB */"
        return PlainTextResponse(out)
    try:
        fns = json.loads(out.strip() or "[]")
    except ValueError:
        fns = []
    rows = [{"name": f.get("name") or f.get("realname") or "",
             "addr": hex(int(f.get("offset", 0))),
             "size": int(f.get("size", 0))} for f in fns if f.get("offset")]
    if rows:
        return {
            "job_id": job_id, "binary": bin_path.name,
            "path": payload.get("path"),
            "binary_md5": payload.get("binary_md5"), "engine": "radare2",
            "total": len(rows), "truncated": len(rows) > 400,
            "functions": rows[:400],
            "hint": "用 read-bytes 或 decompile-single(function=0x…) 深入。",
        }
    # r2 fallback（2026-09-23）：固件常见 no-section-header stripped ELF
    # 上 r2 不建 io 映射、aa 识别 0 函数；llvm-objdump 对大端 MIPS 又
    # 会把 ELF 头当指令扫出乱码。MIPS32 定长 4 字节无相位问题——
    # capstone 按 PT_LOAD 段+正确字节序定点反汇编：jal/bal 目标聚类
    # 出函数边界，产线 daemon 只有几 KB，asm 可直接读。
    try:
        import capstone as _cs
    except ImportError:
        return {
            "job_id": job_id, "binary": bin_path.name,
            "path": payload.get("path"),
            "binary_md5": payload.get("binary_md5"), "engine": "none",
            "total": 0, "truncated": False, "functions": [],
            "hint": "r2 未识别函数且 venv 未装 capstone；试 function=入口",
        }
    data = bin_path.read_bytes()
    head = data[:64]
    little = head[5] == 1
    md = _cs.Cs(_cs.CS_ARCH_MIPS,
                _cs.CS_MODE_MIPS32
                | (_cs.CS_MODE_LITTLE_ENDIAN if little
                   else _cs.CS_MODE_BIG_ENDIAN))
    segs = [s for s in _elf_loadable_segments(bin_path) if s[1] > 0]
    starts: set = set()
    entry = _elf_entry(bin_path)
    if entry:
        starts.add(entry)
    for vaddr, filesz, offset in segs:
        md.skipdata = True
        _start_va = max(vaddr, entry) if entry >= vaddr else vaddr
        _start_off = offset + (_start_va - vaddr)
        for ins in md.disasm(data[_start_off:offset + filesz], _start_va):
            mn = ins.mnemonic
            if mn in ("jal", "bal", "jalr") or mn.startswith("jal"):
                for op in ins.op_str.replace(",", " ").split():
                    if op.startswith("0x"):
                        try:
                            starts.add(int(op, 16) & ~3)
                        except ValueError:
                            pass
    ordered = sorted(a for a in starts
                     if any(v <= a < v + s for v, s, _o in segs))
    if func:
        lo = int(func, 16) & ~3
        lines = []
        for vaddr, filesz, offset in segs:
            if vaddr <= lo < vaddr + filesz:
                fo = offset + (lo - vaddr)
                for ins in md.disasm(data[fo:fo + 8192], lo):
                    lines.append(f"{ins.address:x}:\t{ins.mnemonic}"
                                 f"\t{ins.op_str}")
                    if ins.mnemonic == "jr" and "$ra" in ins.op_str:
                        break
                    if len(lines) >= 400:
                        break
                break
        return PlainTextResponse(
            "\n".join(lines) or "; no decodable instructions at addr")
    frows = []
    for i, a in enumerate(ordered):
        nxt = ordered[i + 1] if i + 1 < len(ordered) else a + 2048
        frows.append({"name": f"sub_{a:x}", "addr": hex(a),
                      "size": max(nxt - a, 16)})
    return {
        "job_id": job_id, "binary": bin_path.name,
        "path": payload.get("path"),
        "binary_md5": payload.get("binary_md5"), "engine": "capstone",
        "total": len(frows), "truncated": len(frows) > 400,
        "functions": frows[:400],
        "hint": ("近似函数边界（调用目标+入口聚类，无符号剥离件）。"
                 "function=0x… 取反汇编切片；数据段判定用 fw_read_bytes。"
                 if frows else "未聚类出函数；直接 function=入口地址"),
    }


def _decrypt_view(job: dict, peek: bool = False) -> dict:
    job_id = job["job_id"]
    stored = fwdecrypt.load_report(DATA_DIR / "decrypt" / job_id)
    if stored:
        stored["job_status"] = job.get("status")
        stored["firmware"] = stored.get("firmware") or job.get("firmware") or ""
        return stored
    if job.get("status") == "decrypting":
        stub = fwdecrypt.empty_report(job_id, job.get("firmware") or "")
        stub["status"] = "running"
        stub["progress"] = 12
        stub["stage"] = "read"
        stub["stage_label"] = "正在解密"
        stub["job_status"] = "decrypting"
        return stub
    if peek:
        fw_path = FIRMWARE_DIR / job_id / "firmware.bin"
        peeked = fwdecrypt.peek(job_id, job.get("firmware") or "", fw_path)
        peeked["job_status"] = job.get("status")
        return peeked
    stub = fwdecrypt.empty_report(job_id, job.get("firmware") or "")
    stub["job_status"] = job.get("status")
    return stub


@app.get("/decrypt", dependencies=[Depends(require_token)])
def list_decrypt(principal: dict = Depends(require_token)):
    """Decrypt progress for every firmware the caller can see."""
    items = []
    with _jobs_lock:
        jobs = sorted(_jobs.values(),
                      key=lambda j: j.get("updated_at") or "", reverse=True)
    for job in jobs:
        if not _can_access(principal, job.get("owner")):
            continue
        items.append(_decrypt_view(job, peek=False))
    running = [i for i in items if i.get("status") == "running"
               or i.get("job_status") == "decrypting"]
    summary = {
        "total": len(items),
        "running": len(running),
        "decrypted": sum(1 for i in items if i.get("status") == "decrypted"),
        "plain": sum(1 for i in items if i.get("status") == "plain"),
        "identified": sum(1 for i in items if i.get("status") == "identified"),
        "failed": sum(1 for i in items if i.get("status") == "failed"),
    }
    return {"summary": summary, "running": running, "items": items}


@app.get("/jobs/{job_id}/decrypt",
         dependencies=[Depends(require_token), Depends(job_guard)])
def get_job_decrypt(job_id: str):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return _decrypt_view(job, peek=True)


# ---------------------------------------------------------------------------
# Protocol reverse (firmware artifacts + user-pasted traffic only)
# ---------------------------------------------------------------------------


@app.post("/protocol/decode", dependencies=[Depends(require_token)])
def protocol_decode(payload: dict = Body(...)):
    """Decode a user-pasted hex/Base64 slice. No live capture, no decrypt."""
    text = str(payload.get("text") or payload.get("hex") or "")
    try:
        data = protocol_reverse.parse_payload(text)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return protocol_reverse.decode_traffic(data)


@app.get("/jobs/{job_id}/protocol-reverse",
         dependencies=[Depends(require_token), Depends(job_guard)])
def get_protocol_reverse(job_id: str):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return protocol_reverse.build_report_from_disk(
        job_id, DATA_DIR, firmware=str(job.get("firmware") or ""))


@app.get("/jobs/{job_id}/protocol-reverse/functions/{md5}/{addr}",
         dependencies=[Depends(require_token), Depends(job_guard)])
def get_protocol_reverse_function(job_id: str, md5: str, addr: str):
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail="job not found")
    if not _MD5_RE.match(md5) or not _ADDR_RE.match(addr):
        raise HTTPException(status_code=400, detail="bad md5/addr format")
    out = protocol_reverse.reverse_from_disk(job_id, DATA_DIR, md5, addr)
    if out is None:
        raise HTTPException(status_code=404, detail="function not found")
    return out


# Upstream vuln-mining agent API (Managed Agents harness in <repo>/vulnagent/).
# Registered after the job/graph APIs, before the SPA catch-all.
vulnagent_api.setup(app, require_token)
from orchestrator.app import emulagent_api  # noqa: E402
emulagent_api.setup(app, require_token)
from orchestrator.app import llm_settings  # noqa: E402
llm_settings.setup(app, require_token)

# Admin console: auth/users/system/logs/dashboard/reports/auto-chain.
# Also registered before the SPA catch-all.
admin_api.setup(app, require_token, require_admin)

# Local CVE/CNVD knowledge base + N-day lookup against firmware jobs.
vulnlib_api.setup(app, require_token, require_admin)

# M-ICS: protocol fuzzing (live-device / emulated target). Before webui too.
protofuzz_api.setup(app, require_token)
# M5: CBM UI reverse proxy (/cbmui, /api, /rpc) + SPA static hosting at "/".
# Registered last so every API route above wins over the catch-alls.
webui.setup(app)
