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

Status machine: pending -> extracting -> parsing -> done -> decompiling ->
decompiled -> graphing -> graphed (decompiling starts automatically after
extraction unless AUTO_DECOMPILE=0; auto jobs continue decompiled -> graph
which chains attack/routes/surfaces; any failure ends in "failed").
"""

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
from fastapi import Body, Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import httpx

from . import accounts, admin_api, config, decompiler, extractor, protofuzz_api, vulnagent_api, webui
from pipeline import evidence as ev
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
from pipeline.extract import px4 as px4_extractor
from pipeline.trace import tracer

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
FRIDA_DIR = DATA_DIR / "frida"
GRAPHEXT_DIR = DATA_DIR / "graphext"
SURFACES_DIR = DATA_DIR / "surfaces"

STATUS_RUNNING = {"pending", "extracting", "parsing", "decompiling",
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


def _manifest_summary(job_id: str):
    manifest_file = EXTRACTED_DIR / job_id / "manifest.json"
    if not manifest_file.is_file():
        return None
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return manifest.get("stats")


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


def _extract_worker(job_id: str):
    job = _jobs[job_id]
    fw_path = FIRMWARE_DIR / job_id / "firmware.bin"
    log_dir = EXTRACTED_DIR / job_id
    emba_log = EXTRACTED_DIR / f"{job_id}.emba.log"
    try:
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
            if timed_out:
                _set_status(job, "failed", f"EMBA timeout after {extractor._cfg('EMBA_TIMEOUT', '7200')}s")
                return
            if rc != 0:
                _set_status(job, "failed", f"EMBA exited with code {rc} (see {emba_log.name})")
                return
            _set_status(job, "parsing")
            extractor.build_manifest(job_id, job["firmware"], log_dir)
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


@app.get("/jobs/{job_id}/identification", dependencies=[Depends(require_token), Depends(job_guard)])
def get_identification(job_id: str):
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail="job not found")
    doc = INPUTS_DIR / job_id / "identification.json"
    if not doc.is_file():
        raise HTTPException(status_code=404,
                            detail="identification.json not built yet")
    return json.loads(doc.read_text(encoding="utf-8"))


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
_FRIDA_RUN_RE = re.compile(r"^fs-[0-9a-f]{8}$")
_FUZZ_LOCK = threading.Lock()
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
    try:
        trace = tracer.run_trace(
            job_id, DATA_DIR, req["binary_md5"], req["argv"],
            port=req.get("port"), request_path=req.get("request_path"),
            trace_id=trace_id, cbm_project=project, argv0=req.get("argv0"))
        if str(trace.get("status") or "").startswith("ok") \
                and (ATTACK_DIR / job_id / "attack_paths.json").is_file():
            try:
                attack_runner.run_job(job_id, DATA_DIR)
            except Exception:
                pass  # trace remains authoritative; attack can be retried manually
    except Exception:  # noqa: BLE001 - run_trace persists its own failure
        pass
    finally:
        TRACE_LOCK.release()


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

    Body: {binary_md5, argv=[...], port?, request_path?, argv0?}. argv0
    forges the guest argv[0] via qemu -0 (busybox multicall binaries
    dispatch on argv[0]; a copy named busybox-arm needs argv0="busybox").
    The job's main status is untouched; trace status lives in trace.json
    (running -> ok | ok_empty_diff | failed). Typical wall time is
    2x(ready+hold) plus qemu overhead, well under 5 minutes
    (TRACE_RUN_TIMEOUT per run, default 60s).
    """
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    md5 = str(payload.get("binary_md5") or "")
    if not _MD5_RE.match(md5):
        raise HTTPException(status_code=400, detail="binary_md5 must be "
                            "a 32-char lowercase md5")
    argv = payload.get("argv")
    if not isinstance(argv, list) or not argv \
            or not all(isinstance(a, (str, int)) for a in argv):
        raise HTTPException(status_code=400,
                            detail="argv must be a non-empty list of strings")
    port = payload.get("port")
    if port is not None and not (isinstance(port, int)
                                 and 1 <= port <= 65535):
        raise HTTPException(status_code=400, detail="port must be 1..65535")
    manifest_file = EXTRACTED_DIR / job_id / "manifest.json"
    if not manifest_file.is_file():
        raise HTTPException(status_code=409,
                            detail="extraction not complete (no manifest.json)")
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    if not any(b.get("md5") == md5 for b in manifest.get("binaries", [])):
        raise HTTPException(status_code=404,
                            detail=f"binary {md5} not in manifest")
    if not (PSEUDOCODE_DIR / job_id / "symbols.json").is_file():
        raise HTTPException(status_code=409,
                            detail="job not decompiled yet (no symbols.json)")
    _check_quota(job_id, "trace")
    if not TRACE_LOCK.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="another trace is running")
    accounts.audit(principal["username"], "trace_trigger", job_id)
    trace_id = tracer.new_trace_id()
    req = {"binary_md5": md5, "argv": argv, "port": port,
           "request_path": payload.get("request_path"),
           "argv0": payload.get("argv0")}
    threading.Thread(target=_trace_worker, args=(job_id, trace_id, req),
                     daemon=True).start()
    return {"job_id": job_id, "trace_id": trace_id, "status": "running"}


@app.get("/jobs/{job_id}/traces", dependencies=[Depends(require_token), Depends(job_guard)])
def list_traces(job_id: str):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    root = TRACES_DIR / job_id
    traces = []
    if root.is_dir():
        for tf in root.glob("*/trace.json"):
            try:
                traces.append(_trace_summary(
                    json.loads(tf.read_text(encoding="utf-8"))))
            except (OSError, json.JSONDecodeError):
                continue
    traces.sort(key=lambda t: t.get("created_at") or "", reverse=True)
    return {"job_id": job_id, "total": len(traces), "traces": traces}


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
    return json.loads(trace_file.read_text(encoding="utf-8"))


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
            "created_at": j["created_at"],
            "updated_at": j["updated_at"],
            "auto": bool(j.get("auto")),
            "profile": j.get("profile") or analysis_profiles.DEFAULT,
            "hunt_session_id": j.get("hunt_session_id"),
            "owner": j.get("owner"),
        } for j in jobs if _can_access(principal, j.get("owner"))]


@app.get("/jobs/{job_id}", dependencies=[Depends(job_guard)])
def get_job(job_id: str):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return {
        **{k: job[k] for k in ("job_id", "firmware", "status", "error",
                               "created_at", "updated_at", "size_bytes")},
        "auto": bool(job.get("auto")),
        "profile": job.get("profile") or analysis_profiles.DEFAULT,
        "owner": job.get("owner"),
        "hunt_session_id": job.get("hunt_session_id"),
        "log_tail": _log_tail(job_id),
        "manifest_summary": _manifest_summary(job_id),
    }


def _tail_text(path: Path, max_bytes: int = 65536) -> list[str]:
    if not path.is_file():
        return []
    with open(path, "rb") as fh:
        fh.seek(0, 2)
        size = fh.tell()
        fh.seek(max(0, size - max_bytes))
        return fh.read().decode("utf-8", errors="replace").splitlines()


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
    return {
        "job_id": job_id,
        "status": job.get("status"),
        "error": job.get("error"),
        "hunt_session_id": job.get("hunt_session_id"),
        "lines": out[-cap:],
    }


# data/<dir>/<job_id> trees owned by a job; removed by DELETE /jobs/{job_id}.
# ("decompile"/"idb" have no module-level constant; resolved from DATA_DIR.)
_JOB_DATA_DIR_NAMES = ("decompile", "idb")


def _job_artifact_dirs(job_id: str) -> list:
    return [
        FIRMWARE_DIR / job_id, EXTRACTED_DIR / job_id, PSEUDOCODE_DIR / job_id,
        CBM_DIR / job_id, TRACES_DIR / job_id, ATTACK_DIR / job_id,
        ROUTES_DIR / job_id, INPUTS_DIR / job_id, FUZZ_DIR / job_id,
        FRIDA_DIR / job_id, GRAPHEXT_DIR / job_id, SURFACES_DIR / job_id,
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
def list_functions(job_id: str):
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
    for md5, info in symbols.get("binaries", {}).items():
        binaries[md5] = {k: info.get(k) for k in
                         ("path", "arch", "bits", "endianness")}
        for fn in info.get("functions", []):
            row = {k: fn.get(k) for k in _FUNCTION_FIELDS}
            row["binary"] = md5
            row["arch"] = info.get("arch")
            functions.append(row)
    return {"job_id": job_id, "binaries": binaries,
            "total": len(functions), "functions": functions}


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


# Upstream vuln-mining agent API (Managed Agents harness in <repo>/vulnagent/).
# Registered after the job/graph APIs, before the SPA catch-all.
vulnagent_api.setup(app, require_token)

# Admin console: auth/users/system/logs/dashboard/reports/auto-chain.
# Also registered before the SPA catch-all.
admin_api.setup(app, require_token, require_admin)

# M-ICS: protocol fuzzing (live-device / emulated target). Before webui too.
protofuzz_api.setup(app, require_token)

# M5: CBM UI reverse proxy (/cbmui, /api, /rpc) + SPA static hosting at "/".
# Registered last so every API route above wins over the catch-alls.
webui.setup(app)
