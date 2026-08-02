"""FastAPI orchestrator for the fwgraph unpack + decompile subsystems.

Endpoints:
  POST /firmware                  upload firmware (multipart), start extraction
  POST /jobs/{job_id}/decompile   (re)run headless IDA decompilation (M2)
  POST /jobs/{job_id}/ailift      run AI symbol recovery + renaming (M3)
  GET  /jobs/{job_id}/ailift      M3 funnel/registry/llm-usage stats + samples
  POST /jobs/{job_id}/graph       build the CBM code graph (M4)
  GET  /jobs/{job_id}/graph       M4 graph_done.json summary
  POST /jobs/{job_id}/trace       M7 qemu-user differential coverage trace
  GET  /jobs/{job_id}/traces      M7 trace list (summaries)
  GET  /jobs/{job_id}/traces/{trace_id}  M7 full trace.json
  POST /graph/query               graph检索 entry point for the vuln-hunting AI:
                                  {job_id, op: search|cypher|trace|snippet|
                                   dangerous|trace_flow, ...}
  GET  /jobs                      list all jobs (newest first)
  GET  /jobs/{job_id}             job status + log tail + manifest summary
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
decompiled -> ailifting -> ailifted -> graphing -> graphed (decompiling starts
automatically after extraction unless AUTO_DECOMPILE=0; any failure ends in
"failed").
"""

import json
import os
import re
import shutil
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import Body, Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import decompiler, extractor, webui
from pipeline.ailift import registry as ailift_registry
from pipeline.ailift import runner as ailift_runner
from pipeline.attack import runner as attack_runner
from pipeline.graph import ingest as graph_ingest
from pipeline.graph import query as graph_query
from pipeline.routes import runner as route_runner
from pipeline.extract import px4 as px4_extractor
from pipeline.trace import tracer

# fwgraph/orchestrator/app/main.py -> ../../.. = fwgraph/
FWGRAPH_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(FWGRAPH_ROOT / ".env")

DATA_DIR = Path(os.getenv("FWGRAPH_DATA", str(FWGRAPH_ROOT / "data")))
FIRMWARE_DIR = DATA_DIR / "firmware"
EXTRACTED_DIR = DATA_DIR / "extracted"
PSEUDOCODE_DIR = DATA_DIR / "pseudocode"
CBM_DIR = DATA_DIR / "cbm"
TRACES_DIR = DATA_DIR / "traces"
ATTACK_DIR = DATA_DIR / "attack"
ROUTES_DIR = DATA_DIR / "routes"

STATUS_RUNNING = {"pending", "extracting", "parsing", "decompiling",
                  "ailifting", "graphing", "attacking", "routing"}
LOG_TAIL_LINES = 30

app = FastAPI(title="fwgraph orchestrator", version="0.1.0")

_security = HTTPBearer(auto_error=False)
_jobs: dict = {}
_jobs_lock = threading.Lock()


def require_token(cred: HTTPAuthorizationCredentials | None = Depends(_security)):
    token = os.getenv("ORCH_TOKEN", "")
    if not token:
        return  # no token configured -> dev mode, auth disabled
    if cred is None or cred.credentials != token:
        raise HTTPException(status_code=401, detail="invalid or missing bearer token")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _job_path(job_id: str) -> Path:
    return FIRMWARE_DIR / job_id / "job.json"


def _save_job(job: dict):
    job["updated_at"] = _now()
    path = _job_path(job["job_id"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(job, indent=2), encoding="utf-8")


def _set_status(job: dict, status: str, error: str | None = None):
    with _jobs_lock:
        job["status"] = status
        job["error"] = error
        _save_job(job)


def _load_jobs():
    """Load persisted jobs; anything left running by a previous instance is
    marked failed (EMBA itself is gone after a restart)."""
    if not FIRMWARE_DIR.is_dir():
        return
    for job_file in sorted(FIRMWARE_DIR.glob("*/job.json")):
        try:
            job = json.loads(job_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if job.get("status") in STATUS_RUNNING:
            job["status"] = "failed"
            job["error"] = "interrupted by service restart"
            job["updated_at"] = _now()
            job_file.write_text(json.dumps(job, indent=2), encoding="utf-8")
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


def _decompile_worker(job_id: str):
    job = _jobs[job_id]
    try:
        _set_status(job, "decompiling")
        summary = decompiler.run_job(job_id, DATA_DIR)
        if summary["succeeded"] > 0:
            _set_status(job, "decompiled")
        else:
            _set_status(job, "failed",
                         "decompilation failed for all binaries "
                         "(see decompile_summary.json)")
    except Exception as exc:  # noqa: BLE001 - any failure must end as 'failed'
        _set_status(job, "failed", f"decompile: {type(exc).__name__}: {exc}")


def _ailift_worker(job_id: str):
    job = _jobs[job_id]
    try:
        _set_status(job, "ailifting")
        ailift_runner.run_job(job_id, DATA_DIR)
        _set_status(job, "ailifted")
    except Exception as exc:  # noqa: BLE001 - any failure must end as 'failed'
        _set_status(job, "failed", f"ailift: {type(exc).__name__}: {exc}")


def _graph_worker(job_id: str):
    job = _jobs[job_id]
    try:
        _set_status(job, "graphing")
        graph_ingest.run_job(job_id, DATA_DIR)
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
        _set_status(job, "done")
    except Exception as exc:  # noqa: BLE001 - any failure must end as 'failed'
        _set_status(job, "failed", f"{type(exc).__name__}: {exc}")
        return
    if os.getenv("AUTO_DECOMPILE", "1") != "0":
        _decompile_worker(job_id)


@app.on_event("startup")
def startup():
    FIRMWARE_DIR.mkdir(parents=True, exist_ok=True)
    EXTRACTED_DIR.mkdir(parents=True, exist_ok=True)
    _load_jobs()


@app.get("/healthz")
def healthz():
    return {"status": "ok", "jobs": len(_jobs)}


@app.post("/firmware", status_code=201, dependencies=[Depends(require_token)])
def upload_firmware(file: UploadFile = File(...)):
    job_id = uuid.uuid4().hex[:12]
    job_dir = FIRMWARE_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    fw_path = job_dir / "firmware.bin"
    with open(fw_path, "wb") as fh:
        shutil.copyfileobj(file.file, fh)

    job = {
        "job_id": job_id,
        "firmware": file.filename or "firmware.bin",
        "status": "pending",
        "error": None,
        "created_at": _now(),
        "updated_at": _now(),
        "firmware_path": str(fw_path),
        "log_dir": str(EXTRACTED_DIR / job_id),
        "size_bytes": fw_path.stat().st_size,
    }
    with _jobs_lock:
        _jobs[job_id] = job
        _save_job(job)
    threading.Thread(target=_extract_worker, args=(job_id,), daemon=True).start()
    return {"job_id": job_id, "status": "pending"}


@app.post("/jobs/{job_id}/decompile", status_code=202, dependencies=[Depends(require_token)])
def trigger_decompile(job_id: str):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    with _jobs_lock:
        if job["status"] in STATUS_RUNNING:
            raise HTTPException(status_code=409,
                                detail=f"job is {job['status']}, wait for it to finish")
        if not (EXTRACTED_DIR / job_id / "manifest.json").is_file():
            raise HTTPException(status_code=409,
                                detail="extraction not complete (no manifest.json)")
        job["status"] = "decompiling"
        job["error"] = None
        _save_job(job)
    threading.Thread(target=_decompile_worker, args=(job_id,), daemon=True).start()
    return {"job_id": job_id, "status": "decompiling"}


@app.post("/jobs/{job_id}/ailift", status_code=202, dependencies=[Depends(require_token)])
def trigger_ailift(job_id: str):
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
        job["status"] = "ailifting"
        job["error"] = None
        _save_job(job)
    threading.Thread(target=_ailift_worker, args=(job_id,), daemon=True).start()
    return {"job_id": job_id, "status": "ailifting"}


@app.get("/jobs/{job_id}/ailift", dependencies=[Depends(require_token)])
def get_ailift(job_id: str):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    pseudo_root = PSEUDOCODE_DIR / job_id
    summary_file = pseudo_root / "ailift_summary.json"
    if not summary_file.is_file() and job["status"] != "ailifting":
        raise HTTPException(status_code=404, detail="ailift not run yet")
    out = {"job_id": job_id, "status": job["status"], "error": job["error"]}
    if summary_file.is_file():
        out["summary"] = json.loads(summary_file.read_text(encoding="utf-8"))
    reg = ailift_registry.dumps_stats(pseudo_root / "name_registry.db")
    if reg:
        out["registry"] = reg["stats"]
        out["tag_samples"] = reg["samples"]
    usage_file = pseudo_root / "llm_usage.json"
    if usage_file.is_file():
        out["llm_usage"] = json.loads(usage_file.read_text(encoding="utf-8"))
    return out


@app.post("/jobs/{job_id}/graph", status_code=202, dependencies=[Depends(require_token)])
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


@app.get("/jobs/{job_id}/graph", dependencies=[Depends(require_token)])
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


@app.post("/jobs/{job_id}/attack", status_code=202,
          dependencies=[Depends(require_token)])
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


@app.get("/jobs/{job_id}/attack", dependencies=[Depends(require_token)])
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


@app.post("/jobs/{job_id}/routes", status_code=202,
          dependencies=[Depends(require_token)])
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
        if not (DATA_DIR / "idb" / job_id).is_dir():
            raise HTTPException(status_code=409, detail="job has no reusable IDB")
        job["status"] = "routing"
        job["error"] = None
        _save_job(job)
    threading.Thread(target=_route_worker, args=(job_id,), daemon=True).start()
    return {"job_id": job_id, "status": "routing"}


@app.get("/jobs/{job_id}/routes", dependencies=[Depends(require_token)])
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
# M7: qemu-user differential coverage traces
# ---------------------------------------------------------------------------

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
        "baseline_functions": (trace.get("baseline") or {}).get("functions"),
        "trigger_functions": (trace.get("trigger") or {}).get("functions"),
        "diff_functions": (trace.get("diff") or {}).get("function_count"),
    }


@app.post("/jobs/{job_id}/trace", status_code=202,
          dependencies=[Depends(require_token)])
def trigger_trace(job_id: str, payload: dict = Body(...)):
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
    if not TRACE_LOCK.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="another trace is running")
    trace_id = tracer.new_trace_id()
    req = {"binary_md5": md5, "argv": argv, "port": port,
           "request_path": payload.get("request_path"),
           "argv0": payload.get("argv0")}
    threading.Thread(target=_trace_worker, args=(job_id, trace_id, req),
                     daemon=True).start()
    return {"job_id": job_id, "trace_id": trace_id, "status": "running"}


@app.get("/jobs/{job_id}/traces", dependencies=[Depends(require_token)])
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
         dependencies=[Depends(require_token)])
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
    return {
        "job_id": job_id, "trace_id": trace_id, "status": trace.get("status"),
        "binary": trace.get("binary"), "argv": trace.get("argv"),
        "request": trace.get("request"),
        "function_count": len(sequence), "sequence": sequence,
        "dangerous_count": len(dangerous), "dangerous": dangerous,
    }


def _attack_surface(job_id: str, payload: dict):
    """Return ranked, precomputed attack paths with optional filters."""
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
        paths.append(path)
        if len(paths) >= limit:
            break
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


@app.post("/graph/query", dependencies=[Depends(require_token)])
def graph_query_endpoint(payload: dict = Body(...)):
    """Graph检索 proxy for the upstream vuln-hunting AI.

    Body: {"job_id": ..., "op": "search"|"cypher"|"trace"|"snippet"|
           "dangerous"|"trace_flow"|"attack_surface"|"routes",
           ...op-specific args}
      search:    pattern (required), label?, limit?
      cypher:    query (required) — raw Cypher against the CBM subset
      trace:     name (required), direction? (both|inbound|outbound)
      snippet:   name (required) — resolves to qualified_name internally
      dangerous: functions? (defaults to query.DEFAULT_DANGEROUS), limit?
      trace_flow: trace_id (required) — M7: ordered request-handling path
                 of one coverage trace + dangerous libc_equiv highlights
      attack_surface: source?, sink?, verified_only?, limit? — ranked paths
      routes: pattern?, method?, binary_md5?, min_confidence?, limit?
    """
    job_id = payload.get("job_id")
    if not job_id or job_id not in _jobs:
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
            q = payload.get("query")
            if not q:
                raise HTTPException(status_code=400,
                                    detail="cypher: 'query' required")
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
        if op == "routes":
            return _routes(job_id, payload)
        raise HTTPException(status_code=400,
                            detail=f"unknown op {op!r}; expected search|cypher|"
                                   "trace|snippet|dangerous|trace_flow|"
                                   "attack_surface|routes")
    except graph_query.CBMError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/jobs", dependencies=[Depends(require_token)])
def list_jobs():
    with _jobs_lock:
        jobs = sorted(_jobs.values(), key=lambda j: j["created_at"], reverse=True)
        return [{
            "job_id": j["job_id"],
            "firmware": j["firmware"],
            "status": j["status"],
            "error": j["error"],
            "created_at": j["created_at"],
            "updated_at": j["updated_at"],
        } for j in jobs]


@app.get("/jobs/{job_id}", dependencies=[Depends(require_token)])
def get_job(job_id: str):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return {
        **{k: job[k] for k in ("job_id", "firmware", "status", "error",
                               "created_at", "updated_at", "size_bytes")},
        "log_tail": _log_tail(job_id),
        "manifest_summary": _manifest_summary(job_id),
    }


@app.get("/jobs/{job_id}/manifest", dependencies=[Depends(require_token)])
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


@app.get("/jobs/{job_id}/functions", dependencies=[Depends(require_token)])
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
         dependencies=[Depends(require_token)])
def get_function_source(job_id: str, md5: str, addr: str):
    """Decompiled pseudo-C for one function (M5 functions page viewer)."""
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    if not _MD5_RE.match(md5) or not _ADDR_RE.match(addr):
        raise HTTPException(status_code=400, detail="bad md5/addr format")
    funcs_dir = PSEUDOCODE_DIR / job_id / md5 / "functions"
    src_file = funcs_dir / f"{addr}.c"
    if not src_file.is_file():
        src_file = funcs_dir / f"{addr.lower()}.c"
    if not src_file.is_file():
        raise HTTPException(status_code=404, detail="function source not found")
    return PlainTextResponse(src_file.read_text(encoding="utf-8",
                                                errors="replace"))


# M5: CBM UI reverse proxy (/cbmui, /api, /rpc) + SPA static hosting at "/".
# Registered last so every API route above wins over the catch-alls.
webui.setup(app)
