"""M7 trace orchestration: baseline/trigger differential coverage.

run_trace() executes the same target twice under qemu-user coverage
(baseline: start -> ready -> hold -> kill; trigger: start -> ready -> one
request -> settle -> kill), maps both PC sets to symbols.json functions and
diffs them: trigger-only functions, in first-execution order, are the
request-handling path. The result is persisted to
data/traces/<job>/<trace_id>/trace.json (status running -> ok|failed, so
pollers see progress).

CBM 0.9.0 probe result: `cli ingest_traces` accepts {project, traces} but
answers {"traces_received":0,"note":"Runtime edge creation from traces not
yet implemented"} — a stub. We still POST the diff (recorded verbatim in
trace.json under cbm_ingest, future CBM versions may materialize it), but
the authoritative trace store is trace.json itself, exposed to the upstream
AI via the trace_flow graph-query op.

CLI: python -m pipeline.trace.tracer <job_id> <binary_md5> -- <argv...>
"""

import http.client
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from pipeline.graph import query as cbm
from pipeline.trace import mapper, qemu_cov

FWGRAPH_ROOT = Path(__file__).resolve().parents[2]

# libc_equiv values flagged as dangerous in trace_flow output.
TRACE_DANGEROUS = {"strcpy", "sprintf", "system", "popen", "execve"}


def _cfg(name, default):
    return os.getenv(name, default)


def _now():
    return datetime.now(timezone.utc).isoformat()


def new_trace_id() -> str:
    return uuid.uuid4().hex[:12]


def trace_dir(data_dir, job_id: str, trace_id: str) -> Path:
    return Path(data_dir) / "traces" / job_id / trace_id


def load_trace(data_dir, job_id: str, trace_id: str) -> dict:
    path = trace_dir(data_dir, job_id, trace_id) / "trace.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _write_trace(data_dir, job_id: str, trace_id: str, trace: dict):
    d = trace_dir(data_dir, job_id, trace_id)
    d.mkdir(parents=True, exist_ok=True)
    (d / "trace.json").write_text(json.dumps(trace, indent=2),
                                  encoding="utf-8")


def _http_trigger(port: int, request_path: str | None):
    """One request against the traced service; returns a small summary.

    A service can accept and process a request but close before producing a
    valid HTTP response. That is still useful execution evidence, so preserve
    the transport error in-band instead of discarding the coverage run.
    """
    if not request_path:
        # bare TCP connect/close — enough to exercise accept() paths
        import socket
        with socket.create_connection(("127.0.0.1", port), timeout=5):
            pass
        return {"kind": "tcp_connect", "port": port}
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", request_path)
        resp = conn.getresponse()
        body = resp.read(4096)
        return {"kind": "http_get", "path": request_path,
                "status": resp.status, "bytes": len(body)}
    except (OSError, http.client.HTTPException) as exc:
        return {"kind": "http_get", "path": request_path,
                "status": None, "bytes": 0,
                "error": f"{type(exc).__name__}: {exc}"}
    finally:
        conn.close()


def _successful_trace_status(diff, trigger_meta: dict) -> str:
    status = "ok" if diff else "ok_empty_diff"
    trigger_result = trigger_meta.get("trigger_result") or {}
    return f"{status}_trigger_error" if trigger_result.get("error") else status


def diff_functions(baseline_seq, trigger_seq):
    """trigger-only functions, preserving trigger execution order."""
    base_addrs = {f["addr"] for f in baseline_seq}
    return [f for f in trigger_seq if f["addr"] not in base_addrs]


def _find_binary(manifest: dict, md5: str) -> dict:
    for b in manifest.get("binaries", []):
        if b.get("md5") == md5:
            return b
    raise qemu_cov.QemuError(f"binary md5 {md5} not in manifest")


def _ingest_to_cbm(project: str, trace: dict) -> dict:
    """Best-effort hand-off to CBM ingest_traces; never fails the trace.

    CBM 0.9.0 implements this as an accepting stub (see module docstring),
    so the response is recorded, not relied upon.
    """
    if not project:
        return {"attempted": False, "reason": "job not graphed yet"}
    payload = [{
        "kind": "request_diff",
        "binary_md5": trace["binary"]["md5"],
        "argv": trace["argv"],
        "request": trace["request"],
        "functions": [{"addr": f["addr"],
                       "name": f.get("ai_name") or f.get("name"),
                       "libc_equiv": f.get("libc_equiv")}
                      for f in trace["diff"]["functions"]],
    }]
    try:
        resp = cbm.ingest_traces(project, payload, timeout=30)
        return {"attempted": True, "response": resp}
    except Exception as exc:  # noqa: BLE001 - best effort by design
        return {"attempted": True, "error": f"{type(exc).__name__}: {exc}"}


def run_trace(job_id: str, data_dir, binary_md5: str, argv,
              port: int | None = None, request_path: str | None = None,
              trace_id: str | None = None, cbm_project: str | None = None,
              argv0: str | None = None):
    """Run one differential trace and persist trace.json. Returns the trace."""
    data_dir = Path(data_dir)
    trace_id = trace_id or new_trace_id()
    run_timeout = float(_cfg("TRACE_RUN_TIMEOUT", "60"))
    hold = float(_cfg("TRACE_HOLD_SECONDS", "2"))
    t0 = time.time()
    trace = {
        "trace_id": trace_id, "job_id": job_id, "status": "running",
        "error": None, "created_at": _now(), "finished_at": None,
        "binary": {"md5": binary_md5}, "argv": list(argv), "argv0": argv0,
        "request": {"port": port, "path": request_path},
    }
    _write_trace(data_dir, job_id, trace_id, trace)
    try:
        manifest = json.loads(
            (data_dir / "extracted" / job_id / "manifest.json")
            .read_text(encoding="utf-8"))
        binary = _find_binary(manifest, binary_md5)
        trace["binary"] = binary
        symbols = json.loads(
            (data_dir / "pseudocode" / job_id / "symbols.json")
            .read_text(encoding="utf-8"))
        functions = symbols.get("binaries", {}).get(binary_md5, {}) \
            .get("functions", [])

        rootfs, path_in_rootfs = qemu_cov.find_rootfs(
            data_dir / "extracted" / job_id, binary["path"])
        qemu_name = qemu_cov.qemu_for(binary.get("arch"),
                                      binary.get("endianness"))
        qemu_in_rootfs = qemu_cov.prepare_rootfs(rootfs, qemu_name,
                                                 path_in_rootfs)
        linker = qemu_cov.inspect_dynamic_linker(rootfs, path_in_rootfs)
        sysroot_prefix = linker.get("sysroot")
        guest_argv = [path_in_rootfs, *[str(a) for a in argv]]

        base_addrs, base_meta = qemu_cov.run_coverage(
            rootfs, qemu_in_rootfs, guest_argv, f"{trace_id}-base",
            port=port, probe_port=False, hold_seconds=hold,
            run_timeout=run_timeout, argv0=argv0,
            sysroot_prefix=sysroot_prefix)
        trig_addrs, trig_meta = qemu_cov.run_coverage(
            rootfs, qemu_in_rootfs, guest_argv, f"{trace_id}-trig",
            port=port, hold_seconds=hold, run_timeout=run_timeout,
            trigger=lambda: _http_trigger(port, request_path) if port else None,
            argv0=argv0, sysroot_prefix=sysroot_prefix)

        base_seq, base_unknown = mapper.map_addresses(base_addrs, functions)
        trig_seq, trig_unknown = mapper.map_addresses(trig_addrs, functions)
        diff = diff_functions(base_seq, trig_seq)

        trace["baseline"] = {**base_meta, "functions": len(base_seq),
                             "unknown_addrs": base_unknown}
        trace["trigger"] = {**trig_meta, "functions": len(trig_seq),
                            "unknown_addrs": trig_unknown}
        trace["diff"] = {"function_count": len(diff), "functions": diff}
        trace["rootfs"] = str(rootfs)
        trace["linker"] = linker
        trace["status"] = _successful_trace_status(diff, trig_meta)
    except Exception as exc:  # noqa: BLE001 - any failure lands in trace.json
        trace["status"] = "failed"
        trace["error"] = f"{type(exc).__name__}: {exc}"
    trace["finished_at"] = _now()
    trace["elapsed_seconds"] = round(time.time() - t0, 2)
    if trace["status"].startswith("ok"):
        trace["cbm_ingest"] = _ingest_to_cbm(cbm_project, trace)
    _write_trace(data_dir, job_id, trace_id, trace)
    return trace


def main(argv):
    if len(argv) < 4 or "--" not in argv:
        print(__doc__)
        return 1
    sep = argv.index("--")
    job_id, md5 = argv[1], argv[2]
    port = None
    args = argv[3:sep]
    if args and args[0] == "--port":
        port = int(args[1])
    from dotenv import load_dotenv
    load_dotenv(FWGRAPH_ROOT / ".env")
    data_dir = Path(_cfg("FWGRAPH_DATA", str(FWGRAPH_ROOT / "data")))
    trace = run_trace(job_id, data_dir, md5, argv[sep + 1:], port=port,
                      request_path="/index.html" if port else None)
    print(json.dumps({k: trace[k] for k in
                      ("trace_id", "status", "error", "elapsed_seconds")},
                     indent=2))
    return 0 if trace["status"].startswith("ok") else 1


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv))
