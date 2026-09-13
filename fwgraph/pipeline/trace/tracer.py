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
import re
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


_HTTP_PORTS = {80, 81, 443, 8000, 8008, 8080, 8081, 8200, 8443, 8888}
_UDP_PORTS = {53, 67, 68, 69, 123, 161, 162, 514, 546, 547, 1900, 5353}
MAX_PAYLOAD = 8192
MAX_PAYLOAD_STEPS = 8
_INPUT_PATH_RE = re.compile(r"^/tmp/[A-Za-z0-9._-]{1,64}$")

# Minimal protocol probes so SSH/SMB/FTP/DNS traces are not a lone \r\n.
_SSH_BANNER = b"SSH-2.0-fwgraph\r\n"
_FTP_USER = b"USER anonymous\r\nPASS fwgraph\r\n"
_SMB1_NEGOTIATE = bytes.fromhex(
    "0000002fff534d4272000000001843c80000000000000000000000000000"
    "0000000000000000024e54204c4d20302e313200")
_DNS_QUERY = bytes.fromhex(
    "000101000001000000000000076578616d706c6503636f6d0000010001")
_SSDP = (
    b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
    b"MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")


def decode_payload(payload, payload_hex) -> bytes | None:
    """UTF-8 payload or hex; None if both omitted. Raises ValueError."""
    if payload and payload_hex:
        raise ValueError("payload 和 payload_hex 不能同时给")
    if payload_hex:
        blob = "".join(str(payload_hex).split())
        if blob.lower().startswith("0x"):
            blob = blob[2:]
        blob = blob.replace(":", "")
        if len(blob) % 2 == 1:
            blob = "0" + blob
        if len(blob) > MAX_PAYLOAD * 2:
            raise ValueError(f"payload_hex 超过 {MAX_PAYLOAD} 字节")
        try:
            return bytes.fromhex(blob)
        except ValueError as exc:
            raise ValueError("payload_hex 不是合法十六进制") from exc
    if payload is None or payload == "":
        return None
    if isinstance(payload, str):
        # models often send the four characters \r\n instead of CRLF
        if "\\n" in payload or "\\r" in payload or "\\t" in payload:
            payload = (payload.replace("\\\\", "\0")
                       .replace("\\r", "\r")
                       .replace("\\n", "\n")
                       .replace("\\t", "\t")
                       .replace("\0", "\\"))
        raw = payload.encode("utf-8", "surrogateescape")
    else:
        raw = bytes(payload)
    if len(raw) > MAX_PAYLOAD:
        raise ValueError(f"payload 超过 {MAX_PAYLOAD} 字节")
    return raw


def decode_payloads(payload, payload_hex, payloads_hex=None) -> list[bytes] | None:
    """One blob, or a same-connection conversation (payloads_hex)."""
    if payloads_hex:
        if payload or payload_hex:
            raise ValueError("payloads_hex 不能和 payload/payload_hex 同时给")
        if not isinstance(payloads_hex, list) or not payloads_hex:
            raise ValueError("payloads_hex 必须是非空十六进制数组")
        if len(payloads_hex) > MAX_PAYLOAD_STEPS:
            raise ValueError(f"payloads_hex 最多 {MAX_PAYLOAD_STEPS} 步")
        out = []
        total = 0
        for i, item in enumerate(payloads_hex):
            blob = decode_payload(None, item)
            if not blob:
                raise ValueError(f"payloads_hex[{i}] 为空")
            total += len(blob)
            if total > MAX_PAYLOAD:
                raise ValueError(f"payloads_hex 合计超过 {MAX_PAYLOAD} 字节")
            out.append(blob)
        return out
    one = decode_payload(payload, payload_hex)
    return None if one is None else [one]


def _payload_chunks(payload) -> list[bytes]:
    if not payload:
        return []
    if isinstance(payload, (bytes, bytearray)):
        return [bytes(payload)]
    return [bytes(x) for x in payload]


def _default_probe(port: int) -> bytes | None:
    if port == 22:
        return _SSH_BANNER
    if port == 21:
        return _FTP_USER
    if port == 23:
        return b"\r\n"
    if port in (139, 445):
        return _SMB1_NEGOTIATE
    if port == 53:
        return _DNS_QUERY
    if port in (67, 68, 546, 547):
        return b"\x01" + b"\x00" * 47
    if port == 1900:
        return _SSDP
    return None


def _tcp_send(port: int, data, kind: str) -> dict:
    import socket
    chunks = _payload_chunks(data) or [b""]
    multi = len(chunks) > 1
    label = "tcp_conversation" if multi else kind
    sent = sum(len(c) for c in chunks)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            sock.settimeout(3)
            recvd = 0
            for i, chunk in enumerate(chunks):
                sock.sendall(chunk)
                try:
                    recvd += len(sock.recv(1024) or b"")
                except OSError:
                    pass
                if i < len(chunks) - 1:
                    time.sleep(0.15)
        out = {"kind": label, "port": port, "sent": sent, "recv": recvd}
        if multi:
            out["steps"] = len(chunks)
        return out
    except OSError as exc:
        out = {"kind": label, "port": port, "sent": sent,
               "error": f"{type(exc).__name__}: {exc}"}
        if multi:
            out["steps"] = len(chunks)
        return out


def _tcp_trigger(port: int) -> dict:
    probe = _default_probe(port)
    if probe:
        return _tcp_send(port, probe, "tcp_payload")
    import socket
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            try:
                sock.sendall(b"\r\n")
            except OSError:
                pass
        return {"kind": "tcp_connect", "port": port}
    except OSError as exc:
        return {"kind": "tcp_connect", "port": port,
                "error": f"{type(exc).__name__}: {exc}"}


def _udp_send(port: int, data) -> dict:
    import socket
    chunks = _payload_chunks(data) or [b""]
    multi = len(chunks) > 1
    label = "udp_conversation" if multi else "udp_payload"
    sent = sum(len(c) for c in chunks)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(2)
        recvd = 0
        for i, chunk in enumerate(chunks):
            sock.sendto(chunk, ("127.0.0.1", port))
            try:
                recvd += len(sock.recvfrom(64)[0] or b"")
            except socket.timeout:
                pass
            if i < len(chunks) - 1:
                time.sleep(0.15)
        out = {"kind": label, "port": port, "sent": sent, "recv": recvd}
        if multi:
            out["steps"] = len(chunks)
        return out
    except OSError as exc:
        out = {"kind": label, "port": port, "sent": sent,
               "error": f"{type(exc).__name__}: {exc}"}
        if multi:
            out["steps"] = len(chunks)
        return out
    finally:
        sock.close()


def _udp_trigger(port: int) -> dict:
    return _udp_send(port, _default_probe(port) or b"\x00" * 16)


def _service_trigger(port: int, request_path: str | None,
                     payload: bytes | None = None) -> dict:
    """HTTP / TCP / UDP from the listen port, or a caller-supplied payload.

    Agents often pass request_path='/' for ftp/ssh/smb; that is not HTTP.
    payload (raw bytes) is sent as-is — use it for SSH KEX, SMB negotiate,
    FTP USER, SOAP POST, DNS, etc.
    """
    if payload:
        if port in _UDP_PORTS:
            return _udp_send(port, payload)
        return _tcp_send(port, payload, "tcp_payload")
    if port in _UDP_PORTS:
        return _udp_trigger(port)
    if port in _HTTP_PORTS:
        return _http_trigger(port, request_path or "/")
    return _tcp_trigger(port)


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
    last_err = None
    for attempt in range(3):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request("GET", request_path, headers={
                "Host": "192.168.0.1",
                "Referer": "http://192.168.0.1" + request_path,
                "Connection": "close",
            })
            resp = conn.getresponse()
            body = resp.read(4096)
            return {"kind": "http_get", "path": request_path,
                    "status": resp.status, "bytes": len(body)}
        except http.client.HTTPException as exc:
            # RemoteDisconnected is also ConnectionResetError; treat it as
            # "peer closed an HTTP conversation", not a bind-race RST.
            return {"kind": "http_get", "path": request_path,
                    "status": None, "bytes": 0,
                    "error": f"{type(exc).__name__}: {exc}"}
        except (ConnectionResetError, ConnectionRefusedError) as exc:
            last_err = exc
            if attempt < 2:
                time.sleep(0.4)
                continue
            return {"kind": "http_get", "path": request_path,
                    "status": None, "bytes": 0,
                    "error": f"{type(exc).__name__}: {exc}"}
        except OSError as exc:
            return {"kind": "http_get", "path": request_path,
                    "status": None, "bytes": 0,
                    "error": f"{type(exc).__name__}: {exc}"}
        finally:
            conn.close()
    return {"kind": "http_get", "path": request_path,
            "status": None, "bytes": 0,
            "error": f"{type(last_err).__name__}: {last_err}"}


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


def resolve_via(via, input_path=None, payload=None, port=None) -> str:
    """via=net stays net even if input_path is set (do not silently become file)."""
    via_l = str(via or "").strip().lower()
    if via_l == "net":
        return "net"
    if via_l == "stdin":
        return "stdin"
    if via_l == "file" or (input_path and via_l not in ("net", "stdin")):
        return "file"
    if via_l == "stdin" or (payload and not port):
        return "stdin"
    return "net"


def run_trace(job_id: str, data_dir, binary_md5: str, argv,
              port: int | None = None, request_path: str | None = None,
              trace_id: str | None = None, cbm_project: str | None = None,
              argv0: str | None = None, payload: bytes | None = None,
              via: str | None = None, input_path: str | None = None):
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
        "request": {"port": port, "path": request_path,
                    "payload_bytes": sum(len(c) for c in _payload_chunks(payload)),
                    "payload_steps": len(_payload_chunks(payload)),
                    "via": via, "input_path": input_path},
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
        via_l = resolve_via(via, input_path=input_path, payload=payload, port=port)
        trace["request"]["via"] = via_l
        blob = b"".join(_payload_chunks(payload))

        if via_l in ("stdin", "file"):
            if via_l == "file":
                if not _INPUT_PATH_RE.match(str(input_path or "")):
                    raise qemu_cov.QemuError("input_path 必须是 /tmp/<简单文件名>")
                name = str(input_path).rsplit("/", 1)[-1]
                base_addrs, base_meta = qemu_cov.run_coverage(
                    rootfs, qemu_in_rootfs, guest_argv, f"{trace_id}-base",
                    port=None, hold_seconds=hold, run_timeout=run_timeout,
                    argv0=argv0, sysroot_prefix=sysroot_prefix)
                trig_addrs, trig_meta = qemu_cov.run_coverage(
                    rootfs, qemu_in_rootfs, guest_argv, f"{trace_id}-trig",
                    port=None, hold_seconds=hold, run_timeout=run_timeout,
                    argv0=argv0, sysroot_prefix=sysroot_prefix,
                    input_blob=(name, blob))
                trig_meta = {**trig_meta, "trigger_result": {
                    "kind": "input_path", "path": input_path, "sent": len(blob)}}
            else:
                base_addrs, base_meta = qemu_cov.run_coverage(
                    rootfs, qemu_in_rootfs, guest_argv, f"{trace_id}-base",
                    port=None, hold_seconds=hold, run_timeout=run_timeout,
                    argv0=argv0, sysroot_prefix=sysroot_prefix,
                    stdin_bytes=b"")
                trig_addrs, trig_meta = qemu_cov.run_coverage(
                    rootfs, qemu_in_rootfs, guest_argv, f"{trace_id}-trig",
                    port=None, hold_seconds=hold, run_timeout=run_timeout,
                    argv0=argv0, sysroot_prefix=sysroot_prefix,
                    stdin_bytes=blob)
                trig_meta = {**trig_meta, "trigger_result": {
                    "kind": "stdin", "sent": len(blob)}}
        else:
            base_addrs, base_meta = qemu_cov.run_coverage(
                rootfs, qemu_in_rootfs, guest_argv, f"{trace_id}-base",
                port=port, probe_port=False, hold_seconds=hold,
                run_timeout=run_timeout, argv0=argv0,
                sysroot_prefix=sysroot_prefix)
            trig_addrs, trig_meta = qemu_cov.run_coverage(
                rootfs, qemu_in_rootfs, guest_argv, f"{trace_id}-trig",
                port=port, hold_seconds=hold, run_timeout=run_timeout,
                trigger=(lambda connect_port: _service_trigger(
                    connect_port, request_path, payload)) if port else None,
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
