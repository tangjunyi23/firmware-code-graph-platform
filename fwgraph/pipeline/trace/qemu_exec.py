"""One-shot qemu-user run for PoC crash checks (no coverage log).

The hunt agent needs a verb that is not 'wait for AFL' and not 'HTTP GET':
feed stdin or a /tmp file into a firmware binary and report rc/signal.
Same docker/userns sandbox as traces; no -d exec so it finishes in seconds.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import signal
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from pipeline import sandbox
from pipeline.trace import qemu_cov

_RUN_ID_RE = re.compile(r"^qe-[0-9a-f]{8}$")
_INPUT_PATH_RE = re.compile(r"^/tmp/[A-Za-z0-9._-]{1,64}$")
MAX_STDIN = 8192
MAX_SECONDS = 20
_TAIL = 2000


def _now():
    return datetime.now(timezone.utc).isoformat()


def decode_bytes(text, hex_text, field="stdin"):
    """Exactly one of text / hex_text, or neither (empty)."""
    if text and hex_text:
        raise ValueError(f"{field} 和 {field}_hex 不能同时给")
    if hex_text:
        blob = "".join(str(hex_text).split())
        if len(blob) > MAX_STDIN * 2:
            raise ValueError(f"{field}_hex 超过 {MAX_STDIN} 字节")
        try:
            return bytes.fromhex(blob)
        except ValueError as exc:
            raise ValueError(f"{field}_hex 不是合法十六进制") from exc
    if text is None or text == "":
        return b""
    if isinstance(text, str):
        if "\\n" in text or "\\r" in text or "\\t" in text:
            text = (text.replace("\\\\", "\0")
                    .replace("\\r", "\r")
                    .replace("\\n", "\n")
                    .replace("\\t", "\t")
                    .replace("\0", "\\"))
        raw = text.encode("utf-8", "surrogateescape")
    else:
        raw = bytes(text)
    if len(raw) > MAX_STDIN:
        raise ValueError(f"{field} 超过 {MAX_STDIN} 字节")
    return raw


def _load_binary(data_dir, job_id, md5):
    manifest = json.loads(
        (Path(data_dir) / "extracted" / job_id / "manifest.json")
        .read_text(encoding="utf-8"))
    for binary in manifest.get("binaries") or []:
        if binary.get("md5") == md5:
            return binary
    raise KeyError(f"binary md5 not in manifest: {md5}")


def _classify_rc(rc):
    """Map wait() rc to status.

    128+N / negative N is a signal. SIGKILL (9 / 137) is our watchdog, not
    a guest crash. App exits like 1 or 255 stay error, not crash.
    """
    if rc is None:
        return "timeout", None
    if rc < 0:
        sig = -rc
    elif 128 <= rc <= 160:
        sig = rc - 128
    else:
        sig = None
    if sig == 9:
        return "timeout", 9
    if sig:
        return "crash", sig
    if rc == 0:
        return "ok", None
    return "error", None


def run_job(job_id, data_dir, binary_md5, argv=None, argv0=None,
            stdin=b"", input_path=None, seconds=8, run_id=None):
    """Run the guest once. Returns the exec.json summary."""
    data_dir = Path(data_dir)
    seconds = max(2, min(int(seconds), MAX_SECONDS))
    stdin = stdin or b""
    if len(stdin) > MAX_STDIN:
        raise ValueError(f"stdin 超过 {MAX_STDIN} 字节")
    if input_path and not _INPUT_PATH_RE.match(input_path):
        raise ValueError("input_path 必须是 /tmp/<简单文件名>")
    info = _load_binary(data_dir, job_id, binary_md5)
    extracted = data_dir / "extracted" / job_id
    rootfs, rel = qemu_cov.find_rootfs(extracted, info["path"])
    qemu_name = qemu_cov.qemu_for(info.get("arch"), info.get("endianness"))
    qemu_in = qemu_cov.prepare_rootfs(rootfs, qemu_name, rel)

    run_id = run_id or f"qe-{os.urandom(4).hex()}"
    work = data_dir / "qemu_exec" / job_id / run_id
    work.mkdir(parents=True, exist_ok=True)
    argv = [str(a) for a in (argv or [])]

    out_dir = Path(tempfile.mkdtemp(prefix=f"fwgraph-exec-{run_id}-"))
    out_dir.chmod(0o777)
    qemu_cov.seed_guest_tmp(rootfs, out_dir)
    if stdin:
        (out_dir / "fwgraph-stdin").write_bytes(stdin)
    if input_path:
        (out_dir / Path(input_path).name).write_bytes(stdin or b"")

    inner = [qemu_in] + (["-0", argv0] if argv0 else []) + [rel] + argv
    script = "exec chroot " + shlex.quote(str(rootfs)) + " " \
        + " ".join(shlex.quote(a) for a in inner)
    if stdin and not input_path:
        script += " < " + shlex.quote(str(Path(rootfs) / "tmp" / "fwgraph-stdin"))
    cmd = ["sh", "-c", script]
    log_path = work / "run.log"
    mounts = [
        (str(rootfs), str(rootfs), "ro"),
        (str(out_dir), str(Path(rootfs) / "tmp"), "rw"),
        ("/proc", str(Path(rootfs) / "proc"), "ro"),
    ]

    started = time.time()
    rc = None
    mode = qemu_cov.trace_exec_mode()
    use_docker = mode == "docker" and sandbox.sandbox_image_present(
        sandbox.SANDBOX_IMAGE)
    if use_docker:
        proc = sandbox.run_sandboxed(
            cmd, image=sandbox.SANDBOX_IMAGE,
            name=f"fwgraph-exec-{run_id}",
            mounts=mounts, network="none", user="0",
            cap_add=["SYS_CHROOT"], log_path=str(log_path),
            timeout=seconds + 3)
        try:
            rc = proc.wait(timeout=seconds + 4)
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "rm", "-f", f"fwgraph-exec-{run_id}"],
                           capture_output=True, check=False)
            rc = None
    else:
        proc = subprocess.Popen(
            cmd, stdout=open(log_path, "wb"), stderr=subprocess.STDOUT,
            start_new_session=True)
        try:
            rc = proc.wait(timeout=seconds + 2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
            rc = None

    blob = b""
    if log_path.is_file():
        blob = log_path.read_bytes()[-_TAIL:]
    text = blob.decode("latin-1", "replace")
    kind, sig = _classify_rc(rc)
    fed = bool(stdin) or bool(input_path)
    crash_kind = None
    if kind == "crash":
        crash_kind = "payload" if fed else "startup"
    if kind == "crash" and crash_kind == "startup":
        nxt = ("启动即崩（未喂 payload）：qemu 环境，不是漏洞。"
               "不要放弃该 ELF，立刻 fw_request_trace（带 port 或 via=stdin）。")
    elif kind == "crash":
        nxt = ("payload 触发崩溃：returncode/signal/output_tail 是动态证据；"
               "读函数后 record_finding，不要跳过。")
    elif kind == "timeout" and not fed:
        nxt = ("没喂输入就超时：守护进程可能仍活着。不要放弃。"
               "立刻 fw_request_trace 带 port。")
    else:
        nxt = ("ok/error/timeout 只说明进程退出，不是无漏洞；"
               "换 payload 或改 fw_request_trace。")
    summary = {
        "run_id": run_id, "job_id": job_id, "engine": "qemu-user",
        "binary_md5": binary_md5, "binary_path": info.get("path"),
        "arch": info.get("arch"), "argv": argv, "argv0": argv0,
        "input_path": input_path, "stdin_bytes": len(stdin),
        "seconds": seconds, "started_at": _now(),
        "status": kind, "returncode": rc, "signal": sig,
        "crash_kind": crash_kind,
        "output_tail": text, "elapsed_seconds": round(time.time() - started, 2),
        "sandbox": "docker" if use_docker else mode,
        "next": nxt,
    }
    (work / "exec.json").write_text(json.dumps(summary, indent=2),
                                    encoding="utf-8")
    return summary


def get_run(job_id, data_dir, run_id):
    if not _RUN_ID_RE.match(run_id):
        raise ValueError("bad run id")
    path = Path(data_dir) / "qemu_exec" / job_id / run_id / "exec.json"
    if not path.is_file():
        raise KeyError(run_id)
    return json.loads(path.read_text(encoding="utf-8"))
