"""Frida dynamic instrumentation stage — for users WITH a live device or
emulation environment running frida-server.

Connects to a remote frida-server (default tcp:27042), attaches to (or
spawns) the target process, hooks the requested functions (module+offset
from the platform's IDA analysis, or exported names) and records every hit
with argument snapshots. Evidence lands in data/frida/<job>/<fsid>/ as
JSONL — the honest "I saw it fire with these args" layer on top of the
static surfaces.

No device reachable -> clean RuntimeError; the platform never pretends.

Endpoints live in orchestrator/app/main.py; this module is transport-free.

Sandbox (Phase 2): local mode (no remote host) with SANDBOX_BACKEND=docker
runs frida-server inside the sandbox image (read-only, cap-drop ALL +
SYS_PTRACE for injection, target dir bind-mounted ro) and connects over the
container bridge IP; the container is always docker rm -f'd afterwards.
"""

import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from pipeline import sandbox

FWGRAPH_ROOT = Path(__file__).resolve().parents[2]

MAX_SECONDS = int(os.getenv("FRIDA_MAX_SECONDS", "300"))
_FSID_RE = re.compile(r"^fs-[0-9a-f]{8}$")
_LOCAL_HOSTS = ("", "local", "127.0.0.1", "localhost")

_AGENT_JS = r"""
const targets = %s;
const hits = [];
function emit(ev) { send(ev); }
function resolveTarget(t) {
  if (t.symbol) {
    if (typeof Module.findGlobalExportByName === 'function') {
      const a = Module.findGlobalExportByName(t.symbol);
      if (a) return a;
    }
    if (typeof Module.findExportByName === 'function') {
      const a = Module.findExportByName(t.module || null, t.symbol);
      if (a) return a;
    }
    if (t.module && typeof Process.getModuleByName === 'function') {
      return Process.getModuleByName(t.module).findExportByName(t.symbol);
    }
    return null;
  }
  if (typeof Module.findBaseAddress === 'function') {
    const base = Module.findBaseAddress(t.module);
    if (base) return base.add(t.offset);
  }
  if (typeof Process.getModuleByName === 'function') {
    return Process.getModuleByName(t.module).base.add(t.offset);
  }
  return null;
}
targets.forEach(function (t) {
  let addr = null;
  try {
    addr = resolveTarget(t);
  } catch (e) { emit({type: 'error', target: t.label, message: String(e)}); }
  if (!addr) { emit({type: 'error', target: t.label, message: 'unresolved'}); return; }
  try {
    Interceptor.attach(addr, {
      onEnter(args) {
        const rec = {type: 'hit', target: t.label, ts: Date.now(), args: []};
        for (let i = 0; i < 4; i++) {
          const a = args[i];
          if (a === undefined) break;
          const ent = {i: i, ptr: a.toString()};
          try {
            if (!a.isNull()) {
              const buf = a.readByteArray(24);
              if (buf) ent.hex = Array.from(new Uint8Array(buf))
                .map(b => b.toString(16).padStart(2, '0')).join('');
            }
          } catch (e) { /* not a readable pointer */ }
          rec.args.push(ent);
        }
        emit(rec);
      }
    });
    emit({type: 'hooked', target: t.label, at: addr.toString()});
  } catch (e) { emit({type: 'error', target: t.label, message: String(e)}); }
});
"""


def _now():
    return datetime.now(timezone.utc).isoformat()


def _docker_rm(name):
    subprocess.run(["docker", "rm", "-f", name], capture_output=True,
                   check=False)


def _device_via_sandbox(frida, process, run_id):
    """本地模式的 docker 沙箱：容器内跑 frida-server，经 bridge IP 连接。
    返回 (容器名, device)；任何一步失败都先清理容器再抛 RuntimeError。"""
    name = f"fwgraph-frida-{run_id}"
    # frida 注入依赖 ptrace：cap-drop ALL 之上单独放行的最小能力
    cmd = ["docker", "run", "-d", "--rm", "--name", name,
           "--network", "bridge", "--read-only",
           "--cap-drop", "ALL", "--cap-add", "SYS_PTRACE",
           "--security-opt", "no-new-privileges"]
    target = Path(process)
    if target.is_absolute():
        # 目标二进制同路径只读挂载进容器；attach 模式要求进程已在容器内，
        # 实际有意义的主要是 spawn 模式
        try:
            os.chmod(target, 0o755)  # EMBA 解出的文件常缺执行位
        except OSError:
            pass
        cmd += ["-v", f"{target.parent}:{target.parent}:ro"]
    cmd += [sandbox.SANDBOX_IMAGE, "frida-server", "-l", "0.0.0.0:27042"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        raise RuntimeError("frida 沙箱容器启动失败："
                           f"{(proc.stderr or '').strip()[-200:]}")
    cid = proc.stdout.strip() or name
    try:
        ip = subprocess.run(
            ["docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", cid],
            capture_output=True, text=True, timeout=15).stdout.strip()
        if not ip:
            raise RuntimeError("frida 沙箱容器未取到 bridge IP")
        mgr = frida.get_device_manager()
        deadline = time.time() + 10
        last = None
        while time.time() < deadline:  # 等容器内 frida-server 开始监听
            try:
                return name, mgr.add_remote_device(ip, timeout=5)
            except Exception as exc:  # noqa: BLE001 - 连接重试窗口
                last = exc
                time.sleep(0.3)
        raise RuntimeError(
            f"沙箱容器内 frida-server 不可达（{ip}:27042）：{last}")
    except Exception:
        _docker_rm(name)
        raise


def _sandbox_fallback_warning(backend):
    """配置了 docker 但无法进容器时的中文警告（落 frida.json）。"""
    if backend != "docker":
        if sandbox.configured_backend("frida") == "docker":
            return ("警告：SANDBOX_BACKEND=docker 但 docker 不可用，本次 "
                    "frida 插桩在宿主机直接运行不可信固件代码。")
        return None
    return (f"警告：沙箱镜像 {sandbox.SANDBOX_IMAGE} 未构建，本次 frida 插桩"
            f"在宿主机直接运行不可信固件代码。构建：{sandbox.BUILD_HINT}")


def run_job(job_id, data_dir, host, process, functions, seconds=60,
            spawn=False, run_id=None):
    """Hook `functions` on `process` via the frida-server at `host`.

    functions: [{"module": "libc.so", "offset": "0x1234"} or
                {"module": "httpd", "symbol": "main"}] — offset is the
                file/static offset the platform reports (IDA addr minus
                image base); label is free-form display text.
    """
    seconds = max(5, min(int(seconds), MAX_SECONDS))
    import frida  # optional dependency; ImportError surfaces as 503 upstream

    run_id = run_id or f"fs-{os.urandom(4).hex()}"
    work = Path(data_dir) / "frida" / job_id / run_id
    work.mkdir(parents=True, exist_ok=True)
    events_path = work / "events.jsonl"

    targets = []
    for i, f in enumerate(functions):
        t = {"label": f.get("label") or f.get("symbol") or
             f.get("offset", f"target{i}")}
        if f.get("module"):
            t["module"] = f["module"]
        if f.get("symbol"):
            t["symbol"] = f["symbol"]
        else:
            off = str(f.get("offset", ""))
            t["offset"] = int(off, 16) if off.startswith("0x") else int(off or 0)
        targets.append(t)

    container = None
    sandbox_backend = "remote"
    sandbox_warning = None
    if host in _LOCAL_HOSTS:
        backend = sandbox.backend_for("frida")
        if backend == "docker" and sandbox.sandbox_image_present(
                sandbox.SANDBOX_IMAGE):
            container, device = _device_via_sandbox(frida, process, run_id)
            sandbox_backend = "docker"
        else:
            sandbox_warning = _sandbox_fallback_warning(backend)
            # x86 目标在本机直接插桩（无需 frida-server）
            device = frida.get_local_device()
            sandbox_backend = "none"
    else:
        mgr = frida.get_device_manager()
        try:
            device = mgr.add_remote_device(host, timeout=10)
        except Exception as exc:
            raise RuntimeError(
                f"frida-server unreachable at {host} ({exc}); start "
                f"frida-server on the device/emulator first") from exc

    pid = None
    session = None
    counts = {"hit": 0, "hooked": 0, "error": 0}
    try:
        with open(events_path, "a", encoding="utf-8") as fh:
            def on_message(msg, _data):
                if msg.get("type") == "send":
                    payload = msg.get("payload", {})
                    kind = payload.get("type", "?")
                    if kind in counts:
                        counts[kind] += 1
                    fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
                    fh.flush()
                elif msg.get("type") == "error":
                    counts["error"] += 1
                    fh.write(json.dumps({"type": "error",
                                         "message": msg.get("description", "?")},
                                        ensure_ascii=False) + "\n")

            try:
                if spawn:
                    pid = device.spawn([process])
                    session = device.attach(pid)
                else:
                    session = device.attach(process)
                script = session.create_script(_AGENT_JS % json.dumps(targets))
                script.on("message", on_message)
                script.load()
                if pid is not None:
                    device.resume(pid)
                time.sleep(seconds)
                script.unload()
            except frida.ProcessNotFoundError as exc:
                raise RuntimeError(f"process not found on device: {process}") \
                    from exc
            finally:
                if session is not None:
                    try:
                        session.detach()
                    except Exception:
                        pass
    finally:
        if container is not None:
            _docker_rm(container)

    summary = {
        "run_id": run_id, "job_id": job_id, "engine": "frida",
        "host": host, "process": process, "spawn": spawn,
        "targets": [t["label"] for t in targets],
        "seconds": seconds, "started_at": _now(),
        "status": "ok",
        "hooked": counts["hooked"], "hits": counts["hit"],
        "errors": counts["error"],
        "events_file": str(events_path),
        "sandbox_backend": sandbox_backend,
        "attribution": "observed_in_window",
        "note": ("Hits are observed in the instrumentation window. "
                 "Not request-caused; not a coverage percentage."),
    }
    if sandbox_backend == "docker":
        summary["sandbox_image"] = sandbox.SANDBOX_IMAGE
        summary["sandbox_limits"] = dict(sandbox.DEFAULT_LIMITS)
    if sandbox_warning:
        summary["sandbox_warning"] = sandbox_warning
    (work / "frida.json").write_text(json.dumps(summary, indent=2),
                                     encoding="utf-8")
    return summary


def list_runs(job_id, data_dir):
    base = Path(data_dir) / "frida" / job_id
    out = []
    if base.is_dir():
        for d in sorted(base.iterdir(), reverse=True):
            f = d / "frida.json"
            if f.is_file():
                out.append(json.loads(f.read_text(encoding="utf-8")))
    return out


def get_run(job_id, data_dir, run_id):
    if not _FSID_RE.match(run_id):
        raise ValueError("bad run id")
    f = Path(data_dir) / "frida" / job_id / run_id / "frida.json"
    if not f.is_file():
        raise KeyError(run_id)
    return json.loads(f.read_text(encoding="utf-8"))
