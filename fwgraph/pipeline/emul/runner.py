"""进程簇固件模拟 runner（阶段 1）。

复用 trace 体系的启动原语（qemu-user + docker 沙箱 + 端口发布），差别在
生命周期：trace 是"启动→打一枪→杀"，模拟是**常驻**——服务进程一直活着，
宿主可随时探活/发包/读 console，AI 按 console 诊断→patch rootfs→重启迭代。

真实性原则：环境是否"活了"从不采信 AI 的口头汇报——fw_emul_publish 时
编排器亲自重探每个声明的端点（真 TCP/HTTP 打到 qemu 里的服务），探不通
拒绝置 ready。
"""
from __future__ import annotations

import base64
import json
import os
import re
import shlex
import shutil
import stat
import socket
import subprocess
import time
from pathlib import Path

from pipeline.emul import store
from pipeline.trace import qemu_cov

CONTAINER_PREFIX = "fwgraph-emul"
DEFAULT_SESSION_GB = float(os.getenv("EMUL_SESSION_GB", "20"))
DEFAULT_GLOBAL_GB = float(os.getenv("EMUL_GLOBAL_GB", "60"))
READY_TIMEOUT = float(os.getenv("EMUL_READY_TIMEOUT", "20"))
MAX_RESPONSE = int(os.getenv("EMUL_MAX_RESPONSE", "8192"))
_GUEST_PATH_RE = re.compile(r"^/[A-Za-z0-9._/@+-]{1,200}$")


class EmulError(Exception):
    """中文错误，直接进工具结果。"""


# ---------------- 磁盘配额 ----------------

def _du_bytes(path: Path) -> int:
    try:
        out = subprocess.run(["du", "-sb", str(path)],
                             capture_output=True, text=True, timeout=60)
        if out.returncode == 0:
            return int(out.stdout.split()[0])
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    return 0


def _emul_workspaces_root(sessions_home: Path) -> Path:
    return Path(sessions_home)


def check_quota(sessions_home: Path, session_id: str,
                extra_bytes: int = 0) -> int:
    """返回当前已用字节；超额抛 EmulError。"""
    if not store_re_session(session_id):
        raise EmulError("session_id 非法")
    used = _du_bytes(_emul_workspaces_root(sessions_home) / session_id
                     / "workspace")
    if used + extra_bytes > DEFAULT_SESSION_GB * 1024 ** 3:
        raise EmulError(
            f"本会话工作区将超过 {DEFAULT_SESSION_GB:g}GB 配额"
            f"（已用 {used / 1024 ** 3:.1f}GB）。先 fw_emul_stop 不用的环境"
            "或删除大文件再来。")
    total = 0
    for sid_dir in _emul_workspaces_root(sessions_home).glob("*/workspace"):
        total += _du_bytes(sid_dir)
        if total + extra_bytes > DEFAULT_GLOBAL_GB * 1024 ** 3:
            raise EmulError(
                f"全局模拟工作区将超过 {DEFAULT_GLOBAL_GB:g}GB 配额。"
                "需要先停止并清理其他模拟环境。")
    return used


def store_re_session(sid: str) -> bool:
    return bool(re.match(r"^[A-Za-z0-9_.-]{1,64}$", str(sid or "")))


# ---------------- build ----------------

def _manifest(data_dir, job_id: str) -> dict:
    mf = Path(data_dir) / "extracted" / job_id / "manifest.json"
    if not mf.is_file():
        raise EmulError(f"任务 {job_id} 没有 manifest.json（先完成解包）")
    return json.loads(mf.read_text(encoding="utf-8"))


def _find_source_rootfs(data_dir, job_id: str) -> tuple:
    """挑一个带 etc/ 的最浅 rootfs 作为模拟底座（与 trace 同源逻辑）。"""
    manifest = _manifest(data_dir, job_id)
    binaries = manifest.get("binaries") or []
    best = None
    for b in binaries:
        p = str(b.get("path") or "")
        if not p:
            continue
        try:
            rootfs, rel = qemu_cov.find_rootfs(
                Path(data_dir) / "extracted" / job_id, p)
        except Exception:  # noqa: BLE001 - find_rootfs 对怪路径宽容
            continue
        if (Path(rootfs) / "etc").is_dir():
            best = (rootfs, rel, b)
            break
        if best is None:
            best = (rootfs, rel, b)
    if best is None:
        raise EmulError("manifest 里没有可定位 rootfs 的二进制")
    return best


def build_env(data_dir, job_id: str, session_id: str,
              sessions_home: Path, env_id: str, budget_gb: float | None = None,
              request_id: str = "", owner: str = "admin") -> dict:
    """把任务 rootfs 拷进会话工作区，形成可写模拟底座。"""
    budget = float(budget_gb or DEFAULT_SESSION_GB)
    if not (0.5 <= budget <= DEFAULT_SESSION_GB):
        raise EmulError(f"budget_gb 需在 0.5~{DEFAULT_SESSION_GB:g} 之间")
    src_rootfs, _rel, binrec = _find_source_rootfs(data_dir, job_id)
    src_bytes = _du_bytes(Path(src_rootfs))
    check_quota(sessions_home, session_id, extra_bytes=src_bytes * 2)

    ws = _emul_workspaces_root(sessions_home) / session_id / "workspace" \
        / "emul" / env_id
    if ws.exists():
        raise EmulError(f"环境 {env_id} 的工作区已存在")
    dest = ws / "rootfs"
    dest.parent.mkdir(parents=True, exist_ok=True)
    # tar 管道拷贝：保留符号链接与内部硬链接（EMBA 解包树大量硬链接，
    # shutil.copytree 会拆链导致 5 倍膨胀且极慢），并排除 /dev /proc
    # （固件字符设备节点无法也无需复制——容器运行时自建设备面）。
    # writable 拷贝与证据树隔离，patch 只影响本环境。
    dest.mkdir(parents=True, exist_ok=True)
    cmd = ("tar -C " + shlex.quote(str(src_rootfs))
           + " --exclude=./dev --exclude=./proc --exclude=./sys -cf - . | "
           "tar -C " + shlex.quote(str(dest)) + " -xpf -")
    cp = subprocess.run(["sh", "-c", cmd],
                        capture_output=True, text=True, timeout=600)
    if cp.returncode != 0:
        shutil.rmtree(ws, ignore_errors=True)
        raise EmulError(f"rootfs 拷贝失败：{cp.stderr[:200]}")
    (dest / "dev").mkdir(exist_ok=True)
    (dest / "tmp").mkdir(exist_ok=True)
    # EMBA 解包会剥执行位；模拟环境里服务会派生兄弟守护进程（如 httpd
    # 派生 ipcserver），bin/sbin 树整体补 u+x（一次性，硬链接树很快）
    subprocess.run(
        ["find", str(dest),
         "-type", "f", "(",
         "-path", "*/bin/*", "-o", "-path", "*/sbin/*", ")",
         "-exec", "chmod", "u+x", "{}", "+"],
        capture_output=True, timeout=180)
    used = _du_bytes(dest)
    if used > budget * 1024 ** 3:
        shutil.rmtree(ws, ignore_errors=True)
        raise EmulError(f"rootfs {used / 1024 ** 3:.1f}GB 超过 {budget:g}GB 预算")

    env = store.new_env_record(
        env_id, job_id, session_id, str(ws),
        str(binrec.get("arch") or ""), str(src_rootfs),
        int(budget * 1024 ** 3), request_id=request_id, owner=owner)
    env["disk_bytes"] = used
    env["status"] = "built"
    store.save_env(data_dir, env)
    store.env_note(env, f"底座就绪：arch={env['arch']} "
                        f"{used / 1024 ** 2:.0f}MiB（源 {src_rootfs}）")
    store.save_env(data_dir, env)
    return env


# ---------------- boot ----------------

def _docker_limits() -> dict:
    return {"mem": os.getenv("EMUL_DOCKER_MEM", "1g"),
            "cpus": os.getenv("EMUL_DOCKER_CPUS", "1.5"),
            "pids": os.getenv("EMUL_DOCKER_PIDS", "256")}


def _shm_seed_sh() -> str:
    """容器内 SysV shm 预播种片段（镜像 python3+ctypes，失败不阻塞启动）。

    种子与 trace 侧 qemu_cov._SHM_SEEDS 同源；在容器私有 IPC namespace
    里执行，宿主与其它环境的旧段不再互相占坑。
    """
    seeds = list(getattr(qemu_cov, "_SHM_SEEDS", ()))
    if not seeds:
        return ":"
    pairs = ",".join(f"({int(k)},{int(s)})" for k, s in seeds)
    py = (
        "import ctypes\n"
        "libc=ctypes.CDLL('libc.so.6',use_errno=True)\n"
        f"for k,s in [{pairs}]:\n"
        "    i=libc.shmget(k,s,0o1000|0o666)\n"
        "    if i<0:\n"
        "        e=libc.shmget(k,0,0)\n"
        "        if e>=0: libc.shmctl(e,0,None)\n"
        "        libc.shmget(k,s,0o1000|0o666)\n"
    )
    return f"python3 -c {shlex.quote(py)} 2>/dev/null || :"


def _boot_service_process(env: dict, rootfs: Path, qemu_in_rootfs: str,
                          argv_in_rootfs: list, argv0: str | None,
                          port: int, host_port: int, container: str,
                          console_path: Path):
    """docker run 常驻容器：与 trace 的差别是 rootfs 可写、不杀进程。

    不走 sandbox.run_sandboxed——那边硬编码 --read-only，模拟必须可写
    （AI 的 patch 要落盘、服务要写 nvram/日志）。
    """
    limits = _docker_limits()
    guest_argv = [str(a) for a in argv_in_rootfs]
    inner = (["chroot", str(rootfs), qemu_in_rootfs]
             + (["-0", argv0] if argv0 else [])
             + guest_argv)
    # SysV shm 预播种（TP-Link httpd 的 mode-0 shmget 陷阱）在容器私有
    # IPC namespace 里做（镜像内 python3+ctypes）：共享宿主 ns 会让外来
    # 旧段占坑（无 CAP_SYS_ADMIN 删不掉，httpd shmget(IPC_CREAT|0777)
    # 永久 EACCES），多环境之间也会互相踩。
    script = _shm_seed_sh() + "; exec " + " ".join(shlex.quote(a) for a in inner)
    cmd = ["docker", "run", "--rm", "--name", container,
           "--user", "0",
           "--network", "bridge",
           "--cap-drop", "ALL", "--cap-add", "SYS_CHROOT",
           "--cap-add", "NET_BIND_SERVICE", "--cap-add", "DAC_OVERRIDE",
           "--security-opt", "no-new-privileges",
           "--pids-limit", limits["pids"],
           "--memory", limits["mem"], "--cpus", limits["cpus"],
           "--sysctl", "net.ipv4.ip_unprivileged_port_start=0",
           "-v", f"{rootfs}:{rootfs}:rw",
           "-v", f"/proc:{rootfs}/proc:ro",
           "-p", f"127.0.0.1:{host_port}:{port}",
           "fwgraph-sandbox:local",
           "sh", "-c", script]
    # 与 trace 同源的环境种子：TP-Link httpd 的 /tmp/dec-model.conf 020
    # 权限陷阱、web 资源目录、fifo（shm 播种已挪进容器私有 IPC ns）
    io_dir = rootfs / "tmp"
    try:
        # 只清陈旧 socket（>120s）：多服务环境里兄弟容器刚创建的活 socket
        # （如 ipcserver 的 /tmp/ipc）必须保留，否则跨容器握手必挂
        now = time.time()
        for stale in io_dir.glob("*"):
            try:
                st = stale.stat(follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISSOCK(st.st_mode) and now - st.st_mtime > 120:
                stale.unlink()
        qemu_cov.seed_guest_tmp(rootfs, io_dir)
    except OSError:
        pass
    log = open(console_path, "ab")
    try:
        return subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True)
    finally:
        log.close()


def _wait_ready(host_port: int, container: str,
                timeout: float) -> tuple:
    deadline = time.monotonic() + timeout
    # docker run 的 Popen 返回 ≠ 容器已在 daemon 注册完成：起查太早会
    # inspect 到 No such object，把活容器误判成 "container exited"（模拟
    # agent 会被这条假错误带偏成"运行时整体故障"）。给创建宽限期。
    grace = time.monotonic() + min(8.0, timeout * 0.5)
    while time.monotonic() < deadline:
        if not store.container_alive(container):
            if time.monotonic() < grace:
                time.sleep(0.5)
                continue
            return False, "container exited"
        try:
            with socket.create_connection(("127.0.0.1", host_port),
                                          timeout=1.5):
                return True, "port open"
        except OSError:
            time.sleep(0.6)
    return False, f"port {host_port} not ready in {timeout:.0f}s"


def _console_text(container: str, tail: int = 60,
                  fallback_path: Path | None = None) -> str:
    """docker logs 优先；容器已被 --rm 清掉（秒退进程）或无输出时，
    回退读 boot 时同步落盘的 console-<svc>.log——秒退进程的报错丢了
    会让模拟 agent 误判「运行时整体故障」，这是观测链路问题不是环境问题。
    """
    text = ""
    try:
        out = subprocess.run(["docker", "logs", "--tail", str(int(tail)),
                              container],
                             capture_output=True, text=True, timeout=10)
        text = out.stdout + out.stderr
    except (OSError, subprocess.TimeoutExpired):
        text = ""
    if fallback_path is not None and (
            not text.strip() or "No such container" in text):
        try:
            ftext = fallback_path.read_text(encoding="utf-8",
                                            errors="replace")
            if ftext.strip():
                text = ftext
        except OSError:
            pass
    return text[-4000:]


def boot_service(data_dir, env: dict, binary_md5: str, argv: list,
                 port: int, argv0: str | None = None,
                 binary_path: str | None = None,
                 name: str | None = None,
                 ready_timeout: float | None = None) -> dict:
    """在环境里拉起一个固件服务进程（qemu-user + chroot + 常驻容器）。"""
    if env.get("status") in ("stopped", "failed"):
        raise EmulError(f"环境已 {env['status']}，先 reset 或重建")
    if env.get("status") == "purged":
        raise EmulError("环境已被自动清理（TTL/磁盘水位），请重建环境")
    if not (1 <= int(port) <= 65535):
        raise EmulError("port 需在 1~65535")
    manifest = _manifest(data_dir, env["job_id"])
    binary = None
    for b in manifest.get("binaries") or []:
        if binary_md5 and b.get("md5") == binary_md5:
            binary = b
            break
        if not binary_md5 and binary_path and str(b.get("path", "")).endswith(
                str(binary_path).lstrip("/")):
            binary = b
            break
    if binary is None:
        raise EmulError(
            f"manifest 里没有匹配的二进制（md5={binary_md5} path={binary_path}）；"
            "用 fw_emul_binaries filter= 精确查")
    rootfs_src, rel = qemu_cov.find_rootfs(
        Path(data_dir) / "extracted" / env["job_id"], binary["path"])
    env_rootfs = Path(env["workspace"]) / "rootfs"
    if not env_rootfs.is_dir():
        raise EmulError("环境 rootfs 缺失（被清理？）请重建环境")
    qemu_name = qemu_cov.qemu_for(binary.get("arch"),
                                  binary.get("endianness"))
    qemu_in_rootfs = qemu_cov.prepare_rootfs(env_rootfs, qemu_name, rel)

    svc_name = re.sub(r"[^A-Za-z0-9_.-]", "-", str(name or rel.rsplit("/", 1)[-1]
                                                    or "svc"))[:40]
    existing = store.service_of(env, svc_name)
    if existing:
        _stop_container(existing.get("container") or "")
        env["services"] = [s for s in env["services"]
                           if s.get("name") != svc_name]
    container = f"{CONTAINER_PREFIX}-{env['env_id']}-{svc_name}"[:96]
    host_port = qemu_cov.publish_host_port(int(port))
    console_path = Path(env["workspace"]) / f"console-{svc_name}.log"

    store.env_note(env, f"boot {svc_name}: {rel} port={port} "
                        f"argv={json.dumps([str(a) for a in argv])}")
    env["status"] = "booting"
    store.save_env(data_dir, env)
    try:
        _boot_service_process(env, env_rootfs, qemu_in_rootfs,
                              [rel, *[str(a) for a in argv]], argv0,
                              int(port), host_port, container, console_path)
    except OSError as exc:
        env["status"] = "failed"
        env["error"] = f"docker 启动失败：{exc}"
        store.save_env(data_dir, env)
        raise EmulError(env["error"]) from exc

    ready, why = _wait_ready(host_port, container,
                             float(ready_timeout or READY_TIMEOUT))
    svc = {
        "name": svc_name, "container": container,
        "binary_md5": binary_md5, "binary_path": rel,
        "argv": [str(a) for a in argv], "argv0": argv0,
        "guest_port": int(port), "host_port": host_port,
        "status": "ok" if ready else "degraded",
        "boot_attempts": (existing or {}).get("boot_attempts", 0) + 1,
        "ready": why,
    }
    env["services"].append(svc)
    env["iterations"] += 1
    svc_status = "ok" if ready else "degraded"
    if env["status"] != "ready":
        env["status"] = "booting" if svc_status == "ok" else "degraded"
    hint = ""
    if not ready and "container exited" not in why:
        hint = ("\n（容器存活但 TCP 端口未就绪：服务可能监听 UDP/其他端口，"
                "或是不监听端口的 AF_UNIX 服务——用 fw_emul_probe path= "
                "探 guest 内 socket 路径）")
    store.env_note(env, f"{svc_name} {'就绪' if ready else '未就绪'}：{why}"
                        + ("" if ready else f"\nconsole 尾部：\n"
                           + _console_text(container, 80, console_path) + hint))
    store.save_env(data_dir, env)
    return {**svc, "console": _console_text(container, 80, console_path)}


# ---------------- 探活 / 发包 ----------------

def _exchange(host_port: int | None = None, proto: str = "tcp",
              payload: bytes | None = None,
              http_method: str | None = None, http_path: str = "/",
              headers: dict | None = None, timeout: float = 8.0,
              unix_sock: str | Path | None = None) -> dict:
    """与模拟服务交换一次数据；返回原始响应（截断）。

    unix_sock：guest 内 AF_UNIX 套接字路径（如 /tmp/ipc）映射到宿主侧
    rootfs bind mount 下的同一文件——unix socket 是文件系统对象，
    容器内进程 bind 的 socket 宿主可直接 connect，用于无 TCP 端口的
    本地服务（如 ipcserver）探活。
    """
    if unix_sock is not None:
        # AF_UNIX sun_path 上限 108 字节：模拟环境的 workspace 路径远超，
        # 用 /tmp 下短符号链接中转（内核 connect 会解析 symlink 到真实 socket）
        real = Path(unix_sock)
        link = None
        try:
            if len(str(real).encode()) > 100:
                link = Path("/tmp") / (
                    f"emul-ux-{real.stat().st_ino & 0xffffffff:08x}.sock")
                if not link.exists():
                    link.symlink_to(real)
                unix_sock = link
        except OSError:
            pass
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(str(unix_sock))
            if payload:
                sock.sendall(payload)
            chunks = []
            while sum(len(c) for c in chunks) < MAX_RESPONSE:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            data = b"".join(chunks)
        except OSError as exc:
            return {"ok": False, "error": str(exc)}
        finally:
            sock.close()
        return {"ok": True, "bytes": len(data),
                "hex": data.hex()[:MAX_RESPONSE * 2],
                "text": data.decode("utf-8", "replace")[:MAX_RESPONSE]}
    if proto == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            if payload:
                sock.sendto(payload, ("127.0.0.1", host_port))
            sock.settimeout(min(timeout, 3.0))
            data, _ = sock.recvfrom(MAX_RESPONSE)
            return {"ok": True, "bytes": len(data),
                    "hex": data.hex()[:MAX_RESPONSE * 2],
                    "text": data.decode("utf-8", "replace")[:MAX_RESPONSE]}
        except OSError as exc:
            return {"ok": False, "error": str(exc)}
        finally:
            sock.close()
    if http_method:
        req = f"{http_method} {http_path} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        for k, v in (headers or {}).items():
            req += f"{k}: {v}\r\n"
        body = payload or b""
        req += f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        payload = req.encode("latin-1", "replace") + body
    try:
        with socket.create_connection(("127.0.0.1", host_port),
                                      timeout=timeout) as sock:
            if not payload:
                # 纯探活：connect 成功即监活着，静默协议不必等数据
                return {"ok": True, "bytes": 0, "hex": "", "text": "",
                        "note": "connected (silent protocol)"}
            sock.settimeout(timeout)
            sock.sendall(payload)
            chunks = []
            while sum(len(c) for c in chunks) < MAX_RESPONSE:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            data = b"".join(chunks)
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "bytes": len(data),
            "hex": data.hex()[:MAX_RESPONSE * 2],
            "text": data.decode("utf-8", "replace")[:MAX_RESPONSE]}


def _resolve_host_port(env: dict, port) -> int:
    port = int(port)
    for svc in env.get("services", []):
        if svc.get("guest_port") == port and svc.get("status") != "stopped":
            return int(svc["host_port"])
    raise EmulError(f"环境里没有 guest_port={port} 的在运行服务；"
                    "先 fw_emul_boot 或核对端口")




def _unix_probe_via_container(env: dict, host_path: Path,
                              payload: bytes | None,
                              http_path: str | None,
                              http_method: str | None,
                              timeout: float = 6.0) -> dict:
    """容器内 python3 直连 guest unix socket（root 属主 socket 宿主用户
    无 connect 权限；bind mount 下容器内同一文件可访问）。纯 connect 判活。"""
    container = next((sv["container"] for sv in env.get("services", [])
                      if sv.get("status") not in ("stopped",)), None)
    if not container:
        return {"ok": False, "error": "环境里没有在运行的容器可借用探测"}
    send = (payload or b"").hex()
    # bind mount 保持宿主长路径，AF_UNIX sun_path 108 上限会炸：
    # exec -w 进 socket 所在目录，connect 用相对文件名（内核按 cwd 解析）
    code = (
        "import socket\n"
        f"s=socket.socket(socket.AF_UNIX);s.settimeout({timeout})\n"
        f"s.connect({host_path.name!r})\n"
        "print('CONNECTED')\n"
        + (f"data=bytes.fromhex({send!r})\ns.sendall(data)\n"
           "buf=b''\n"
           "try:\n"
           "    while len(buf)<4096:\n"
           "        c=s.recv(4096)\n"
           "        if not c: break\n"
           "        buf+=c\n"
           "except Exception: pass\n"
           "print('HEX',buf.hex())\n" if send else "")
    )
    try:
        out = subprocess.run(["docker", "exec", "-w", str(host_path.parent),
                              container, "python3", "-c", code],
                             capture_output=True, text=True,
                             timeout=timeout + 6)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": f"容器内探测失败：{exc}"}
    text = out.stdout + out.stderr
    if "CONNECTED" not in text:
        return {"ok": False,
                "error": (text.strip() or "connect 失败")[:300]}
    hexpart = ""
    for line in text.splitlines():
        if line.startswith("HEX "):
            hexpart = line[4:].strip()
    data = bytes.fromhex(hexpart) if hexpart else b""
    return {"ok": True, "bytes": len(data),
            "hex": data.hex()[:MAX_RESPONSE * 2],
            "text": data.decode("utf-8", "replace")[:MAX_RESPONSE]}


def probe(data_dir, env: dict, port=None, proto: str = "tcp",
          http_path: str | None = None, payload_hex: str | None = None,
          http_method: str | None = None, path: str | None = None) -> dict:
    """探活：TCP/UDP 端口（port）或 guest 内 unix socket 路径（path）。"""
    payload = bytes.fromhex(payload_hex) if payload_hex else None
    if path:
        host_path = Path(env["workspace"]) / "rootfs" / str(path).lstrip("/")
        if not host_path.exists():
            return {"ok": False, "path": str(path),
                    "error": f"socket 文件不存在（服务没起来或路径不对）：{path}"}
        out = _unix_probe_via_container(env, host_path, payload,
                                        http_path, http_method)
        out["path"] = str(path)
        return out
    if port is None:
        raise EmulError("probe 需要 port（TCP/UDP）或 path（unix socket）之一")
    host_port = _resolve_host_port(env, port)
    out = _exchange(host_port, proto, payload,
                    http_method=http_method or ("GET" if http_path else None),
                    http_path=http_path or "/")
    out["port"] = int(port)
    return out


def send(data_dir, env: dict, port, proto: str = "tcp",
         payload_hex: str | None = None, payload_text: str | None = None,
         http_method: str | None = None, http_path: str = "/",
         headers: dict | None = None) -> dict:
    if payload_hex and payload_text:
        raise EmulError("payload_hex 与 payload_text 只能给一个")
    blob = (bytes.fromhex(payload_hex) if payload_hex
            else payload_text.encode() if payload_text else None)
    host_port = _resolve_host_port(env, port)
    return _exchange(host_port, proto, blob, http_method=http_method,
                     http_path=http_path, headers=headers)


# ---------------- patch / reset / stop / publish ----------------

def _guest_target(env: dict, guest_path: str) -> Path:
    if not _GUEST_PATH_RE.match(str(guest_path or "")):
        raise EmulError("path 必须是 rootfs 内的绝对路径（/etc/... 形式）")
    rootfs = (Path(env["workspace"]) / "rootfs").resolve()
    target = (rootfs / str(guest_path).lstrip("/")).resolve()
    if rootfs != target and rootfs not in target.parents:
        raise EmulError("path 越出 rootfs")
    return target


def patch_file(data_dir, env: dict, op: str, guest_path: str,
               content_b64: str | None = None, mode: str | None = None,
               content_text: str | None = None) -> dict:
    if content_b64 and content_text:
        raise EmulError("content_b64 与 content_text 只能给一个")
    target = _guest_target(env, guest_path)
    if op == "write":
        blob = (base64.b64decode(content_b64) if content_b64
                else (content_text or "").encode("utf-8"))
        if len(blob) > 4 * 1024 * 1024:
            raise EmulError("单文件写入上限 4MiB")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)
        if mode:
            _apply_mode(target, mode)
    elif op == "delete":
        if target.is_dir():
            shutil.rmtree(target)
        elif target.exists():
            target.unlink()
        else:
            raise EmulError(f"要删除的文件不存在：{guest_path}")
    elif op == "chmod":
        _apply_mode(target, mode)
    else:
        raise EmulError("op 只支持 write|delete|chmod")
    env["disk_bytes"] = _du_bytes(Path(env["workspace"]))
    store.env_note(env, f"patch {op} {guest_path}"
                        + (f" mode={mode}" if mode else ""))
    store.save_env(data_dir, env)
    return {"ok": True, "path": guest_path}


def _apply_mode(target: Path, mode: str) -> None:
    try:
        os.chmod(target, int(str(mode), 8))
    except (OSError, ValueError) as exc:
        raise EmulError(f"mode 必须是八进制（如 0755）：{exc}") from exc


def read_file(env: dict, guest_path: str, max_bytes: int = 65536) -> dict:
    target = _guest_target(env, guest_path)
    if not target.is_file():
        raise EmulError(f"文件不存在：{guest_path}")
    blob = target.read_bytes()[:max_bytes]
    return {"path": guest_path, "bytes": len(blob),
            "content": blob.decode("utf-8", "replace")}


def _stop_container(container: str) -> None:
    if container and re.match(r"^[\w.-]{1,96}$", container):
        subprocess.run(["docker", "rm", "-f", container],
                       capture_output=True, timeout=20)


def reset_env(data_dir, env: dict) -> dict:
    """杀掉全部服务容器按原配置重启（patch 后的 rootfs 保留）。"""
    if env.get("status") == "purged":
        raise EmulError("环境已被自动清理（TTL/磁盘水位），无法 reset，请重建")
    stopped = 0
    for svc in env.get("services", []):
        _stop_container(svc.get("container") or "")
        stopped += 1
    env["status"] = "booting"
    store.save_env(data_dir, env)
    results = []
    for svc in env.get("services", []):
        try:
            results.append(boot_service(
                data_dir, env, svc["binary_md5"], svc["argv"],
                svc["guest_port"], argv0=svc.get("argv0"),
                name=svc["name"]))
        except EmulError as exc:
            results.append({"name": svc["name"], "error": str(exc)})
    return {"restarted": len(results), "results": results}


def stop_env(data_dir, env: dict, reason: str = "stop") -> dict:
    for svc in env.get("services", []):
        _stop_container(svc.get("container") or "")
        svc["status"] = "stopped"
    env["status"] = "stopped"
    store.env_note(env, f"环境停止（{reason}）")
    store.save_env(data_dir, env)
    return {"env_id": env["env_id"], "status": "stopped"}


def publish_env(data_dir, env: dict, endpoints: list,
                note: str = "") -> dict:
    """编排器复探每个声明端点；全部通过才置 ready（真实性闸门）。"""
    if not endpoints:
        raise EmulError("endpoints 不能为空：[{port, proto, http_path?} | {path}(unix)]")
    probed = []
    all_ok = True
    for ep in endpoints[:12]:
        try:
            res = probe(data_dir, env, ep.get("port"),
                        proto=str(ep.get("proto") or "tcp"),
                        http_path=ep.get("http_path"),
                        http_method="GET" if ep.get("http_path") else None,
                        path=ep.get("path"))
        except EmulError as exc:
            res = {"ok": False, "error": str(exc)}
        probed.append({"port": ep.get("port"),
                       "proto": ep.get("proto") or "tcp",
                       "http_path": ep.get("http_path"),
                       "path": ep.get("path"),
                       "ok": bool(res.get("ok")),
                       "bytes": res.get("bytes"),
                       "preview": (res.get("text") or res.get("error")
                                   or "")[:160]})
        all_ok = all_ok and bool(res.get("ok"))
    if not all_ok:
        env["status"] = "degraded"
        store.env_note(env, "publish 复探未通过，保持 degraded："
                        + json.dumps(probed, ensure_ascii=False)[:400])
        store.save_env(data_dir, env)
        return {"published": False, "status": "degraded",
                "endpoints": probed,
                "hint": "有端点探不通。fw_emul_console 看输出，patch 后 "
                        "reset 再试；探不通禁止宣布就绪。"}
    env["status"] = "ready"
    env["verified_endpoints"] = probed
    if note:
        store.env_note(env, f"就绪：{note[:200]}")
    store.env_note(env, "publish 复探通过：" +
                   json.dumps([p["port"] for p in probed]))
    store.save_env(data_dir, env)
    return {"published": True, "status": "ready", "endpoints": probed}


def reconcile_env(data_dir, env: dict) -> dict:
    """编排器重启后对账：容器没了就把状态收敛到 stopped。"""
    if env.get("status") not in ("booting", "ready", "degraded"):
        return env
    alive = [store.container_alive(s.get("container") or "")
             for s in env.get("services", [])]
    if any(alive):
        if not all(alive):
            env["status"] = "degraded"
            for svc, ok in zip(env["services"], alive):
                svc["status"] = "ok" if ok else "stopped"
            store.save_env(data_dir, env)
        return env
    env["status"] = "stopped"
    store.env_note(env, "编排器对账：服务容器均已消失，置 stopped")
    store.save_env(data_dir, env)
    return env


def console(env: dict, service: str | None = None,
            tail: int = 120) -> dict:
    targets = []
    for svc in env.get("services", []):
        if service and svc["name"] != service:
            continue
        targets.append(svc)
    if not targets:
        raise EmulError("没有匹配的服务（先 fw_emul_boot）")
    out = {}
    for svc in targets:
        out[svc["name"]] = {
            "status": svc["status"], "host_port": svc["host_port"],
            "console": _console_text(
                svc["container"], int(tail),
                Path(env["workspace"]) / f"console-{svc['name']}.log"),
        }
    return out
