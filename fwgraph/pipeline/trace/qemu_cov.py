"""M7 qemu-user coverage runner.

Selects the qemu-user binary for a manifest arch/endianness pair, prepares an
extracted rootfs for chroot execution (proc mount, /tmp, qemu copy, exec
bit), runs the target under `chroot . /<qemu> -d exec -D <log>` with a hard
timeout and process-group cleanup, and parses the exec log into an ordered
list of executed guest PCs.

Verified on Ubuntu 26.04 with qemu-user-binfmt 10.2.1 (binaries are named
/usr/bin/qemu-mips, qemu-arm, ... and are static-pie, so they run inside a
chroot). Two chroot pitfalls discovered empirically:

  - qemu-user reads /proc/sys/vm/mmap_min_addr at startup and exits
    silently (rc=1, no message) when /proc is not mounted in the chroot.
  - EMBA-extracted binaries often lack the exec bit (mode 0664); qemu-user
    then fails silently right after fstat() of the guest. chmod +x first.

qemu 10 `-d exec` line format (guest PC is the 2nd '/'-separated field):
  Trace 0: 0x713468000100 [00000000/0000000000400290/000000e2/00000000]
qemu <= 7 printed the older form, also accepted:
  Trace 0x713468000100 [0x400290]

Sandboxing (S4): the coverage run never needs real root. Where the kernel
allows unprivileged user namespaces, the chroot runs under
`unshare -Urm[n] sh -c 'mount proc; exec chroot ...'` — fake root via uid
map, a private mount namespace for the in-run /proc mount, and no network
for one-shot runs (service runs keep the host net: the readiness probe and
trigger connect from the host over loopback). Ubuntu's
kernel.apparmor_restrict_unprivileged_userns=1 blocks unshare for
unprofiled processes; there the legacy `sudo chroot` path stays, but only
when the operator explicitly sets TRACE_ALLOW_ROOT_CHROOT=1, and every such
run stamps a Chinese warning into its meta (which lands in trace.json).

Sandboxing (Phase 2): SANDBOX_BACKEND=docker (or TRACE_SANDBOX_BACKEND)
with the fwgraph-sandbox image built runs the coverage inside a container
instead — rootfs bind-mounted read-only at its host path plus its top-level
dirs bound over the same container paths (so guest absolute-path opens keep
rootfs semantics without a chroot), one-shot runs get --network none,
service runs publish 127.0.0.1:<port>, the exec log comes back via an
/out bind mount, and the fwgraph-trace-<run_id> container is always
docker rm -f'd. Docker/image unavailable -> the userns/root ruling above.
"""

import ctypes
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from pathlib import PurePosixPath

from pipeline import sandbox

# qemu-user 所在目录（QEMU_BIN_DIR env 可覆盖；测试直接 monkeypatch 本常量）
QEMU_BIN_DIR = os.environ.get("QEMU_BIN_DIR", "/usr/bin")

# (arch, endianness) -> qemu-user binary name. Values match manifest.json
# produced by orchestrator.app.extractor.normalize_arch.
QEMU_MAP = {
    ("mips", "be"): "qemu-mips",
    ("mips", "le"): "qemu-mipsel",
    ("mips64", "be"): "qemu-mips64",
    ("mips64", "le"): "qemu-mips64el",
    ("arm", "le"): "qemu-arm",
    ("arm", "be"): "qemu-armeb",
    ("arm64", "le"): "qemu-aarch64",
    ("arm64", "be"): "qemu-aarch64_be",
    ("x64", "le"): "qemu-x86_64",
    ("x86", "le"): "qemu-i386",
    ("ppc", "be"): "qemu-ppc",
    ("ppc64", "be"): "qemu-ppc64",
    ("ppc64", "le"): "qemu-ppc64le",
    ("riscv", "le"): "qemu-riscv64",
}

# Top-level dirs that mark a filesystem root. Used to locate the rootfs an
# extracted binary belongs to: the shallowest ancestor of the binary whose
# relative path starts with one of these.
ROOTFS_TOPDIRS = {"bin", "sbin", "usr", "lib", "lib64", "etc", "var", "opt",
                  "home", "root", "www", "web", "cgi-bin"}

# qemu 10: "Trace 0: 0xHOST [FLAGS/GUESTPC/...]"
_TRACE_NEW_RE = re.compile(
    r"^Trace \d+: 0x[0-9a-fA-F]+ \[[0-9a-fA-F]+/([0-9a-fA-F]+)")
# qemu <= 7: "Trace 0xHOST [0xGUESTPC]"
_TRACE_OLD_RE = re.compile(r"^Trace 0x[0-9a-fA-F]+ \[0x([0-9a-fA-F]+)\]")
_INTERP_RE = re.compile(r"Requesting program interpreter: ([^]]+)]")
_NEEDED_RE = re.compile(r"Shared library: \[([^]]+)\]")
_SEARCH_PATH_RE = re.compile(r"(?:Library runpath|Library rpath): \[([^]]*)\]")

# docker trace 模式下绑定进容器同名路径的 rootfs 顶层目录：容器内不做
# chroot，guest 运行期的绝对路径 open() 靠这些只读绑定保持 rootfs 文件语义。
# 不含 usr——保护镜像 /usr/bin/qemu-*。不含 etc——盖住 /etc 会让
# docker --read-only 无法挂 hostname。不含 lib/lib64——盖住会把
# qemu 自己的动态链接器换成固件 uclibc，表现为 stat qemu: no such file。
# 固件库靠 qemu -L <rootfs>；固件 /usr/bin/* 走 rootfs 宿主路径 bind。
_DOCKER_BIND_TOPDIRS = ("var", "opt",
                        "home", "root", "www", "web", "cgi-bin")

SUDO_TIMEOUT = 30


class QemuError(RuntimeError):
    """Setup or execution failure of the coverage run."""


def _cfg(name: str, default: str) -> str:
    return os.getenv(name, default)


def qemu_for(arch: str, endianness: str | None) -> str:
    """Resolve the qemu-user binary name for a manifest arch/endianness."""
    key = (arch, endianness or "le")
    name = QEMU_MAP.get(key) or QEMU_MAP.get((arch, "le")) \
        or QEMU_MAP.get((arch, "be"))
    if not name:
        raise QemuError(f"no qemu-user mapping for arch={arch!r} "
                        f"endianness={endianness!r}")
    host_bin = Path(QEMU_BIN_DIR) / name
    if not host_bin.is_file():
        raise QemuError(f"{host_bin} not found (apt-get install "
                        f"qemu-user-binfmt)")
    return name


def find_rootfs(extracted_dir, rel_path: str):
    """Locate (rootfs_path, path_in_rootfs) for a manifest binary path.

    The rootfs is the shallowest ancestor directory of the binary for which
    the binary's relative path starts with a standard top-level dir (bin/,
    usr/, ...). EMBA layouts like
    firmware/binwalk_extracted/.../0/bin/busybox then resolve to
    rootfs=.../0, path_in_rootfs=/bin/busybox, while .../0/usr/sbin/x still
    resolves to the same rootfs (usr/ is not mistaken for the root).
    """
    binary = Path(extracted_dir) / rel_path
    if not binary.is_file():
        raise QemuError(f"binary not found: {binary}")
    stop = Path(extracted_dir).resolve()
    best = None
    ancestor = binary.parent
    # walk up while strictly below extracted_dir; the shallowest ancestor
    # whose relative path starts with a rootfs topdir wins (so usr/ inside a
    # rootfs is never mistaken for the root itself)
    while stop in ancestor.resolve().parents:
        rel = binary.relative_to(ancestor)
        if rel.parts and rel.parts[0] in ROOTFS_TOPDIRS:
            best = ancestor
        ancestor = ancestor.parent
    if best is None:
        raise QemuError(f"cannot locate rootfs for {rel_path} "
                        f"(no bin/sbin/usr/... ancestor)")
    return best, "/" + str(binary.relative_to(best)).replace(os.sep, "/")


def _sudo_prefix() -> list:
    return ["sudo", "-S", "-p", ""] if _sudo_pw() else ["sudo", "-n"]


def _sudo_pw() -> str:
    return _cfg("TRACE_SUDO_PASSWORD", _cfg("EMBA_SUDO_PASSWORD", ""))


def sudo_run(args, timeout=SUDO_TIMEOUT, check=True):
    """Run a command as root; the sudo password is fed on stdin."""
    password = _sudo_pw()
    proc = subprocess.run(_sudo_prefix() + [str(a) for a in args],
                          input=(password + "\n" if password else None),
                          capture_output=True,
                          text=True, timeout=timeout)
    if check and proc.returncode != 0:
        raise QemuError(f"sudo {args[0]} failed rc={proc.returncode}: "
                        f"{(proc.stderr or proc.stdout or '').strip()[-200:]}")
    return proc


# ---------------------------------------------------------------------------
# S4 sandbox: prefer unprivileged user namespaces; sudo-chroot is the
# explicitly-gated fallback.
# ---------------------------------------------------------------------------

ROOT_CHROOT_WARNING = (
    "警告：内核禁止非特权 user namespace，本次 trace 以真实 root 权限 "
    "chroot 运行不可信固件并共享宿主机网络（TRACE_ALLOW_ROOT_CHROOT=1 "
    "已显式开启）。建议在内核允许后改回 unshare 沙箱。")

_USERNS_OK = None


def userns_available() -> bool:
    """Probe (cached per process) whether unprivileged user namespaces work.

    Ubuntu 23.10+ sets kernel.apparmor_restrict_unprivileged_userns=1, which
    makes `unshare -Urn` fail with 'write failed /proc/self/uid_map' for
    unprofiled processes.
    """
    global _USERNS_OK
    if _USERNS_OK is None:
        try:
            _USERNS_OK = subprocess.run(
                ["unshare", "-Urn", "true"],
                capture_output=True, timeout=10).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            _USERNS_OK = False
    return _USERNS_OK


def sandbox_mode() -> str:
    """'userns' when the kernel allows it; 'root' only with the explicit
    TRACE_ALLOW_ROOT_CHROOT=1 opt-in; otherwise refuse to run untrusted
    firmware at all."""
    if userns_available():
        return "userns"
    if _cfg("TRACE_ALLOW_ROOT_CHROOT", "0") == "1":
        return "root"
    raise QemuError(
        "trace 沙箱不可用：内核禁止非特权 user namespace（unshare -Urn 失败），"
        "且未设置 TRACE_ALLOW_ROOT_CHROOT=1。确认接受「以真实 root 运行不可信"
        "固件并共享宿主机网络」的风险后，请在 .env 中显式开启该开关再重试。")


def trace_exec_mode() -> str:
    """本次 trace 的执行后端：docker（SANDBOX_BACKEND / TRACE_SANDBOX_BACKEND
    选中且 docker 与沙箱镜像均可用）优先；否则回退 sandbox_mode() 的
    userns/root 原有裁决。"""
    if (sandbox.backend_for("trace") == "docker"
            and sandbox.sandbox_image_present(sandbox.SANDBOX_IMAGE)):
        return "docker"
    return sandbox_mode()


def _readelf(args, binary: Path) -> str:
    try:
        proc = subprocess.run(["readelf", *args, str(binary)],
                              capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise QemuError(f"readelf failed for {binary}: {exc}") from exc
    if proc.returncode != 0:
        raise QemuError(
            f"readelf failed for {binary}: "
            f"{(proc.stderr or proc.stdout or '').strip()[-300:]}"
        )
    return proc.stdout


def _safe_guest_path(value: str, label: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts:
        raise QemuError(f"unsafe {label} path in ELF: {value!r}")
    return path


def inspect_dynamic_linker(rootfs, target_in_rootfs: str) -> dict:
    """Resolve a dynamic ELF's loader and direct libraries inside its rootfs."""
    rootfs = Path(rootfs)
    target = _safe_guest_path(target_in_rootfs, "target")
    target_host = rootfs / str(target).lstrip("/")
    if not target_host.is_file():
        raise QemuError(f"dynamic-link inspection target missing: {target_host}")

    program_headers = _readelf(["-lW"], target_host)
    interp_match = _INTERP_RE.search(program_headers)
    if not interp_match:
        return {"dynamic": False, "interpreter": None, "sysroot": None,
                "needed": [], "search_paths": []}

    interpreter = str(_safe_guest_path(interp_match.group(1).strip(),
                                       "interpreter"))
    interp_host = rootfs / interpreter.lstrip("/")
    if not interp_host.is_file():
        raise QemuError(
            f"ELF interpreter {interpreter} is absent from rootfs {rootfs}"
        )

    dynamic = _readelf(["-dW"], target_host)
    needed = _NEEDED_RE.findall(dynamic)
    search_paths = []
    for raw in _SEARCH_PATH_RE.findall(dynamic):
        for item in raw.split(":"):
            if not item:
                continue
            expanded = item.replace("$ORIGIN", str(target.parent))
            try:
                search_paths.append(str(_safe_guest_path(expanded, "library search")))
            except QemuError:
                # leftover host RPATH (build-machine paths, "..") is not a
                # guest search dir; DT_NEEDED still resolves via /lib.
                continue
    search_paths.extend(["/lib", "/usr/lib", "/lib32", "/usr/lib32"])

    resolved = {}
    missing = []
    for name in needed:
        if "/" in name:
            candidates = [_safe_guest_path(name, "needed library")]
        else:
            candidates = [PurePosixPath(directory) / name
                          for directory in search_paths]
        match = next((candidate for candidate in candidates
                      if (rootfs / str(candidate).lstrip("/")).is_file()), None)
        if match is None:
            missing.append(name)
        else:
            resolved[name] = str(match)
    if missing:
        raise QemuError(
            f"ELF interpreter {interpreter} found but DT_NEEDED libraries "
            f"are missing: {', '.join(sorted(missing))}"
        )
    return {
        "dynamic": True,
        "interpreter": interpreter,
        "sysroot": "/",
        "needed": needed,
        "search_paths": search_paths,
        "resolved": resolved,
    }


def prepare_rootfs(rootfs, qemu_name: str, target_in_rootfs: str) -> str:
    """Make rootfs ready for coverage; returns the qemu path to execute.

    Idempotent: the qemu binary is (re)copied when missing or different in
    size, the target gets the exec bit (EMBA drops it). /proc handling
    depends on the sandbox mode: root mode mounts <rootfs>/proc via sudo
    (left mounted, as before); userns mode mounts it inside each run's
    private mount namespace instead, so nothing leaks onto the host.
    docker 模式跳过这两者——容器镜像自带 qemu（/usr/bin/<qemu>）、容器自带
    /proc，rootfs 以只读挂载进容器，此处只补目标执行位。
    """
    rootfs = Path(rootfs)
    mode = trace_exec_mode()
    proc_dir = rootfs / "proc"
    proc_dir.mkdir(exist_ok=True)
    if mode == "root":
        mounted = subprocess.run(["mountpoint", "-q", str(proc_dir)],
                                 capture_output=True).returncode == 0
        if not mounted:
            sudo_run(["mount", "-t", "proc", "proc", str(proc_dir)])
    tmp_dir = rootfs / "tmp"
    tmp_dir.mkdir(exist_ok=True)

    def _chmod_x(path):
        try:
            if mode == "root":
                raise OSError("root mode keeps the historical sudo chmod")
            os.chmod(path, 0o755)
        except OSError:
            # root-owned leftovers from earlier sudo runs need sudo once
            sudo_run(["chmod", "+x", str(path)])

    if mode == "docker":
        # 容器内 chroot 进固件 rootfs：必须把宿主 qemu 拷进树，不能用镜像
        # /usr/bin/qemu-*（chroot 后那是固件自己的 /usr/bin）。
        _chmod_x(rootfs / target_in_rootfs.lstrip("/"))
        qemu_dest = rootfs / qemu_name
        qemu_src = Path(QEMU_BIN_DIR) / qemu_name
        if (not qemu_dest.is_file()
                or qemu_dest.stat().st_size != qemu_src.stat().st_size):
            shutil.copyfile(qemu_src, qemu_dest)
        _chmod_x(qemu_dest)
        return "/" + qemu_name

    qemu_dest = rootfs / qemu_name
    qemu_src = Path(QEMU_BIN_DIR) / qemu_name
    if (not qemu_dest.is_file()
            or qemu_dest.stat().st_size != qemu_src.stat().st_size):
        try:
            if mode != "userns":
                raise OSError("root mode keeps the historical sudo cp")
            shutil.copyfile(qemu_src, qemu_dest)
        except OSError:
            sudo_run(["cp", str(qemu_src), str(qemu_dest)])

    _chmod_x(qemu_dest)
    _chmod_x(rootfs / target_in_rootfs.lstrip("/"))
    return "/" + qemu_name


def parse_exec_log(log_path) -> list:
    """Parse a qemu `-d exec` log into ordered unique guest PCs.

    Order is first appearance in the log; re-executions of an already-seen
    TB are dropped. Non-Trace lines (e.g. 'Linking TBs ...') are ignored.
    """
    seen = set()
    addrs = []
    with open(log_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.startswith("Trace"):
                continue
            m = _TRACE_NEW_RE.match(line) or _TRACE_OLD_RE.match(line)
            if not m:
                continue
            pc = int(m.group(1), 16)
            if pc not in seen:
                seen.add(pc)
                addrs.append(pc)
    return addrs


def publish_host_port(guest_port: int) -> int:
    """Host loopback port for docker -p / the trigger probe.

    Guest 22/80 collide with host sshd/http; publishing 127.0.0.1:22:22
    makes docker fail with rc=125. Privileged ports shift to 10000+guest.
    """
    preferred = guest_port if guest_port >= 1024 else 10000 + guest_port
    for cand in (preferred, *range(11000, 12000)):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", cand))
                return cand
            except OSError:
                continue
    raise QemuError(f"no free loopback port to publish guest {guest_port}")


def _call_trigger(trigger, connect_port):
    """New callbacks take the host connect port; old 0-arg lambdas still run."""
    try:
        return trigger(connect_port)
    except TypeError:
        return trigger()


def wait_port(port: int, proc, timeout: float):
    """Poll until 127.0.0.1:port accepts a TCP connection.

    Raises QemuError if the target process exits first or the deadline
    passes. A connection that is immediately refused is not readiness; the
    chroot shares the host network namespace (service runs are exactly the
    case where sandboxing keeps the host net), so host-side probing works.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rc = proc.poll()
        if rc is not None:
            raise QemuError(f"target exited before port {port} was ready "
                            f"(rc={rc})")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.25)
    raise QemuError(f"port {port} not ready within {timeout}s")


# TP-Link httpd dhcps_shm_init: shmget(0x2f, 16384, IPC_CREAT) then another
# 43511 / 73052 segment. Guest often omits mode bits (IPC_CREAT|000); the
# leftover 000 segment makes shmat EACCES and qemu SIGSEGV. Pre-create 0666
# in the same IPC namespace (docker --ipc=host).
_SHM_SEEDS = ((0x2F, 16384), (43511, 131072))
_IPC_CREAT = 0o1000
_IPC_RMID = 0


def seed_sysv_shm(seeds=_SHM_SEEDS):
    """Ensure SysV shm keys exist with mode 0666. Returns created/repaired ids."""
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
    except OSError:
        return []
    out = []
    for key, size in seeds:
        shmid = libc.shmget(int(key), int(size), _IPC_CREAT | 0o666)
        if shmid < 0:
            existing = libc.shmget(int(key), 0, 0)
            if existing >= 0:
                libc.shmctl(existing, _IPC_RMID, None)
            shmid = libc.shmget(int(key), int(size), _IPC_CREAT | 0o666)
        if shmid >= 0:
            out.append(shmid)
    return out


def seed_guest_tmp(rootfs, tmp_dir):
    """Pre-create guest /tmp files qemu-user httpd (and similar) need.

    TP-Link httpd creates /tmp/dec-model.conf with mode 020 then reopens
    O_RDONLY (EACCES → SIGSEGV). An existing 0666 file keeps a readable
    mode. Copy web/oem/model.conf beside it when present.
    """
    tmp_dir = Path(tmp_dir)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    seed = tmp_dir / "dec-model.conf"
    if not seed.exists():
        seed.write_bytes(b"")
    try:
        os.chmod(seed, 0o666)
    except OSError:
        pass
    model = Path(rootfs) / "web" / "oem" / "model.conf"
    if model.is_file():
        dest = tmp_dir / "model.conf"
        if not dest.exists():
            shutil.copyfile(model, dest)
        try:
            os.chmod(dest, 0o666)
        except OSError:
            pass
    for name in ("wr841n", "usbdisk", "userRpm", "dynaform", "login", "help",
                 "frames", "images"):
        (tmp_dir / name).mkdir(exist_ok=True)
    fifo = tmp_dir / "pipe_mud80"
    if not fifo.exists():
        try:
            os.mkfifo(fifo, 0o666)
        except OSError:
            pass


def _with_stdin_redirect(argv, stdin_path):
    return ["sh", "-c", "exec "
            + " ".join(shlex.quote(str(a)) for a in argv)
            + " < " + shlex.quote(str(stdin_path))]


def run_coverage(rootfs, qemu_in_rootfs: str, argv_in_rootfs, run_id: str,
                 port: int | None = None, probe_port: bool = True,
                 ready_timeout: float = 10.0, hold_seconds: float = 2.0,
                 run_timeout: float = 60.0,
                 trigger=None, argv0: str | None = None,
                 sysroot_prefix: str | None = None,
                 host_port: int | None = None,
                 stdin_bytes=None, input_blob=None):
    """One coverage run. Returns (ordered PCs, meta).

    Two lifecycles:
      - service (port given): spawn -> [probe_port: wait for the port] ->
        trigger() -> settle hold_seconds -> SIGTERM the process group.
        Baseline runs pass probe_port=False: the readiness probe is a real
        TCP connect that the service accept()s, and letting it into the
        baseline would subtract the accept/read path from the diff.
      - one-shot (no port): spawn -> wait for natural exit up to
        run_timeout -> SIGTERM if still running (a lingering process is not
        an error; its coverage so far is still collected).
    Hard cap run_timeout on the whole run; exceeding it for a service run
    raises QemuError('timeout'). Leftover qemu processes are reaped by
    pkill on the unique per-run log path (always in the qemu cmdline).
    argv0, when given, is passed as qemu-user's `-0` to forge the guest
    argv[0] — busybox-style multicall binaries dispatch on it, and a
    firmware copy named e.g. busybox-arm would otherwise exit with
    'applet not found'.

    Sandbox (S4 + Phase 2): see module docstring. 'userns' mode runs the
    chroot with fake root and (one-shot only) no network; 'root' mode is the
    gated legacy sudo chroot and stamps ROOT_CHROOT_WARNING into meta;
    'docker' mode runs qemu inside the fwgraph-sandbox image and is cleaned
    up via `docker rm -f fwgraph-trace-<run_id>`.
    """
    rootfs = Path(rootfs).resolve()
    # 2026-09-23：部分固件（D-Link DIR 系）rootfs/tmp 是指向不存在目标的
    # 悬空符号链接——docker 模式把 out_dir bind 到 rootfs/tmp 时目标不存
    # 在，bind 静默失效，qemu -D /tmp/fwgraph-cov-*.log 打不开覆盖日志
    # （挖掘 agent 三连失败的根因）。guest 的 /tmp 本就该是可写目录：
    # 统一替换为真实目录。
    _tmp_host = Path(rootfs) / "tmp"
    if _tmp_host.is_symlink() or not _tmp_host.is_dir():
        if _tmp_host.is_symlink():
            _tmp_host.unlink()
        _tmp_host.mkdir(parents=True, exist_ok=True)
    _tmp_host.chmod(0o777)
    log_in_rootfs = f"/tmp/fwgraph-cov-{run_id}.log"
    log_host = Path(rootfs) / log_in_rootfs.lstrip("/")
    if log_host.exists():
        log_host.unlink()
    mode = trace_exec_mode()
    argv_list = [str(a) for a in argv_in_rootfs]
    log_label = log_in_rootfs
    container = None
    out_dir = None
    if mode == "docker":
        # chroot 进固件 rootfs：guest 的 /etc /web /usr 都是固件的。
        # exec 日志写到 chroot /tmp（把 out_dir bind 上去），宿主编排器再读。
        out_dir = Path(tempfile.mkdtemp(prefix=f"fwgraph-cov-{run_id}-"))
        out_dir.chmod(0o777)
        log_label = f"/tmp/fwgraph-cov-{run_id}.log"
        log_host = out_dir / f"fwgraph-cov-{run_id}.log"
        container = f"fwgraph-trace-{run_id}"
        qemu_argv = (["chroot", str(rootfs), qemu_in_rootfs]
                     + (["-0", argv0] if argv0 else [])
                     + ["-d", "exec", "-D", log_label]
                     + argv_list)
        io_dir = out_dir
        mounts = [
            (str(rootfs), str(rootfs), "ro"),
            (str(out_dir), str(Path(rootfs) / "tmp"), "rw"),
            ("/proc", str(Path(rootfs) / "proc"), "ro"),
        ]
    else:
        qemu_argv = ([qemu_in_rootfs]
                     + (["-0", argv0] if argv0 else [])
                     + (["-L", sysroot_prefix] if sysroot_prefix else [])
                     + ["-d", "exec", "-D", log_in_rootfs]
                     + argv_list)
        io_dir = Path(rootfs) / "tmp"
        io_dir.mkdir(parents=True, exist_ok=True)
    seed_guest_tmp(rootfs, io_dir)
    seed_sysv_shm()
    if stdin_bytes is not None:
        stdin_file = io_dir / "fwgraph-stdin"
        stdin_file.write_bytes(stdin_bytes)
        try:
            os.chmod(stdin_file, 0o666)
        except OSError:
            pass
        # docker: 外层 sh 在容器里、chroot 外；容器 /tmp 是 tmpfs。
        # stdin 文件在 out_dir，bind 到 rootfs/tmp（与 qemu_exec 同路径）。
        # userns/root: sh 已在 chroot 内，读 /tmp/fwgraph-stdin。
        stdin_path = (Path(rootfs) / "tmp" / "fwgraph-stdin"
                      if mode == "docker" else "/tmp/fwgraph-stdin")
        qemu_argv = _with_stdin_redirect(qemu_argv, stdin_path)
    if input_blob:
        name, blob = input_blob
        (io_dir / str(name)).write_bytes(blob or b"")
    if mode == "userns":
        # -U/-r: fake root via uid map; -m: private mount ns so the in-run
        # proc mount dies with the namespace; -n: no network — skipped for
        # service runs, whose readiness probe/trigger must reach the guest
        # over host loopback (a private netns would make it unreachable).
        script = (
            "mount -t proc proc "
            + shlex.quote(str(Path(rootfs) / "proc")) + " 2>/dev/null || :; "
            + "exec chroot " + shlex.quote(str(rootfs)) + " "
            + " ".join(shlex.quote(a) for a in qemu_argv))
        cmd = (["unshare", "-Urm"] + ([] if port else ["-n"])
               + ["sh", "-c", script])
        password = ""
    elif mode != "docker":
        cmd = _sudo_prefix() + ["chroot", str(rootfs)] + qemu_argv
        password = _sudo_pw()
    t0 = time.monotonic()
    if mode == "docker":
        # service 型发布 127.0.0.1:<port>，就绪探针/trigger 逻辑不变；
        # timeout 不传——生命周期由下面 finally 的 docker rm -f 兜底
        if port and host_port is None:
            host_port = publish_host_port(port)
        proc = sandbox.run_sandboxed(
            qemu_argv, image=sandbox.SANDBOX_IMAGE, name=container,
            mounts=mounts, network="bridge" if port else "none",
            ports=[(host_port, port)] if port else None,
            user="0",
            cap_add=["SYS_CHROOT", "NET_BIND_SERVICE"],
            ipc="host",
            sysctls=({"net.ipv4.ip_unprivileged_port_start": "0"}
                     if port else None))
        password = ""
    else:
        proc = subprocess.Popen(cmd,
                                stdin=subprocess.PIPE if password else subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                start_new_session=True, text=True)
    trigger_result = None
    try:
        if password:
            proc.stdin.write(password + "\n")
            proc.stdin.close()
        if port:
            if probe_port:
                wait_port(host_port or port, proc,
                          min(ready_timeout, run_timeout))
            else:
                # baseline: plain startup window — a probe connection would
                # be accept()ed by the service and pollute the diff
                _sleep_or_die(proc, hold_seconds)
            if trigger is not None:
                trigger_result = _call_trigger(trigger, host_port or port)
            _sleep_or_die(proc, hold_seconds)
        else:
            if trigger is not None:
                trigger_result = _call_trigger(trigger, host_port or port)
            _wait_exit(proc, run_timeout)
    finally:
        if mode == "docker":
            # rm -f 具名容器（--rm 仅对自然退出生效），客户端随之退出
            subprocess.run(["docker", "rm", "-f", container],
                           capture_output=True, check=False)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
        else:
            _kill_tree(proc, log_in_rootfs, sudo=(mode == "root"))
    elapsed = time.monotonic() - t0
    if mode == "root":
        # the chrooted qemu runs as real root and writes the exec log with
        # mode 600; the parse step runs as the service user. In userns mode
        # the log is written by (fake-root ->) the invoking user itself.
        sudo_run(["chmod", "644", str(log_host)], check=False)
    try:
        if not log_host.is_file() or log_host.stat().st_size == 0:
            extra = ""
            try:
                if proc.stderr:
                    extra = (proc.stderr.read() or "")[-400:]
            except Exception:
                extra = ""
            raise QemuError(
                f"empty coverage log (target rc={proc.poll()}); "
                f"check qemu can run the binary"
                + (f": {extra.strip()}" if extra.strip() else ""))
        addrs = parse_exec_log(log_host)
    finally:
        if out_dir is not None:
            shutil.rmtree(out_dir, ignore_errors=True)
    meta = {"log": log_label, "tb_count": len(addrs),
            "elapsed_seconds": round(elapsed, 2), "sandbox": mode,
            "sandbox_backend": mode}
    if mode == "docker":
        meta["sandbox_image"] = sandbox.SANDBOX_IMAGE
        meta["sandbox_limits"] = dict(sandbox.DEFAULT_LIMITS)
    if mode == "root":
        meta["sandbox_warning"] = ROOT_CHROOT_WARNING
    if trigger is not None:
        meta["trigger_result"] = trigger_result
    return addrs, meta


def _wait_exit(proc, timeout: float):
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        pass  # still running: caller's finally kills it, coverage stands


def _sleep_or_die(proc, seconds: float):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return  # target exited on its own; caller handles empty log
        time.sleep(0.1)


def _kill_tree(proc, log_in_rootfs: str, sudo: bool = True):
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        if sudo:
            sudo_run(["kill", "-TERM", f"-{proc.pid}"], check=False)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            if sudo:
                sudo_run(["kill", "-KILL", f"-{proc.pid}"], check=False)
        proc.wait(timeout=5)
    # reap any chrooted qemu that survived a group kill (unique log path is
    # always in its cmdline)
    if sudo:
        sudo_run(["pkill", "-f", log_in_rootfs], check=False)
    else:
        subprocess.run(["pkill", "-f", log_in_rootfs],
                       capture_output=True, check=False)
