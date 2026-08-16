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
"""

import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import time
from pathlib import Path
from pathlib import PurePosixPath

QEMU_BIN_DIR = "/usr/bin"

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
                  "home", "root", "www", "cgi-bin"}

# qemu 10: "Trace 0: 0xHOST [FLAGS/GUESTPC/...]"
_TRACE_NEW_RE = re.compile(
    r"^Trace \d+: 0x[0-9a-fA-F]+ \[[0-9a-fA-F]+/([0-9a-fA-F]+)")
# qemu <= 7: "Trace 0xHOST [0xGUESTPC]"
_TRACE_OLD_RE = re.compile(r"^Trace 0x[0-9a-fA-F]+ \[0x([0-9a-fA-F]+)\]")
_INTERP_RE = re.compile(r"Requesting program interpreter: ([^]]+)]")
_NEEDED_RE = re.compile(r"Shared library: \[([^]]+)\]")
_SEARCH_PATH_RE = re.compile(r"(?:Library runpath|Library rpath): \[([^]]*)\]")

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
            search_paths.append(str(_safe_guest_path(expanded, "library search")))
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
    """Make rootfs ready for chroot coverage; returns qemu path in rootfs.

    Idempotent: the qemu binary is (re)copied when missing or different in
    size, the target gets the exec bit (EMBA drops it). /proc handling
    depends on the sandbox mode: root mode mounts <rootfs>/proc via sudo
    (left mounted, as before); userns mode mounts it inside each run's
    private mount namespace instead, so nothing leaks onto the host.
    """
    rootfs = Path(rootfs)
    mode = sandbox_mode()
    proc_dir = rootfs / "proc"
    proc_dir.mkdir(exist_ok=True)
    if mode == "root":
        mounted = subprocess.run(["mountpoint", "-q", str(proc_dir)],
                                 capture_output=True).returncode == 0
        if not mounted:
            sudo_run(["mount", "-t", "proc", "proc", str(proc_dir)])
    tmp_dir = rootfs / "tmp"
    tmp_dir.mkdir(exist_ok=True)
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

    def _chmod_x(path):
        try:
            if mode != "userns":
                raise OSError("root mode keeps the historical sudo chmod")
            os.chmod(path, 0o755)
        except OSError:
            # root-owned leftovers from earlier sudo runs need sudo once
            sudo_run(["chmod", "+x", str(path)])

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


def run_coverage(rootfs, qemu_in_rootfs: str, argv_in_rootfs, run_id: str,
                 port: int | None = None, probe_port: bool = True,
                 ready_timeout: float = 10.0, hold_seconds: float = 2.0,
                 run_timeout: float = 60.0,
                 trigger=None, argv0: str | None = None,
                 sysroot_prefix: str | None = None):
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

    Sandbox (S4): see module docstring. 'userns' mode runs the chroot with
    fake root and (one-shot only) no network; 'root' mode is the gated
    legacy sudo chroot and stamps ROOT_CHROOT_WARNING into meta.
    """
    log_in_rootfs = f"/tmp/fwgraph-cov-{run_id}.log"
    log_host = Path(rootfs) / log_in_rootfs.lstrip("/")
    if log_host.exists():
        log_host.unlink()
    mode = sandbox_mode()
    qemu_argv = ([qemu_in_rootfs]
                 + (["-0", argv0] if argv0 else [])
                 + (["-L", sysroot_prefix] if sysroot_prefix else [])
                 + ["-d", "exec", "-D", log_in_rootfs]
                 + [str(a) for a in argv_in_rootfs])
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
    else:
        cmd = _sudo_prefix() + ["chroot", str(rootfs)] + qemu_argv
        password = _sudo_pw()
    t0 = time.monotonic()
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
                wait_port(port, proc, min(ready_timeout, run_timeout))
            else:
                # baseline: plain startup window — a probe connection would
                # be accept()ed by the service and pollute the diff
                _sleep_or_die(proc, hold_seconds)
            if trigger is not None:
                trigger_result = trigger()
            _sleep_or_die(proc, hold_seconds)
        else:
            if trigger is not None:
                trigger_result = trigger()
            _wait_exit(proc, run_timeout)
    finally:
        _kill_tree(proc, log_in_rootfs, sudo=(mode == "root"))
    elapsed = time.monotonic() - t0
    if mode == "root":
        # the chrooted qemu runs as real root and writes the exec log with
        # mode 600; the parse step runs as the service user. In userns mode
        # the log is written by (fake-root ->) the invoking user itself.
        sudo_run(["chmod", "644", str(log_host)], check=False)
    if not log_host.is_file() or log_host.stat().st_size == 0:
        raise QemuError(f"empty coverage log (target rc={proc.poll()}); "
                        f"check qemu can run the binary")
    addrs = parse_exec_log(log_host)
    meta = {"log": log_in_rootfs, "tb_count": len(addrs),
            "elapsed_seconds": round(elapsed, 2), "sandbox": mode}
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
