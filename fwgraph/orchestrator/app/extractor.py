"""Extraction executor for the fwgraph orchestrator (M1).

Runs EMBA with the extract-only profile via subprocess (non-blocking Popen +
polling), then parses csv_logs/p99_prepare_analyzer.csv into manifest.json.

Config (from .env, with defaults matching the dev VM):
  EMBA_BACKEND        script | docker | auto
                      script = sudo ./emba（开发机）
                      docker = 官方镜像 embeddedanalyzer/emba（compose 交付）
                      auto   = 容器内走 docker（官方镜像）
  EMBA_IMAGE          docker 后端镜像（默认 embeddedanalyzer/emba:2.0.3a）
  EMBA_DIR            EMBA repo path            (默认 <仓库根>/emba，即 fwgraph/ 同级)
  EMBA_PROFILE        profile in scan-profiles/ (extract-only.emba)
  EMBA_TIMEOUT        extraction timeout in s   (7200)
  EMBA_SUDO_PASSWORD  sudo password for EMBA    (required unless sudo -n works)
"""

import json
import os
import signal
import subprocess
import threading
import time
from collections import Counter
from pathlib import Path

from . import config

# EMBA uses fixed container names (emba / emba_quest) -> only one run at a time.
EMBA_LOCK = threading.Lock()

# 默认按仓库布局推导：fwgraph/ 与 emba/ 同级（EMBA_DIR env 优先，见 run_emba）
EMBA_DIR_DEFAULT = str(config.FWGRAPH_ROOT.parent / "emba")
EMBA_IMAGE_DEFAULT = "embeddedanalyzer/emba:2.0.3a"
_PROFILE_SRC = (
    Path(__file__).resolve().parents[2] / "pipeline" / "extract" / "extract-only.emba"
)


def _cfg(name: str, default: str) -> str:
    return os.getenv(name, default)


def normalize_arch(machine: str) -> str:
    """Normalize the readelf Machine column (spaces already stripped by EMBA,
    e.g. 'AdvancedMicroDevicesX86-64', 'MIPSR3000', 'Intel80386')."""
    m = machine.lower()
    if "aarch64" in m:
        return "arm64"
    if "arm" in m:
        return "arm"
    if "mips" in m:
        return "mips"
    if "x86-64" in m or "x86_64" in m or "amd64" in m:
        return "x64"
    if "80386" in m or "i386" in m or "x86" in m:
        return "x86"
    if "powerpc64" in m or "ppc64" in m:
        return "ppc64"
    if "powerpc" in m or "ppc" in m:
        return "ppc"
    if "risc-v" in m or "riscv" in m:
        return "riscv"
    return "unknown"


def parse_p99_csv(csv_path, log_dir=None):
    """Parse EMBA's p99_prepare_analyzer.csv into a list of binary dicts.

    Row layout (semicolon separated, trailing ';', written by
    binary_architecture_threader in helpers_emba_prepare.sh):
      source_module;path;ELF class;Data(endianness);Machine;Flags;
      guessed toolchain;file(1) output;MD5;

    Tolerant parsing: comment/empty lines and rows with fewer than 9 fields
    are skipped. Only ELF executables / shared objects are kept.
    """
    csv_path = Path(csv_path)
    if not csv_path.is_file():
        raise FileNotFoundError(f"p99 csv not found: {csv_path}")

    binaries = []
    seen = set()
    with open(csv_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(";")
            if len(parts) < 9:
                continue
            path, elf_class, data, machine = parts[1], parts[2], parts[3], parts[4]
            file_output, md5 = parts[7], parts[8]

            fo = file_output.lower()
            if "elf" not in fo or ("executable" not in fo and "shared object" not in fo):
                continue

            if "ELF64" in elf_class:
                bits = 64
            elif "ELF32" in elf_class:
                bits = 32
            else:
                bits = None

            dl = data.lower()
            if "little" in dl:
                endianness = "le"
            elif "big" in dl:
                endianness = "be"
            else:
                endianness = None

            rel = path
            if path.startswith("/logs/"):
                # container path -> host path relative to the EMBA log dir
                rel = path[len("/logs/"):]
            elif log_dir and os.path.isabs(path):
                try:
                    rel = os.path.relpath(path, log_dir)
                except ValueError:
                    rel = path

            key = (rel, md5)
            if key in seen:
                continue
            seen.add(key)

            binaries.append({
                "path": rel,
                "arch": normalize_arch(machine),
                "bits": bits,
                "endianness": endianness,
                "md5": md5,
            })

    binaries.sort(key=lambda b: b["path"])
    return binaries


def _in_container() -> bool:
    return os.path.exists("/.dockerenv")


def use_docker_backend() -> bool:
    """True when extract should launch the official EMBA image via docker."""
    mode = _cfg("EMBA_BACKEND", "auto").strip().lower()
    if mode == "docker":
        return True
    if mode == "script":
        return False
    return _in_container()


def emba_image_present(image: str | None = None) -> bool:
    image = image or _cfg("EMBA_IMAGE", EMBA_IMAGE_DEFAULT)
    try:
        return subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True, timeout=15).returncode == 0
    except Exception:  # noqa: BLE001 - probe must not raise
        return False


def _ensure_profile() -> Path:
    dest_dir = Path(os.getenv("FWGRAPH_DATA") or config.data_dir()) / "emba"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / "extract-only.emba"
    if _PROFILE_SRC.is_file():
        dest.write_bytes(_PROFILE_SRC.read_bytes())
    elif not dest.is_file():
        dest.write_text("# extract-only placeholder\n", encoding="utf-8")
    return dest


def _docker_emba_cmd(firmware_path, log_dir):
    from pipeline.sandbox.docker_backend import host_mount_path

    image = _cfg("EMBA_IMAGE", EMBA_IMAGE_DEFAULT)
    fw = Path(firmware_path).resolve()
    logs = Path(log_dir).resolve()
    logs.mkdir(parents=True, exist_ok=True)
    profile = _ensure_profile()
    return [
        "docker", "run", "--rm", "--name", "emba",
        "--privileged",
        "--network", "none",
        "--cap-add", "SYS_ADMIN",
        "-v", f"{host_mount_path(fw.parent)}:/firmware:ro",
        "-v", f"{host_mount_path(logs)}:/logs",
        "-v", f"{host_mount_path(profile)}:/emba/scan-profiles/extract-only.emba:ro",
        "--entrypoint", "./emba",
        image,
        "-l", "/logs",
        "-f", f"/firmware/{fw.name}",
        "-p", "./scan-profiles/extract-only.emba",
        "-F", "-y",
    ]


def run_emba(firmware_path, log_dir, stdout_log_path, timeout=None):
    """Run EMBA extract-only on firmware_path, logging to log_dir.

    Returns (returncode, timed_out). EMBA's own stdout/stderr goes to
    stdout_log_path. On timeout the whole process group is killed and the
    leftover EMBA containers are removed.
    """
    timeout = int(timeout or _cfg("EMBA_TIMEOUT", "7200"))
    docker = use_docker_backend()
    if docker:
        cmd = _docker_emba_cmd(firmware_path, log_dir)
        cwd = None
        sudo_pw = ""
    else:
        emba_dir = _cfg("EMBA_DIR", EMBA_DIR_DEFAULT)
        profile = _cfg("EMBA_PROFILE", "extract-only.emba")
        sudo_pw = _cfg("EMBA_SUDO_PASSWORD", "")
        # -F: ignore host-side dependency-check errors (emba_venv / NVD database /
        # inotifywait are missing on this host but unused by dockerized extraction).
        # -y: overwrite a non-empty log dir without an interactive prompt.
        sudo_args = ["-S", "-p", ""] if sudo_pw else ["-n"]
        cmd = [
            "sudo", *sudo_args, "./emba",
            "-l", str(log_dir),
            "-f", str(firmware_path),
            "-p", f"./scan-profiles/{profile}",
            "-F", "-y",
        ]
        cwd = emba_dir

    with EMBA_LOCK, open(stdout_log_path, "wb") as logf:
        logf.write(f"[extractor] cmd: {' '.join(cmd)} (timeout {timeout}s)\n".encode())
        logf.flush()
        if docker and not emba_image_present():
            image = _cfg("EMBA_IMAGE", EMBA_IMAGE_DEFAULT)
            logf.write(
                f"[extractor] 未找到镜像 {image}。"
                f"请先 docker pull {image} 或 "
                f"docker compose --profile tools pull\n".encode())
            return 127, False
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdin=subprocess.PIPE if sudo_pw else subprocess.DEVNULL,
            stdout=logf,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        if sudo_pw:
            proc.stdin.write((sudo_pw + "\n").encode())
            proc.stdin.close()
        deadline = time.monotonic() + timeout
        while proc.poll() is None:
            if time.monotonic() > deadline:
                _kill_emba(proc, logf)
                _chown_output(log_dir)
                return -signal.SIGKILL, True
            time.sleep(5)
        _chown_output(log_dir)
        return proc.returncode, False


def _chown_output(log_dir):
    """Make root-owned EMBA container output readable by the worker user."""
    if os.geteuid() == 0:
        return
    owner = f"{os.getuid()}:{os.getgid()}"
    sudo_pw = _cfg("EMBA_SUDO_PASSWORD", "")
    if sudo_pw:
        proc = subprocess.run(
            ["sudo", "-S", "-p", "", "chown", "-R", owner, str(log_dir)],
            input=sudo_pw + "\n",
            capture_output=True,
            text=True,
            timeout=120,
        )
    else:
        proc = subprocess.run(
            ["sudo", "-n", "chown", "-R", owner, str(log_dir)],
            capture_output=True,
            text=True,
            timeout=120,
        )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[-300:]
        raise RuntimeError(f"cannot take ownership of EMBA output: {detail}")


def _kill_emba(proc, logf):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    # EMBA runs its analysis in detached docker containers; stop them too.
    subprocess.run(["docker", "rm", "-f", "emba", "emba_quest"],
                   capture_output=True, timeout=60)
    proc.wait()
    logf.write(b"[extractor] timeout - EMBA process group killed, containers removed\n")


def unpack_hints(log_dir) -> list[str]:
    """Detect why a firmware tree has no ELF (encryption, empty extract)."""
    log_dir = Path(log_dir)
    text = ""
    for rel in (
        "p02_firmware_bin_file_check/p02_binwalk_output.txt",
        "p50_binwalk_extractor/binwalk-firmware.log",
        "p02_firmware_bin_file_check.txt",
    ):
        path = log_dir / rel
        if path.is_file():
            try:
                text += path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
    hints = []
    low = text.lower()
    if "openssl encryption" in low or "openssl enc" in low:
        hints.append("openssl")
    if "extraction of openssl" in low and "failed" in low:
        hints.append("openssl_failed")
    return hints


def empty_firmware_message(log_dir) -> str:
    hints = unpack_hints(log_dir)
    msg = "解包未发现可反编译的 ELF"
    if "openssl" in hints:
        msg += ("。binwalk 检测到 OpenSSL salted 加密，未提供密钥时无法展开"
                "文件系统，后续反编译不会有输入。")
    else:
        msg += "。可能不是标准 Linux 固件，或解包器未能识别分区/文件系统。"
    return msg


def build_manifest(job_id: str, firmware_name: str, log_dir) -> dict:
    """Parse the p99 CSV under log_dir and write manifest.json next to it."""
    log_dir = Path(log_dir)
    csv_path = log_dir / "csv_logs" / "p99_prepare_analyzer.csv"
    binaries = parse_p99_csv(csv_path, log_dir)

    # hardening profile per binary (native parser, works on sstripped ELFs);
    # a failure here must never break manifest generation
    from pipeline.extract.checksec import checksec
    for b in binaries:
        try:
            b["checksec"] = checksec(log_dir / b["path"])
        except Exception:  # noqa: BLE001
            b["checksec"] = None

    fw_root = log_dir / "firmware"
    extracted_files = (
        sum(len(files) for _, _, files in os.walk(fw_root)) if fw_root.is_dir() else 0
    )
    by_arch = Counter(b["arch"] for b in binaries)

    manifest = {
        "firmware": firmware_name,
        "job_id": job_id,
        "binaries": binaries,
        "stats": {
            "total_binaries": len(binaries),
            "extracted_files": extracted_files,
            "by_arch": dict(sorted(by_arch.items())),
        },
    }
    manifest_path = log_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest
