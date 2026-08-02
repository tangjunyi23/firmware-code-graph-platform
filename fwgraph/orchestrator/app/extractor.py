"""Extraction executor for the fwgraph orchestrator (M1).

Runs EMBA with the extract-only profile via subprocess (non-blocking Popen +
polling), then parses csv_logs/p99_prepare_analyzer.csv into manifest.json.

Config (from .env, with defaults matching the dev VM):
  EMBA_DIR            EMBA repo path            (/home/tankuku/firmware-graph/emba)
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

# EMBA uses fixed container names (emba / emba_quest) -> only one run at a time.
EMBA_LOCK = threading.Lock()

EMBA_DIR_DEFAULT = "/home/tankuku/firmware-graph/emba"


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


def run_emba(firmware_path, log_dir, stdout_log_path, timeout=None):
    """Run EMBA extract-only on firmware_path, logging to log_dir.

    Returns (returncode, timed_out). EMBA's own stdout/stderr goes to
    stdout_log_path. On timeout the whole process group is killed and the
    leftover EMBA containers are removed.
    """
    emba_dir = _cfg("EMBA_DIR", EMBA_DIR_DEFAULT)
    profile = _cfg("EMBA_PROFILE", "extract-only.emba")
    sudo_pw = _cfg("EMBA_SUDO_PASSWORD", "")
    timeout = int(timeout or _cfg("EMBA_TIMEOUT", "7200"))

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
    with EMBA_LOCK, open(stdout_log_path, "wb") as logf:
        logf.write(f"[extractor] cmd: sudo ./emba -l {log_dir} -f {firmware_path} "
                   f"-p ./scan-profiles/{profile} -F -y (timeout {timeout}s)\n".encode())
        logf.flush()
        proc = subprocess.Popen(
            cmd,
            cwd=emba_dir,
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
                return -signal.SIGKILL, True
            time.sleep(5)
        return proc.returncode, False


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


def build_manifest(job_id: str, firmware_name: str, log_dir) -> dict:
    """Parse the p99 CSV under log_dir and write manifest.json next to it."""
    log_dir = Path(log_dir)
    csv_path = log_dir / "csv_logs" / "p99_prepare_analyzer.csv"
    binaries = parse_p99_csv(csv_path, log_dir)

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
