"""Unit tests for orchestrator.app.extractor.parse_p99_csv.

The fixture mimics EMBA's csv_logs/p99_prepare_analyzer.csv as written by
binary_architecture_threader (helpers_emba_prepare.sh):
  source;path;class;data;machine;flags;guessed;file(1) output;md5;
(semicolon separated, trailing ';', ';' inside file output replaced by ',').
"""

import pytest

from orchestrator.app import extractor
from orchestrator.app.extractor import normalize_arch, parse_p99_csv

P99_FIXTURE = """\
# p99_prepare_analyzer csv log
P99_prepare_analyzer;/logs/firmware/bin/busybox-mips;ELF32;2's complement, big endian;MIPSR3000;0x50001007,noreorder,pic,cpic,o32,mips2;NA;ELF 32-bit MSB executable, MIPS, MIPS-I version 1 (SYSV), statically linked, stripped;11111111111111111111111111111111;
P99_prepare_analyzer;/logs/firmware/bin/busybox-arm;ELF32;2's complement, little endian;ARM;0x5000200,;NA;ELF 32-bit LSB executable, ARM, EABI4 version 1 (SYSV), statically linked, stripped;22222222222222222222222222222222;
P99_prepare_analyzer;/logs/firmware/lib/libc.so.6;ELF64;2's complement, little endian;AdvancedMicroDevicesX86-64;0x0,;NA;ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, stripped;33333333333333333333333333333333;
P60_deep_extractor;/logs/firmware/sbin/pppd;ELF32;2's complement, big endian;PowerPC;0x0,;NA;ELF 32-bit MSB pie executable, PowerPC or cisco 4500, version 1 (SYSV), dynamically linked, stripped;66666666666666666666666666666666;
P99_prepare_analyzer;/logs/firmware/etc/passwd;NA;NA;NA;NA;NA;ASCII text;44444444444444444444444444444444;
P99_prepare_analyzer;/logs/firmware/lib/util.o;ELF64;2's complement, little endian;AdvancedMicroDevicesX86-64;0x0,;NA;ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped;55555555555555555555555555555555;
P99_prepare_analyzer;/logs/firmware/bin/busybox-mips;ELF32;2's complement, big endian;MIPSR3000;0x50001007,noreorder,pic,cpic,o32,mips2;NA;ELF 32-bit MSB executable, MIPS, MIPS-I version 1 (SYSV), statically linked, stripped;11111111111111111111111111111111;
broken;line

"""


@pytest.fixture()
def csv_file(tmp_path):
    p = tmp_path / "p99_prepare_analyzer.csv"
    p.write_text(P99_FIXTURE, encoding="utf-8")
    return p


def test_parse_keeps_only_elf_executables_and_shared_objects(csv_file):
    bins = parse_p99_csv(csv_file)
    paths = [b["path"] for b in bins]
    # passwd (non-ELF), util.o (relocatable) filtered out; duplicate md5+path dropped
    assert paths == [
        "firmware/bin/busybox-arm",
        "firmware/bin/busybox-mips",
        "firmware/lib/libc.so.6",
        "firmware/sbin/pppd",
    ]


def test_parse_fields(csv_file):
    bins = {b["path"]: b for b in parse_p99_csv(csv_file)}

    mips = bins["firmware/bin/busybox-mips"]
    assert mips == {
        "path": "firmware/bin/busybox-mips",
        "arch": "mips",
        "bits": 32,
        "endianness": "be",
        "md5": "11111111111111111111111111111111",
    }

    arm = bins["firmware/bin/busybox-arm"]
    assert (arm["arch"], arm["bits"], arm["endianness"]) == ("arm", 32, "le")

    libc = bins["firmware/lib/libc.so.6"]
    assert (libc["arch"], libc["bits"], libc["endianness"]) == ("x64", 64, "le")

    pppd = bins["firmware/sbin/pppd"]
    assert (pppd["arch"], pppd["bits"], pppd["endianness"]) == ("ppc", 32, "be")


def test_parse_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        parse_p99_csv(tmp_path / "nope.csv")


def test_parse_empty_file(tmp_path):
    p = tmp_path / "empty.csv"
    p.write_text("", encoding="utf-8")
    assert parse_p99_csv(p) == []


@pytest.mark.parametrize("machine,expected", [
    ("MIPSR3000", "mips"),
    ("ARM", "arm"),
    ("AArch64", "arm64"),
    ("Intel80386", "x86"),
    ("AdvancedMicroDevicesX86-64", "x64"),
    ("PowerPC", "ppc"),
    ("PowerPC64", "ppc64"),
    ("RISC-V", "riscv"),
    ("NA", "unknown"),
])
def test_normalize_arch(machine, expected):
    assert normalize_arch(machine) == expected


class _CaptureStdin:
    def __init__(self):
        self.data = b""
        self.closed = False

    def write(self, data):
        self.data += data

    def close(self):
        self.closed = True


class _FinishedProcess:
    pid = 1234
    returncode = 0

    def __init__(self):
        self.stdin = _CaptureStdin()

    def poll(self):
        return 0


def test_run_emba_keeps_sudo_password_out_of_command(tmp_path, monkeypatch):
    captured = {}

    def fake_popen(command, **options):
        captured["command"] = command
        captured["options"] = options
        captured["process"] = _FinishedProcess()
        return captured["process"]

    monkeypatch.setattr(extractor.subprocess, "Popen", fake_popen)
    monkeypatch.setenv("EMBA_DIR", str(tmp_path))
    monkeypatch.setenv("EMBA_SUDO_PASSWORD", "unit-test-value")

    rc, timed_out = extractor.run_emba(
        tmp_path / "firmware.bin", tmp_path / "logs", tmp_path / "emba.log"
    )

    assert (rc, timed_out) == (0, False)
    assert isinstance(captured["command"], list)
    assert "unit-test-value" not in captured["command"]
    assert captured["command"][:4] == ["sudo", "-S", "-p", ""]
    assert captured["process"].stdin.data == b"unit-test-value\n"
    assert captured["process"].stdin.closed


def test_run_emba_uses_noninteractive_sudo_without_password(tmp_path, monkeypatch):
    captured = {}

    def fake_popen(command, **options):
        captured["command"] = command
        captured["options"] = options
        return _FinishedProcess()

    monkeypatch.setattr(extractor.subprocess, "Popen", fake_popen)
    monkeypatch.setenv("EMBA_DIR", str(tmp_path))
    monkeypatch.delenv("EMBA_SUDO_PASSWORD", raising=False)

    rc, timed_out = extractor.run_emba(
        tmp_path / "firmware.bin", tmp_path / "logs", tmp_path / "emba.log"
    )

    assert (rc, timed_out) == (0, False)
    assert captured["command"][:2] == ["sudo", "-n"]
    assert captured["options"]["stdin"] is extractor.subprocess.DEVNULL
