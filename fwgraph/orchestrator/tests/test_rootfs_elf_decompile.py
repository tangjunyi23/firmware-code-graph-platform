"""rootfs_elf is the ELF decompiler; adapter maps its files to symbols.json."""

import json
from pathlib import Path

import pytest

from orchestrator.app import decompiler
from pipeline.decompile.rootfs_elf_adapt import adapt_rootfs_elf_outdir


def _write_index(outdir: Path, rows: list[dict]):
    (outdir / "function_index.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def _write_decompile(outdir: Path, ea: int, name: str, body: str):
    d = outdir / "decompile"
    d.mkdir(parents=True, exist_ok=True)
    text = (
        "/*\n"
        f" * func-name: {name}\n"
        f" * func-address: {hex(ea)}\n"
        " * callers: none\n"
        " * callees: none\n"
        " */\n"
        "\n"
        f"{body}\n"
    )
    (d / f"{name}_{ea:X}.c").write_text(text, encoding="utf-8")


def test_adapt_writes_functions_and_symbols_raw(tmp_path):
    out = tmp_path / "export"
    out.mkdir()
    _write_index(out, [
        {"name": "main", "address": "0x401000",
         "callees": ["0x401100"], "is_entry_candidate": True},
        {"name": "strcpy", "address": "0x401100",
         "callees": [], "is_entry_candidate": False},
    ])
    _write_decompile(out, 0x401000, "main",
                     'int main() { strcpy("admin_password"); return 0; }')
    _write_decompile(out, 0x401100, "strcpy", "char *strcpy(char *d, char *s);")
    (out / "exports.txt").write_text(
        "# Exports\n0x401000:main\n", encoding="utf-8")

    done = adapt_rootfs_elf_outdir(out, {"arch": "mips", "bits": 32,
                                         "endianness": "be"})
    assert done["status"] == "ok"
    assert done["exporter"] == "rootfs_elf"
    assert done["functions"] == 2
    assert done["decompiled"] == 2

    src = (out / "functions" / "0x401000.c").read_text(encoding="utf-8")
    assert src.startswith("// addr=0x401000 name=main arch=mips32be size=0\n")
    assert "int main()" in src
    assert "func-address" not in src

    raw = json.loads((out / "symbols_raw.json").read_text(encoding="utf-8"))
    main = next(f for f in raw["functions"] if f["name"] == "main")
    assert main["is_exported"] is True
    assert main["calls"] == ["strcpy"]
    assert "admin_password" in main["strings"]
    assert main["decompile_ok"] is True


def test_adapt_without_decompile_file_keeps_symbol(tmp_path):
    out = tmp_path / "export"
    out.mkdir()
    _write_index(out, [
        {"name": "sub_400", "address": "0x400", "callees": []},
    ])
    done = adapt_rootfs_elf_outdir(out, {})
    assert done["status"] == "ok"
    assert done["decompiled"] == 0
    raw = json.loads((out / "symbols_raw.json").read_text(encoding="utf-8"))
    assert raw["functions"][0]["decompile_ok"] is False
    assert not (out / "functions" / "0x400.c").exists()


def test_adapt_empty_export_is_error(tmp_path):
    out = tmp_path / "export"
    out.mkdir()
    done = adapt_rootfs_elf_outdir(out, {})
    assert done["status"] == "error"
    assert "no functions" in done["error"]


def test_elf_command_uses_rootfs_elf_worker(tmp_path, monkeypatch):
    monkeypatch.setenv("IDA_DIR", str(tmp_path / "ida"))
    cmd = decompiler._rootfs_elf_command(tmp_path / "busybox", tmp_path / "out")
    assert cmd[0]
    assert cmd[1].endswith("ida_worker.py")
    assert "ida_export.py" not in " ".join(cmd)
    assert "--skip-memory" in cmd
    assert "--ida-dir" in cmd


def test_decompile_binary_dispatches_elf_to_rootfs_elf(tmp_path, monkeypatch):
    called = []

    def fake_elf(job_id, binary, data_dir, timeout):
        called.append("elf")
        return {"status": "ok", "exporter": "rootfs_elf"}

    def fake_idat(job_id, binary, data_dir, timeout):
        called.append("idat")
        return {"status": "ok", "exporter": "ida_export"}

    monkeypatch.setattr(decompiler, "_decompile_binary_rootfs_elf", fake_elf)
    monkeypatch.setattr(decompiler, "_decompile_binary_idat", fake_idat)
    decompiler._decompile_binary("job", {"md5": "a" * 32, "path": "bin/a"},
                                 tmp_path, 10)
    decompiler._decompile_binary(
        "job",
        {"md5": "b" * 32, "path": "fw.bin", "file_format": "raw"},
        tmp_path, 10)
    assert called == ["elf", "idat"]


def test_rootfs_elf_worker_success_adapts(tmp_path, monkeypatch):
    job = "rootfsjob001"
    md5 = "c" * 32
    ext = tmp_path / "extracted" / job
    ext.mkdir(parents=True)
    elf = ext / "bin" / "httpd"
    elf.parent.mkdir()
    elf.write_bytes(b"\x7fELF")
    outdir = tmp_path / "pseudocode" / job / md5

    class FakeProc:
        returncode = 0

        def poll(self):
            return 0

        def wait(self):
            return 0

    def fake_popen(cmd, stdout=None, stderr=None, env=None,
                   start_new_session=None):
        assert "ida_worker.py" in cmd[1]
        outdir.mkdir(parents=True, exist_ok=True)
        _write_index(outdir, [
            {"name": "httpd_main", "address": "0x1000", "callees": []},
        ])
        _write_decompile(outdir, 0x1000, "httpd_main", "void httpd_main() {}")
        return FakeProc()

    monkeypatch.setattr(decompiler.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(decompiler.config, "ida_dir",
                        lambda: Path("/opt/ida-pro-9.1"))
    result = decompiler._decompile_binary(
        job,
        {"md5": md5, "path": "bin/httpd", "arch": "mips", "bits": 32,
         "endianness": "le"},
        tmp_path, timeout=30)
    assert result["status"] == "ok"
    assert result["exporter"] == "rootfs_elf"
    assert result["functions"] == 1
    assert result["decompiled"] == 1
    assert (outdir / "functions" / "0x1000.c").is_file()
    assert (outdir / "symbols_raw.json").is_file()
