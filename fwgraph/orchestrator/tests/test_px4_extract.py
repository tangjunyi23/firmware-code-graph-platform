"""PX4FWv1 extraction and raw-loader contract tests."""

import base64
import hashlib
import json
import struct
import zlib

import pytest

from orchestrator.app import decompiler
from pipeline.extract import px4


def _container(image: bytes, **overrides) -> dict:
    data = {
        "magic": "PX4FWv1",
        "board_id": 35,
        "board_revision": 0,
        "image_size": len(image),
        "image_maxsize": 4_063_232,
        "git_identity": "v1.17.0",
        "git_hash": "a" * 40,
        "summary": "PX4FMUv6XRT",
        "description": "test fixture",
        "image": base64.b64encode(zlib.compress(image)).decode("ascii"),
    }
    data.update(overrides)
    return data


def _v6xrt_image() -> bytes:
    image = bytearray(b"\xff" * 0x5000)
    struct.pack_into("<II", image, 0x2000, 0x202587FC, 0x300223A9)
    image[0x23A8:0x23AC] = b"\x00\xbf\x00\xbf"
    return bytes(image)


def test_extract_v6xrt_writes_raw_manifest(tmp_path):
    source = tmp_path / "sample.px4"
    image = _v6xrt_image()
    source.write_text(json.dumps(_container(image)), encoding="utf-8")
    out = tmp_path / "out"

    manifest = px4.extract_px4("job1", "sample.px4", source, out)

    raw = out / "firmware/px4/firmware.bin"
    assert raw.read_bytes() == image
    binary = manifest["binaries"][0]
    assert binary["md5"] == hashlib.md5(image, usedforsecurity=False).hexdigest()
    assert binary["sha256"] == hashlib.sha256(image).hexdigest()
    assert binary["arch"] == "arm"
    assert binary["file_format"] == "raw"
    assert binary["loader"] == {
        "ida_processor": "ARM",
        "image_base": 0x30020000,
        "vector_offset": 0x2000,
        "initial_sp": 0x202587FC,
        "entrypoint": 0x300223A8,
    }
    metadata = json.loads((out / "px4_metadata.json").read_text())
    assert "image" not in metadata
    assert metadata["container_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()


@pytest.mark.parametrize("change,match", [
    ({"magic": "other"}, "magic"),
    ({"board_id": 99999}, "unsupported PX4 board_id"),
    ({"image_size": 1}, "size mismatch"),
])
def test_extract_rejects_bad_container(tmp_path, change, match):
    source = tmp_path / "sample.px4"
    source.write_text(json.dumps(_container(_v6xrt_image(), **change)), encoding="utf-8")
    with pytest.raises(px4.Px4FormatError, match=match):
        px4.extract_px4("job1", "sample.px4", source, tmp_path / "out")


def test_extract_rejects_wrong_vector_profile(tmp_path):
    image = bytearray(_v6xrt_image())
    struct.pack_into("<I", image, 0x2004, 0x080041A9)
    source = tmp_path / "sample.px4"
    source.write_text(json.dumps(_container(bytes(image))), encoding="utf-8")
    with pytest.raises(px4.Px4FormatError, match="outside image mapping"):
        px4.extract_px4("job1", "sample.px4", source, tmp_path / "out")


def test_raw_ida_command_contains_verified_loader_options(tmp_path):
    binary = {
        "file_format": "raw",
        "arch": "arm",
        "bits": 32,
        "endianness": "le",
        "loader": {
            "ida_processor": "ARM",
            "image_base": 0x30020000,
            "entrypoint": 0x300223A8,
        },
    }
    cmd = decompiler._ida_command(
        tmp_path / "idat", tmp_path / "input", tmp_path / "out", binary
    )
    assert "-pARM:ARMv7-M" in cmd
    assert "-b3002000" in cmd
    assert "-TBinary file" in cmd
    assert "--raw-entry=0x300223a8" in cmd[-2]
    assert cmd[-1] == str(tmp_path / "input")


def test_raw_ida_command_requires_verified_entrypoint(tmp_path):
    binary = {
        "file_format": "raw",
        "bits": 32,
        "endianness": "le",
        "loader": {"ida_processor": "ARM", "image_base": 0x30020000},
    }
    with pytest.raises(ValueError, match="verified entrypoint"):
        decompiler._ida_command(
            tmp_path / "idat", tmp_path / "input", tmp_path / "out", binary
        )


def test_raw_idb_reuse_does_not_force_loader_again(tmp_path):
    binary = {
        "file_format": "raw",
        "bits": 32,
        "endianness": "le",
        "loader": {
            "ida_processor": "ARM",
            "image_base": 0x30020000,
            "entrypoint": 0x300223A8,
        },
    }
    cmd = decompiler._ida_command(
        tmp_path / "idat", tmp_path / "input.i64", tmp_path / "out", binary
    )
    assert "-pARM:ARMv7-M" not in cmd
    assert not any(arg.startswith("-b") for arg in cmd)
    assert "-TBinary file" not in cmd
    assert "--raw-entry=0x300223a8" in cmd[-2]


def test_raw_arm_uses_cortex_m_processor_profile(monkeypatch):
    monkeypatch.delenv("ARM_DEFAULT_ARCHITECTURE", raising=False)
    env = decompiler._ida_environment({"file_format": "raw", "arch": "arm"})
    assert env["TVHEADLESS"] == "1"
    assert env["ARM_DEFAULT_ARCHITECTURE"] == "ARMv7-M"


def test_elf_ida_command_does_not_force_raw_loader(tmp_path):
    cmd = decompiler._ida_command(
        tmp_path / "idat", tmp_path / "input", tmp_path / "out", {"arch": "mips"}
    )
    assert not any(arg.startswith("-p") for arg in cmd)
    assert not any(arg.startswith("-b") for arg in cmd)
