"""PX4 firmware-container extraction with explicit raw-image provenance."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import struct
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path


MAX_CONTAINER_BYTES = 32 * 1024 * 1024
MAX_IMAGE_BYTES = 64 * 1024 * 1024


class Px4FormatError(ValueError):
    """Raised when a PX4 container is malformed or unsupported."""


@dataclass(frozen=True)
class BoardProfile:
    board_id: int
    board: str
    soc: str
    image_base: int
    vector_offset: int = 0
    arch: str = "arm"
    bits: int = 32
    endianness: str = "le"
    ida_processor: str = "ARM"
    rtos: str = "NuttX"


# These addresses come from the matching PX4 v1.17.0 board linker scripts.
# Keeping this table explicit prevents a plausible-looking reset vector from
# silently creating a wrong immutable function identity.
BOARD_PROFILES = {
    9: BoardProfile(9, "px4_fmu-v3", "STM32F427", 0x08004000),
    11: BoardProfile(11, "px4_fmu-v4", "STM32F427", 0x08004000),
    50: BoardProfile(50, "px4_fmu-v5", "STM32F765", 0x08008000),
    51: BoardProfile(51, "px4_fmu-v5x", "STM32F765", 0x08008000),
    53: BoardProfile(53, "px4_fmu-v6x", "STM32H753", 0x08020000),
    56: BoardProfile(56, "px4_fmu-v6c", "STM32H743", 0x08020000),
    139: BoardProfile(139, "holybro_durandal-v1", "STM32H7", 0x08020000),
    140: BoardProfile(140, "cubepilot_cubeorange", "STM32H7", 0x08020000),
    1009: BoardProfile(1009, "cuav_nora", "STM32H7", 0x08020000),
    1010: BoardProfile(1010, "cuav_x7pro", "STM32H7", 0x08020000),
    1017: BoardProfile(1017, "mro_pixracerpro", "STM32H7", 0x08020000),
    35: BoardProfile(
        35, "px4_fmu-v6xrt", "MIMXRT1176", 0x30020000, vector_offset=0x2000
    ),
}


def looks_like_px4(path, firmware_name: str = "") -> bool:
    """Recognize a PX4FWv1 JSON container without decoding its image."""
    path = Path(path)
    if firmware_name.lower().endswith(".px4"):
        return True
    try:
        head = path.read_bytes()[:4096]
    except OSError:
        return False
    return head.lstrip().startswith(b"{") and b'"PX4FWv1"' in head


def _integer(data: dict, key: str) -> int:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise Px4FormatError(f"PX4 field {key!r} must be an integer")
    return value


def _decode_image(data: dict) -> bytes:
    encoded = data.get("image")
    if not isinstance(encoded, str) or not encoded:
        raise Px4FormatError("PX4 image is missing or not a base64 string")
    try:
        compressed = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise Px4FormatError("PX4 image is not valid base64") from exc

    decoder = zlib.decompressobj()
    try:
        image = decoder.decompress(compressed, MAX_IMAGE_BYTES + 1)
    except zlib.error as exc:
        raise Px4FormatError(f"PX4 image zlib error: {exc}") from exc
    if len(image) > MAX_IMAGE_BYTES or decoder.unconsumed_tail:
        raise Px4FormatError(f"PX4 image exceeds {MAX_IMAGE_BYTES} bytes")
    try:
        image += decoder.flush()
    except zlib.error as exc:
        raise Px4FormatError(f"PX4 image zlib finalization error: {exc}") from exc
    if not decoder.eof or decoder.unused_data:
        raise Px4FormatError("PX4 image has truncated or trailing compressed data")
    if len(image) > MAX_IMAGE_BYTES:
        raise Px4FormatError(f"PX4 image exceeds {MAX_IMAGE_BYTES} bytes")
    return image


def _validate_vectors(image: bytes, profile: BoardProfile) -> tuple[int, int]:
    offset = profile.vector_offset
    if offset < 0 or offset + 8 > len(image):
        raise Px4FormatError(
            f"board {profile.board_id} vector offset is outside the image"
        )
    initial_sp, reset_thumb = struct.unpack_from("<II", image, offset)
    reset = reset_thumb & ~1
    if not (0x20000000 <= initial_sp < 0x40000000):
        raise Px4FormatError(
            f"board {profile.board_id} has implausible initial SP {initial_sp:#x}"
        )
    if not reset_thumb & 1:
        raise Px4FormatError(
            f"board {profile.board_id} reset handler is not Thumb code"
        )
    if not (profile.image_base <= reset < profile.image_base + len(image)):
        raise Px4FormatError(
            f"board {profile.board_id} reset handler {reset:#x} is outside image mapping"
        )
    return initial_sp, reset


def extract_px4(job_id: str, firmware_name: str, firmware_path, log_dir) -> dict:
    """Decode a PX4FWv1 container and write a manifest for IDA raw loading."""
    firmware_path = Path(firmware_path)
    log_dir = Path(log_dir)
    size = firmware_path.stat().st_size
    if size > MAX_CONTAINER_BYTES:
        raise Px4FormatError(f"PX4 container exceeds {MAX_CONTAINER_BYTES} bytes")
    try:
        data = json.loads(firmware_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Px4FormatError(f"invalid PX4 JSON container: {exc}") from exc
    if not isinstance(data, dict) or data.get("magic") != "PX4FWv1":
        raise Px4FormatError("unsupported PX4 magic (expected PX4FWv1)")

    board_id = _integer(data, "board_id")
    image_size = _integer(data, "image_size")
    image_maxsize = _integer(data, "image_maxsize")
    if image_size <= 0 or image_maxsize <= 0 or image_size > image_maxsize:
        raise Px4FormatError("invalid PX4 image_size/image_maxsize")
    profile = BOARD_PROFILES.get(board_id)
    if profile is None:
        raise Px4FormatError(
            f"unsupported PX4 board_id {board_id}; add a linker-verified profile"
        )

    image = _decode_image(data)
    if len(image) != image_size:
        raise Px4FormatError(
            f"PX4 image size mismatch: declared {image_size}, decoded {len(image)}"
        )
    initial_sp, entrypoint = _validate_vectors(image, profile)

    image_md5 = hashlib.md5(image, usedforsecurity=False).hexdigest()
    image_sha256 = hashlib.sha256(image).hexdigest()
    container_sha256 = hashlib.sha256(firmware_path.read_bytes()).hexdigest()
    image_dir = log_dir / "firmware" / "px4"
    image_dir.mkdir(parents=True, exist_ok=True)
    image_path = image_dir / "firmware.bin"
    image_path.write_bytes(image)

    metadata = {
        "format": "PX4FWv1",
        "firmware_name": firmware_name,
        "container_sha256": container_sha256,
        "image_sha256": image_sha256,
        "image_md5": image_md5,
        "image_size": len(image),
        "image_maxsize": image_maxsize,
        "board_revision": data.get("board_revision"),
        "git_identity": data.get("git_identity"),
        "git_hash": data.get("git_hash"),
        "build_time": data.get("build_time"),
        "summary": data.get("summary"),
        "description": data.get("description"),
        "profile": {**asdict(profile),
                    "image_base": f"{profile.image_base:#x}",
                    "vector_offset": f"{profile.vector_offset:#x}"},
        "initial_sp": f"{initial_sp:#x}",
        "entrypoint": f"{entrypoint:#x}",
    }
    (log_dir / "px4_metadata.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )

    binary = {
        "path": "firmware/px4/firmware.bin",
        "arch": profile.arch,
        "bits": profile.bits,
        "endianness": profile.endianness,
        "md5": image_md5,
        "sha256": image_sha256,
        "file_format": "raw",
        "rtos": profile.rtos,
        "board_id": board_id,
        "board": profile.board,
        "soc": profile.soc,
        "loader": {
            "ida_processor": profile.ida_processor,
            "image_base": profile.image_base,
            "vector_offset": profile.vector_offset,
            "initial_sp": initial_sp,
            "entrypoint": entrypoint,
        },
    }
    manifest = {
        "firmware": firmware_name,
        "job_id": job_id,
        "firmware_format": "px4",
        "binaries": [binary],
        "px4": metadata,
        "stats": {
            "total_binaries": 1,
            "extracted_files": 1,
            "by_arch": {profile.arch: 1},
        },
    }
    (log_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return manifest
