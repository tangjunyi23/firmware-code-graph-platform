"""Firmware unwrap / vendor-container identification.

Runs automatically after upload. This module only:

  * fingerprints the uploaded image
  * strips published vendor headers
  * inflates gzip / zlib / xz / zip wrappers
  * carves a known inner filesystem if it sits after a header

It does not brute-force unknown keys, talk to live devices, or recover
session material. Encrypted containers that cannot be unwrapped are marked
``identified`` so EMBA can still try its extractors.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import math
import re
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

try:
    import lzma
except ImportError:  # pragma: no cover
    lzma = None


SCAN_BYTES = 2 * 1024 * 1024
ENTROPY_WINDOW = 64 * 1024
MAX_OUT_BYTES = 2 * 1024**3

# Long signatures only — 2-byte magics are too collision-prone for a scan.
INNER_MAGICS = (
    (b"hsqs", "squashfs"),
    (b"sqsh", "squashfs"),
    (b"qshs", "squashfs"),
    (b"shsq", "squashfs"),
    (b"\x45\x3d\xcd\x28", "cramfs"),
    (b"UBI#", "ubi"),
    (b"UBI!", "ubi-ec"),
    (b"\x27\x05\x19\x56", "uimage"),
    (b"HDR0", "trx"),
    (b"\x7fELF", "elf"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"PK\x03\x04", "zip"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"7z\xbc\xaf'\x1c", "7z"),
    (b"ANDROID!", "android-boot"),
    (b"hsqt", "squashfs"),
)

HEAD_MAGICS = INNER_MAGICS + (
    (b"SHRS", "dlink-shrs"),
    (b"DHTB", "dlink-dhtb"),
    (b"HDR1", "xiaomi-hdr1"),
    (b"HDR2", "xiaomi-hdr2"),
    (b"Salted__", "openssl-enc"),
    (b"encrpted", "foscam"),
    (b"ENCRYPTED", "generic-enc"),
)

VENDOR_RX = (
    (re.compile(r"tplink|tp-link|archer|deco|merc", re.I), "TP-Link"),
    (re.compile(r"xiaomi|redmi|miwifi", re.I), "小米"),
    (re.compile(r"dlink|d-link", re.I), "D-Link"),
    (re.compile(r"netgear", re.I), "NETGEAR"),
    (re.compile(r"asus", re.I), "华硕"),
    (re.compile(r"huawei|honor", re.I), "华为"),
    (re.compile(r"zyxel", re.I), "Zyxel"),
    (re.compile(r"buffalo", re.I), "Buffalo"),
    (re.compile(r"foscam", re.I), "Foscam"),
    (re.compile(r"dahua", re.I), "大华"),
    (re.compile(r"hikvision", re.I), "海康"),
    (re.compile(r"openwrt", re.I), "OpenWrt"),
)

COMMON_OFFSETS = (
    0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x1400,
    0x2000, 0x4000, 0x8000, 0x10000,
)

PLAIN_KINDS = {
    "squashfs", "cramfs", "ubi", "ubi-ec", "uimage", "trx", "elf",
    "android-boot", "jffs2",
}
WRAP_KINDS = {"gzip", "zip", "xz", "7z", "zlib"}
ENC_KINDS = {
    "dlink-shrs", "dlink-dhtb", "xiaomi-hdr1", "xiaomi-hdr2",
    "openssl-enc", "foscam", "generic-enc",
}

STEPS = (
    ("read", "读取固件"),
    ("fingerprint", "识别格式"),
    ("unwrap", "解密 / 剥离容器"),
    ("verify", "校验内部镜像"),
    ("done", "完成"),
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 3)


def _vendor(name: str, blob: bytes) -> str:
    text = name or ""
    for rx, label in VENDOR_RX:
        if rx.search(text):
            return label
    head = blob[:4096]
    if b"TP-LINK" in head or b"tp-link" in head or b"fw-type:" in head:
        return "TP-Link"
    if b"xiaomi" in head.lower() or head.startswith((b"HDR1", b"HDR2")):
        return "小米"
    if head.startswith((b"SHRS", b"DHTB")):
        return "D-Link"
    return "未知"


def _match_at(data: bytes, offset: int, table=INNER_MAGICS) -> str | None:
    if offset < 0 or offset >= len(data):
        return None
    window = data[offset:offset + 16]
    for magic, kind in table:
        if window.startswith(magic):
            return kind
    if offset == 0 and len(data) >= 2 and data[0] == 0x78 and data[1] in (0x01, 0x9C, 0xDA):
        return "zlib"
    return None


def find_inners(data: bytes, limit: int = SCAN_BYTES) -> list[dict]:
    region = data[:limit]
    hits = []
    seen = set()
    for magic, kind in INNER_MAGICS:
        start = 0
        while True:
            pos = region.find(magic, start)
            if pos < 0:
                break
            key = (kind, pos)
            if key not in seen:
                seen.add(key)
                hits.append({"kind": kind, "offset": pos})
            start = pos + 1
            if len(hits) >= 12:
                return hits
    return hits


def fingerprint(data: bytes, name: str = "") -> dict:
    head_kind = _match_at(data, 0, HEAD_MAGICS) or _match_at(data, 0)
    inners = find_inners(data)
    sample = data[:ENTROPY_WINDOW]
    mid = data[65536:65536 + ENTROPY_WINDOW] if len(data) > 65536 else b""
    ent = _entropy(sample)
    ent_mid = _entropy(mid) if mid else ent
    vendor = _vendor(name, data)
    encrypted = head_kind in ENC_KINDS
    if head_kind is None and ent >= 7.6 and not inners:
        encrypted = True
        head_kind = head_kind or "high-entropy"
    return {
        "head_kind": head_kind or "unknown",
        "inners": inners,
        "entropy": ent,
        "entropy_mid": ent_mid,
        "vendor": vendor,
        "encrypted": encrypted,
        "size": len(data),
    }


def _write_json(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def _step(steps: list[dict], sid: str, status: str, detail: str = "", pct: int | None = None):
    for row in steps:
        if row["id"] == sid:
            row["status"] = status
            if detail:
                row["detail"] = detail
            if pct is not None:
                row["pct"] = pct
            return
    rec = {"id": sid, "label": dict(STEPS).get(sid, sid),
           "status": status, "detail": detail}
    if pct is not None:
        rec["pct"] = pct
    steps.append(rec)


def _log(doc: dict, line: str) -> None:
    doc.setdefault("log", []).append(f"{_now()}  {line}")
    if len(doc["log"]) > 80:
        del doc["log"][:-80]


def _emit(doc: dict, out_dir: Path, cb) -> None:
    doc["updated_at"] = _now()
    _write_json(out_dir / "decrypt.json", doc)
    if cb:
        cb(doc)


def _carve(src: Path, dest: Path, offset: int) -> int:
    written = 0
    with src.open("rb") as fh, dest.open("wb") as out:
        fh.seek(offset)
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            written += len(chunk)
            if written > MAX_OUT_BYTES:
                raise ValueError("剥离结果超过 2GB 上限")
            out.write(chunk)
    return written


def _inflate_gzip(src: Path, dest: Path) -> int:
    written = 0
    with gzip.open(src, "rb") as fh, dest.open("wb") as out:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            written += len(chunk)
            if written > MAX_OUT_BYTES:
                raise ValueError("解压结果超过 2GB 上限")
            out.write(chunk)
    return written


def _inflate_zlib(data: bytes, dest: Path) -> int:
    raw = zlib.decompress(data)
    if len(raw) > MAX_OUT_BYTES:
        raise ValueError("解压结果超过 2GB 上限")
    dest.write_bytes(raw)
    return len(raw)


def _inflate_xz(src: Path, dest: Path) -> int:
    if lzma is None:
        raise ValueError("当前环境没有 lzma")
    written = 0
    with lzma.open(src, "rb") as fh, dest.open("wb") as out:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            written += len(chunk)
            if written > MAX_OUT_BYTES:
                raise ValueError("解压结果超过 2GB 上限")
            out.write(chunk)
    return written


def _inflate_zip(src: Path, dest: Path) -> int:
    with zipfile.ZipFile(src) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if not infos:
            raise ValueError("zip 里没有文件")
        infos.sort(key=lambda i: i.file_size, reverse=True)
        chosen = infos[0]
        written = 0
        with zf.open(chosen) as fh, dest.open("wb") as out:
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_OUT_BYTES:
                    raise ValueError("解压结果超过 2GB 上限")
                out.write(chunk)
        return written


def _verify_file(path: Path) -> list[str]:
    head = path.read_bytes()[:SCAN_BYTES] if path.is_file() else b""
    kinds = []
    kind0 = _match_at(head, 0)
    if kind0:
        kinds.append(kind0)
    for hit in find_inners(head):
        if hit["kind"] not in kinds:
            kinds.append(hit["kind"])
    return kinds


def empty_report(job_id: str, firmware: str = "") -> dict:
    return {
        "job_id": job_id,
        "firmware": firmware,
        "status": "none",
        "needed": False,
        "progress": 0,
        "stage": "idle",
        "stage_label": "尚未分析",
        "vendor": "未知",
        "method": "",
        "cipher": "",
        "entropy": 0,
        "inner": [],
        "output": None,
        "output_sha256": None,
        "error": None,
        "steps": [{"id": sid, "label": label, "status": "wait", "detail": ""}
                  for sid, label in STEPS],
        "log": [],
        "updated_at": _now(),
    }


def run_job(job_id: str, firmware: str, src: Path, out_dir: Path,
            progress_cb=None) -> dict:
    """Fingerprint and unwrap ``src`` into ``out_dir``. Always writes decrypt.json."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    doc = empty_report(job_id, firmware)
    doc["status"] = "running"
    doc["stage"] = "read"
    doc["stage_label"] = "正在读取固件"
    doc["progress"] = 8
    _step(doc["steps"], "read", "now", pct=8)
    _log(doc, f"开始分析 {firmware or src.name}")
    _emit(doc, out_dir, progress_cb)

    if not Path(src).is_file():
        doc["status"] = "failed"
        doc["error"] = "找不到上传的固件文件"
        doc["progress"] = 0
        _step(doc["steps"], "read", "err", doc["error"])
        _log(doc, doc["error"])
        _emit(doc, out_dir, progress_cb)
        return doc

    size = src.stat().st_size
    head = src.read_bytes()[:SCAN_BYTES]
    md5 = hashlib.md5(head, usedforsecurity=False).hexdigest()
    doc["size_bytes"] = size
    doc["head_md5"] = md5
    _step(doc["steps"], "read", "ok", f"{size} 字节", pct=18)
    doc["progress"] = 18
    doc["stage"] = "fingerprint"
    doc["stage_label"] = "正在识别格式"
    _step(doc["steps"], "fingerprint", "now", pct=22)
    _emit(doc, out_dir, progress_cb)

    info = fingerprint(head, firmware)
    doc["vendor"] = info["vendor"]
    doc["entropy"] = info["entropy"]
    doc["inner"] = [h["kind"] for h in info["inners"][:8]]
    doc["head_kind"] = info["head_kind"]
    _log(doc, f"格式 {info['head_kind']} · 熵 {info['entropy']} · 厂商 {info['vendor']}")
    _step(doc["steps"], "fingerprint", "ok",
          f"{info['head_kind']} / 熵 {info['entropy']}", pct=34)
    doc["progress"] = 34
    _emit(doc, out_dir, progress_cb)

    dest = out_dir / "firmware.dec.bin"
    unwrapped = False
    method = ""
    cipher = "none"
    needed = False

    head_kind = info["head_kind"]
    inners = info["inners"]
    first_inner = next((h for h in inners if h["offset"] > 0), None)
    plain_at_zero = head_kind in PLAIN_KINDS

    doc["stage"] = "unwrap"
    doc["stage_label"] = "正在解密 / 剥离容器"
    _step(doc["steps"], "unwrap", "now", pct=42)
    _emit(doc, out_dir, progress_cb)

    try:
        if plain_at_zero:
            method = "plain"
            needed = False
            _log(doc, "镜像头部已是可解包格式，无需解密")
        elif head_kind == "gzip":
            needed = True
            n = _inflate_gzip(src, dest)
            unwrapped = True
            method = "gzip"
            cipher = "deflate"
            _log(doc, f"gzip 解压完成，{n} 字节")
        elif head_kind == "zlib":
            needed = True
            n = _inflate_zlib(src.read_bytes(), dest)
            unwrapped = True
            method = "zlib"
            cipher = "deflate"
            _log(doc, f"zlib 解压完成，{n} 字节")
        elif head_kind == "xz":
            needed = True
            n = _inflate_xz(src, dest)
            unwrapped = True
            method = "xz"
            cipher = "lzma2"
            _log(doc, f"xz 解压完成，{n} 字节")
        elif head_kind == "zip":
            needed = True
            n = _inflate_zip(src, dest)
            unwrapped = True
            method = "zip"
            _log(doc, f"zip 取出最大文件，{n} 字节")
        elif first_inner:
            needed = True
            n = _carve(src, dest, first_inner["offset"])
            unwrapped = True
            method = f"carve@{first_inner['offset']}"
            _log(doc, f"在偏移 {first_inner['offset']} 剥离出 {first_inner['kind']}，{n} 字节")
        elif head_kind in ENC_KINDS or info["encrypted"]:
            needed = True
            method = "identified"
            cipher = head_kind
            _log(doc, "识别为加密容器，本步不猜测密钥，交给后续解包器继续处理")
        else:
            # try common header offsets even if scan missed
            carved = None
            if size > SCAN_BYTES:
                with src.open("rb") as fh:
                    extra = fh.read(max(COMMON_OFFSETS) + 32)
            else:
                extra = head
            for off in COMMON_OFFSETS:
                kind = _match_at(extra, off)
                if kind in PLAIN_KINDS:
                    carved = (off, kind)
                    break
            if carved:
                needed = True
                n = _carve(src, dest, carved[0])
                unwrapped = True
                method = f"carve@{carved[0]}"
                _log(doc, f"在常见偏移 {carved[0]} 剥离出 {carved[1]}，{n} 字节")
            else:
                method = "plain"
                needed = False
                _log(doc, "未发现加密容器特征，按明文镜像继续解包")
    except Exception as exc:  # noqa: BLE001 - persist and continue extract
        doc["error"] = f"{type(exc).__name__}: {exc}"
        _log(doc, f"剥离失败：{doc['error']}")
        _step(doc["steps"], "unwrap", "err", doc["error"], pct=50)
        unwrapped = False
        method = method or "error"

    doc["needed"] = needed
    doc["method"] = method
    doc["cipher"] = cipher
    if unwrapped:
        doc["output"] = str(dest)
        digest = hashlib.sha256()
        with dest.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
        doc["output_sha256"] = digest.hexdigest()
        _step(doc["steps"], "unwrap", "ok", method, pct=78)
    else:
        if dest.is_file():
            dest.unlink(missing_ok=True)
        doc["output"] = None
        status_detail = "无需剥离" if not needed else "未能自动解开，保留原文件"
        _step(doc["steps"], "unwrap", "ok" if not doc.get("error") else "err",
              status_detail, pct=70)
    doc["progress"] = 82
    doc["stage"] = "verify"
    doc["stage_label"] = "正在校验内部镜像"
    _step(doc["steps"], "verify", "now", pct=84)
    _emit(doc, out_dir, progress_cb)

    check_path = dest if unwrapped else src
    kinds = _verify_file(check_path)
    if kinds:
        doc["inner"] = kinds
        _step(doc["steps"], "verify", "ok", "、".join(kinds), pct=94)
        _log(doc, "内部可见：" + "、".join(kinds))
    else:
        _step(doc["steps"], "verify", "ok", "未见标准文件系统魔数", pct=90)
        _log(doc, "校验未看到 squashfs / uImage / TRX 等魔数")

    if unwrapped:
        doc["status"] = "decrypted"
        doc["stage_label"] = "已解密，可继续解包"
    elif needed and (head_kind in ENC_KINDS or info["encrypted"]):
        doc["status"] = "identified"
        doc["stage_label"] = "已识别加密，等待解包器"
    elif doc.get("error") and needed:
        doc["status"] = "failed"
        doc["stage_label"] = "解密失败"
    else:
        doc["status"] = "plain"
        doc["stage_label"] = "明文固件，无需解密"
    doc["stage"] = "done"
    doc["progress"] = 100
    _step(doc["steps"], "done", "ok" if doc["status"] != "failed" else "err",
          doc["stage_label"], pct=100)
    _log(doc, doc["stage_label"])
    _emit(doc, out_dir, progress_cb)
    return doc


def load_report(out_dir: Path) -> dict | None:
    path = Path(out_dir) / "decrypt.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def peek(job_id: str, firmware: str, src: Path) -> dict:
    """Read-only fingerprint for jobs that have not run decrypt yet."""
    doc = empty_report(job_id, firmware)
    if not Path(src).is_file():
        return doc
    head = src.read_bytes()[:SCAN_BYTES]
    info = fingerprint(head, firmware)
    doc["status"] = "peek"
    doc["progress"] = 0
    doc["stage"] = "fingerprint"
    doc["stage_label"] = "尚未自动解密（上传后会自动跑）"
    doc["vendor"] = info["vendor"]
    doc["entropy"] = info["entropy"]
    doc["inner"] = [h["kind"] for h in info["inners"][:8]]
    doc["head_kind"] = info["head_kind"]
    doc["needed"] = bool(info["encrypted"] or info["head_kind"] in WRAP_KINDS | ENC_KINDS)
    doc["size_bytes"] = src.stat().st_size
    return doc
