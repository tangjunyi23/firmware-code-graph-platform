"""moria 快诊/补刀封装（解包链分层强化的 moria 侧）。

职责（见 docs/plan-moria-mithril.md）：
- identify()：上传固件的结构快诊（`moria -j <file>`，纯识别不解包）——
  结构树（偏移/类型/置信度）落 data/extracted/<job>/moria-tree.json，
  供洞察页、对账补刀与挖掘 agent（fw_structure_tree）消费。
- scan_rootfs()：EMBA 主解包完成后对 rootfs 目录扫描，产出 UPX 加壳
  清单（manifest binaries[].packed）——加壳 ELF 反编译会静默失败，
  标记让攻击面分析的盲区显式化。
- extract()：`moria -e` 定点/降级解包（带 --depth/--max-files/--max-bytes
  防护参数），供对账补刀与 EMBA 失败兜底。

全部 best-effort：moria 缺失/失败不阻塞主链（MORIA_ENABLED=0 完全回退）。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

_FWGRAPH_ROOT = Path(__file__).resolve().parents[2]


class MoriaUnavailable(RuntimeError):
    pass


def enabled() -> bool:
    return os.getenv("MORIA_ENABLED", "1") not in ("0", "false", "no")


def bin_path() -> str:
    """定位 moria 二进制：env 覆盖 → vendor → PATH。"""
    env = os.getenv("MORIA_BIN", "").strip()
    if env and Path(env).is_file():
        return env
    vendored = _FWGRAPH_ROOT / "vendor" / "bin" / "moria"
    if vendored.is_file() and os.access(vendored, os.X_OK):
        return str(vendored)
    found = shutil.which("moria")
    if found:
        return found
    raise MoriaUnavailable("moria binary not found (MORIA_BIN/vendor/PATH)")


def _limits() -> list:
    return [
        "--depth", os.getenv("MORIA_DEPTH", "16"),
        "--max-files", os.getenv("MORIA_MAX_FILES", "100000"),
        "--max-bytes", os.getenv("MORIA_MAX_BYTES", str(8 * 1024 ** 3)),
    ]


def _run(args: list, timeout: float) -> dict:
    cmd = [bin_path(), *args]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if out.returncode != 0:
        raise RuntimeError(f"moria exited {out.returncode}: "
                           f"{(out.stderr or out.stdout)[-300:]}")
    return json.loads(out.stdout)


def identify(fw_path: Path, timeout: float = 120) -> dict:
    """结构快诊：返回归一化结果（同时落盘 moria-tree.json 由调用方决定）。"""
    d = _run(["-j", *_limits(), str(fw_path)], timeout)
    findings = []
    for f in d.get("findings") or []:
        findings.append({
            "offset": int(f.get("offset") or 0),
            "size": int(f.get("size") or 0),
            "type": f.get("type") or "",
            "confidence": int(f.get("confidence") or 0),
            "tier": f.get("confidence_tier") or "",
            "description": str(f.get("description") or "")[:160],
        })
    return {
        "tool": "moria", "path": str(fw_path),
        "size": int(d.get("size") or 0),
        "summary": d.get("summary") or "",
        "assessment": d.get("assessment") or "",
        "findings": findings,
        "unidentified": [
            {"offset": int(u.get("offset") or 0), "size": int(u.get("size") or 0)}
            for u in (d.get("unidentified_regions") or [])[:64]
        ],
    }


def scan_rootfs(rootfs: Path, timeout: float = 300) -> dict:
    """解包后目录扫描：UPX 加壳清单 + 类型分布 + 未识别热点。

    返回 {upx: [{path, arch, compression, evidence}], by_type, unknown_paths}。
    """
    d = _run(["-j", *_limits(), str(rootfs)], timeout)
    upx, unknown = [], []
    for entry in d.get("files") or []:
        rel = str(entry.get("path") or "")
        for f in entry.get("findings") or []:
            t = str(f.get("type") or "")
            if t == "upx":
                upx.append({
                    "path": rel,
                    "arch": f.get("arch") or "",
                    "compression": f.get("compression") or "",
                    "version": f.get("version") or "",
                    "evidence": str(f.get("evidence") or "")[:160],
                })
            if t == "unknown" and len(unknown) < 64:
                unknown.append(rel)
    return {"upx": upx, "by_type": d.get("by_type") or {},
            "unknown_paths": unknown,
            "file_count": int(d.get("file_count") or 0)}


def extract(fw_path: Path, out_dir: Path, timeout: float = 900) -> dict:
    """moria -e 解包到 out_dir（定点补刀/降级兜底共用）。"""
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [bin_path(), "-e", "-C", str(out_dir), *_limits(), str(fw_path)]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return {"rc": out.returncode,
            "tail": (out.stdout + out.stderr)[-800:],
            "out_dir": str(out_dir)}


def annotate_manifest(manifest_file: Path, rootfs: Path) -> int:
    """把 scan_rootfs 的 UPX 清单合入 manifest（binaries[].packed）。

    返回打标数量。按「rootfs 内路径后缀匹配」对齐 manifest 的 binaries
    （manifest 记录的是固件内绝对路径，如 /usr/bin/httpd）。
    """
    if not manifest_file.is_file():
        return 0
    scan = scan_rootfs(rootfs)
    if not scan["upx"]:
        return 0
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    packed_rel = {u["path"].lstrip("/") for u in scan["upx"]}
    marked = 0
    for b in manifest.get("binaries") or []:
        p = str(b.get("path") or "").lstrip("/")
        if p in packed_rel or any(p.endswith(r) or r.endswith(p)
                                  for r in packed_rel):
            b["packed"] = True
            marked += 1
    if marked:
        manifest["moria"] = {"upx_packed": len(scan["upx"]),
                             "by_type": scan["by_type"]}
        manifest_file.write_text(json.dumps(manifest, indent=1),
                                 encoding="utf-8")
    return marked


# 快诊树里视为「应解出的文件系统/容器结构」的类型（对账补刀的依据）
_FS_TYPES = {"squashfs", "ext2", "ext3", "ext4", "f2fs", "xfs", "btrfs",
             "hfsplus", "ntfs", "erofs", "jffs2", "ubifs", "romfs",
             "yaffs2", "cramfs", "ubi", "cpio", "tar", "zip"}


def rescue_extract(fw_path: Path, log_dir: Path,
                   tree: dict | None = None) -> dict:
    """对账补刀 / 降级兜底：moria -e 提取到 log_dir/moria_extracted/。

    触发条件由调用方判定（EMBA 失败，或快诊树里的文件系统结构未被
    EMBA 覆盖）。返回 {done, out_dir, binaries}：binaries 为产物内的
    ELF 清单（供合并进 manifest）。
    """
    out_dir = Path(log_dir) / "moria_extracted"
    res = extract(fw_path, out_dir)
    binaries = []
    if res["rc"] == 0 and out_dir.is_dir():
        binaries = [r for p in sorted(out_dir.rglob("*"))
                   if p.is_file() and not p.is_symlink()
                   for r in [_binrec(p, out_dir)] if r]
    return {"done": res["rc"] == 0, "out_dir": str(out_dir),
            "tail": res["tail"], "binaries": binaries}


def merge_into_manifest(manifest_file: Path, extra: list) -> int:
    """把 moria 产物二进制并入 manifest（md5 去重，source=moria）。"""
    if not extra or not manifest_file.is_file():
        return 0
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    known = {b.get("md5") for b in manifest.get("binaries") or []}
    added = [b for b in extra if b.get("md5") not in known]
    if not added:
        return 0
    manifest.setdefault("binaries", []).extend(added)
    stats = manifest.setdefault("stats", {})
    stats["total_binaries"] = int(stats.get("total_binaries") or 0) + len(added)
    stats["moria_rescued"] = len(added)
    manifest_file.write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return len(added)


def fs_findings_uncovered(tree: dict | None, log_dir: Path) -> list:
    """快诊树里识别到、但 log_dir 下没有对应产物的文件系统结构。

    简化对账：EMBA 已解出可用 rootfs（firmware/ 树非空）时跳过——
    只有「树里有文件系统、EMBA 却什么都没解出」才值得补刀，避免对
    已知结构重复提取。
    """
    if not tree:
        return []
    fw_root = Path(log_dir) / "firmware"
    if fw_root.is_dir() and any(fw_root.rglob("*")):
        return []
    return [f for f in tree.get("findings") or []
            if f.get("type") in _FS_TYPES]



def _binrec(p: Path, out_dir: Path) -> dict:
    """moria 产物内的一个 ELF 二进制记录（manifest 兼容形状）。"""
    from pipeline.extract.checksec import checksec
    with open(p, "rb") as fh:
        if fh.read(4) != b"\x7fELF":
            return {}
    rel = "/" + str(p.relative_to(out_dir))
    return {"path": rel, "md5": _md5(p), "source": "moria",
            "size": p.stat().st_size, **_elf_meta(p),
            "checksec": _safe(lambda: checksec(p))}

def _md5(p: Path) -> str:
    import hashlib
    h = hashlib.md5()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe(fn):
    try:
        return fn()
    except Exception:  # noqa: BLE001
        return None


def _elf_meta(p: Path) -> dict:
    """最小 ELF 元数据（arch/bits/endianness），不依赖 pyelftools。"""
    try:
        with open(p, "rb") as fh:
            eh = fh.read(20)
        if len(eh) < 20 or eh[:4] != b"\x7fELF":
            return {}
        bits = 64 if eh[4] == 2 else 32
        little = eh[5] == 1
        machine = int.from_bytes(eh[18:20], "little" if little else "big")
        arch = {8: "mips", 40: "arm", 62: "x86", 183: "aarch64",
                20: "powerpc"}.get(machine, f"machine{machine}")
        return {"arch": arch, "bits": bits,
                "endianness": "little" if little else "big"}
    except OSError:
        return {}
