"""Analysis gears for the homepage: low / high / xhigh.

Each profile trades depth (and wall time) for coverage. Missing or unknown
names fall back to `high`, which matches the pre-gear auto-chain defaults.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DEFAULT = "high"

_PROFILES: dict[str, dict[str, Any]] = {
    "low": {
        "id": "low",
        "label": "Low",
        "title": "快速扫描",
        "eta": "最快",
        "blurb": "少反编译、不做 CFG 扩展和攻击路径 AI 分诊，随后短轮次静态挖掘。",
        "decompile_max_binaries": 12,
        "prefer_network": True,
        "graphext": False,
        "attack_ai": False,
        "attack_ai_max_paths": 0,
        "scoring": {
            "max_depth": 6,
            "path_limit": 20,
            "candidate_limit": 2000,
        },
        "hunt_mode": "static",
        "max_turns": 12,
    },
    "high": {
        "id": "high",
        "label": "High",
        "title": "标准分析",
        "eta": "中等",
        "blurb": "较大规模反编译 + 图谱/CFG + 攻击路径 AI 分诊，随后中等轮次静态挖掘。",
        "decompile_max_binaries": 64,
        "prefer_network": True,
        "graphext": True,
        "attack_ai": True,
        "attack_ai_max_paths": 20,
        "scoring": {
            "max_depth": 8,
            "path_limit": 50,
            "candidate_limit": 5000,
        },
        "hunt_mode": "static",
        "max_turns": 32,
    },
    "xhigh": {
        "id": "xhigh",
        "label": "XHigh",
        "title": "深度分析",
        "eta": "最长",
        "blurb": "尽量全量反编译、更深路径搜索，随后动静结合挖掘（可请求覆盖率追踪）。",
        "decompile_max_binaries": None,
        "prefer_network": False,
        "graphext": True,
        "attack_ai": True,
        "attack_ai_max_paths": 40,
        "scoring": {
            "max_depth": 10,
            "path_limit": 80,
            "candidate_limit": 8000,
        },
        "hunt_mode": "dynamic",
        "max_turns": 50,
    },
}


class UnknownProfile(ValueError):
    pass


def spec(name: str | None) -> dict[str, Any]:
    """Return a copy of the named profile. Empty/None → high. Unknown → error."""
    key = str(name or DEFAULT).strip().lower()
    if not key:
        key = DEFAULT
    if key not in _PROFILES:
        raise UnknownProfile(f"profile must be low|high|xhigh, got {name!r}")
    item = _PROFILES[key]
    return {
        **item,
        "scoring": dict(item["scoring"]),
    }


def public_list() -> list[dict[str, Any]]:
    return [
        {
            "id": p["id"],
            "label": p["label"],
            "title": p["title"],
            "eta": p["eta"],
            "blurb": p["blurb"],
            "hunt_mode": p["hunt_mode"],
            "max_turns": p["max_turns"],
            "decompile_max_binaries": p["decompile_max_binaries"],
        }
        for p in _PROFILES.values()
    ]


def _ident_paths(data_dir: Path, job_id: str) -> set[str]:
    path = data_dir / "inputs" / job_id / "identification.json"
    if not path.is_file():
        return set()
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    names: set[str] = set()
    for item in doc.get("inputs") or []:
        for raw in item.get("entry_files") or []:
            text = str(raw or "").lstrip("/")
            if text:
                names.add(text)
                names.add(text.rsplit("/", 1)[-1])
        for hop in item.get("processing_chain") or []:
            text = str(hop.get("file") or "").lstrip("/")
            if text:
                names.add(text)
                names.add(text.rsplit("/", 1)[-1])
    return names


def select_decompile_targets(
    job_id: str, data_dir, profile_name: str | None,
) -> set[str] | None:
    """Subset of manifest md5s for this gear, or None to decompile all."""
    item = spec(profile_name)
    cap = item.get("decompile_max_binaries")
    if not cap:
        return None
    data_dir = Path(data_dir)
    manifest_path = data_dir / "extracted" / job_id / "manifest.json"
    if not manifest_path.is_file():
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    binaries = [b for b in (manifest.get("binaries") or []) if b.get("md5")]
    if len(binaries) <= cap:
        return None
    network = _ident_paths(data_dir, job_id) if item.get("prefer_network") else set()

    def rank(binary: dict) -> tuple:
        path = str(binary.get("path") or "")
        base = path.rsplit("/", 1)[-1]
        hit = any(token and token in path for token in network) or base in network
        execish = any(seg in f"/{path}/" for seg in ("/bin/", "/sbin/", "/usr/bin/"))
        size = int(binary.get("size") or 0)
        return (1 if hit else 0, 1 if execish else 0, size)

    ranked = sorted(binaries, key=rank, reverse=True)
    return {b["md5"] for b in ranked[: int(cap)]}
