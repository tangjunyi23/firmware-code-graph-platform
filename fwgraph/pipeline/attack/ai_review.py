"""LLM review overlay for Top-N attack paths (hints only, not evidence)."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from pipeline import llm

PRIORITY = frozenset({"P0", "P1", "P2", "noise"})
VULN_CLASS = frozenset({"cmdi", "bof", "fmt", "pathtrv", "intov", "unknown"})
DATAFLOW = frozenset({"likely", "unclear", "unlikely"})
CWE_RE = re.compile(r"^CWE-\d+$")
DANGEROUS = (
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "system", "popen",
    "execve", "execlp", "memcpy", "memmove", "scanf", "sscanf", "recv",
)
_CALL_LINE = re.compile(r"\b(" + "|".join(DANGEROUS) + r")\s*\(", re.I)

SYSTEM = """你是固件攻击路径分诊器。只根据给定的 Hex-Rays 伪代码与静态路径做提示，不是漏洞结论。
规则：
- 只输出 JSON 数组，不要 markdown。
- 不得改函数名、不得编造符号、不得把路径标成 verified/observed。
- reason 用中文，不超过 200 字，引用必须带原地址。
- priority: P0=高优先深挖, P1=值得看, P2=低优先, noise=规则误报/消毒充分。
- vuln_class_hint: cmdi|bof|fmt|pathtrv|intov|unknown
- cwe_hint: 单个 CWE-数字 或 null
- sanitizer_effective: true|false|null
- dataflow: likely|unclear|unlikely（攻击者数据是否可能到达 sink）
每条必须包含 path_id，且 path_id 必须来自输入。"""


def enabled() -> bool:
    if os.getenv("AUTO_ATTACK_AI", "").strip() == "0":
        return False
    return llm.enabled()


def _max_paths() -> int:
    try:
        return max(1, min(int(os.getenv("ATTACK_AI_MAX_PATHS", "20")), 50))
    except ValueError:
        return 20


def _read_brief(pseudo_root: Path, md5: str, addr: str) -> dict:
    path = pseudo_root / md5 / "functions" / f"{addr}.c"
    if not path.is_file():
        path = pseudo_root / md5 / "functions" / f"{str(addr).lower()}.c"
    if not path.is_file():
        return {"head": [], "dangerous_calls": []}
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    dangerous = []
    for lineno, line in enumerate(lines, 1):
        if _CALL_LINE.search(line):
            dangerous.append({"line": lineno, "text": line.strip()[:160]})
        if len(dangerous) >= 8:
            break
    return {"head": lines[:8], "dangerous_calls": dangerous}


def _pack_path(path: dict, pseudo_root: Path) -> dict:
    md5 = path.get("binary_md5")
    chain = path.get("chain") or []
    src = path.get("source") or {}
    sink = path.get("sink") or {}
    return {
        "path_id": path.get("path_id"),
        "score": path.get("score"),
        "edge_count": path.get("edge_count"),
        "asrc": src.get("asrc") or [],
        "asink": sink.get("asink") or [],
        "sanitizers": path.get("sanitizers") or [],
        "verified_reachable": bool(path.get("verified_reachable")),
        "chain": [{"addr": n.get("addr"), "name": n.get("name")}
                  for n in chain[:8]],
        "source_brief": _read_brief(pseudo_root, md5, str(src.get("addr") or "")),
        "sink_brief": _read_brief(pseudo_root, md5, str(sink.get("addr") or "")),
    }


def _validate_row(row: dict, known_ids: set) -> dict | None:
    if not isinstance(row, dict):
        return None
    path_id = str(row.get("path_id") or "")
    if path_id not in known_ids:
        return None
    priority = str(row.get("priority") or "")
    if priority not in PRIORITY:
        return None
    vuln = str(row.get("vuln_class_hint") or "unknown")
    if vuln not in VULN_CLASS:
        vuln = "unknown"
    cwe = row.get("cwe_hint")
    if cwe in ("", None):
        cwe = None
    else:
        cwe = str(cwe)
        if not CWE_RE.match(cwe):
            cwe = None
    se = row.get("sanitizer_effective")
    if se not in (True, False, None):
        se = None
    dataflow = str(row.get("dataflow") or "unclear")
    if dataflow not in DATAFLOW:
        dataflow = "unclear"
    reason = str(row.get("reason") or "").strip()
    if len(reason) > 200:
        reason = reason[:200]
    return {
        "path_id": path_id,
        "priority": priority,
        "vuln_class_hint": vuln,
        "cwe_hint": cwe,
        "sanitizer_effective": se,
        "dataflow": dataflow,
        "reason": reason,
        "source": "llm",
    }


def compact(review: dict | None) -> dict | None:
    if not isinstance(review, dict):
        return None
    return {k: review.get(k) for k in (
        "priority", "vuln_class_hint", "cwe_hint", "dataflow", "reason")}


def review(job_id: str, data_dir, artifact: dict, pseudo_root,
           max_paths: int | None = None) -> dict:
    """Mutate artifact['paths'] in place; write ai_review.json. Best-effort."""
    data_dir = Path(data_dir)
    pseudo_root = Path(pseudo_root)
    paths = list(artifact.get("paths") or [])
    cap = max_paths if max_paths is not None else _max_paths()
    targets = paths[:max(1, int(cap))]
    if not targets:
        stats = {"status": "skipped", "reason": "no_paths", "reviewed": 0}
        _write_overlay(data_dir, job_id, stats, [])
        return stats
    packed = [_pack_path(p, pseudo_root) for p in targets]
    known = {p["path_id"] for p in packed if p.get("path_id")}
    rows = []
    errors = []
    chunk = max(1, min(int(os.getenv("ATTACK_AI_CHUNK", "5")), 20))
    for i in range(0, len(packed), chunk):
        batch = packed[i:i + chunk]
        user = json.dumps({"job_id": job_id, "paths": batch}, ensure_ascii=False)
        try:
            parsed = llm.chat_json(SYSTEM, user)
        except Exception as exc:  # noqa: BLE001 - keep other chunks
            errors.append(f"{type(exc).__name__}: {exc}")
            continue
        if isinstance(parsed, dict):
            rows.extend(parsed.get("paths") or parsed.get("reviews") or [parsed])
        elif isinstance(parsed, list):
            rows.extend(parsed)
    if not rows and errors:
        stats = {"status": "error", "error": errors[0],
                 "reviewed": 0, "requested": len(targets),
                 "errors": len(errors)}
        _write_overlay(data_dir, job_id, stats, [])
        return stats
    accepted = []
    seen = set()
    for row in rows:
        item = _validate_row(row, known)
        if item is None or item["path_id"] in seen:
            continue
        seen.add(item["path_id"])
        accepted.append(item)
    by_id = {item["path_id"]: item for item in accepted}
    for path in paths:
        pid = path.get("path_id")
        if pid in by_id:
            path["ai_review"] = by_id[pid]
    stats = {"status": "ok", "requested": len(targets),
             "reviewed": len(accepted), "dropped": max(0, len(rows) - len(accepted))}
    _write_overlay(data_dir, job_id, stats, accepted)
    return stats


def _write_overlay(data_dir: Path, job_id: str, stats: dict, rows: list):
    attack_dir = data_dir / "attack" / job_id
    attack_dir.mkdir(parents=True, exist_ok=True)
    payload = {"job_id": job_id, **stats, "reviews": rows}
    (attack_dir / "ai_review.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def review_artifact(job_id: str, data_dir) -> dict:
    """Load attack_paths.json, review, rewrite. Raises if artifact missing."""
    data_dir = Path(data_dir)
    artifact_path = data_dir / "attack" / job_id / "attack_paths.json"
    if not artifact_path.is_file():
        raise FileNotFoundError("attack analysis not run yet")
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    pseudo_root = data_dir / "pseudocode" / job_id
    stats = review(job_id, data_dir, artifact, pseudo_root)
    artifact.setdefault("summary", {})["ai_review"] = stats
    artifact_path.write_text(json.dumps(artifact, indent=2, ensure_ascii=False),
                             encoding="utf-8")
    return stats
