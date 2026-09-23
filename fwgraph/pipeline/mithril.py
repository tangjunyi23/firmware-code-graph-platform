"""mithril 语义扫描封装（解包产物的认证风险 / SBOM / CVE / boot 审计）。

四类输出（见 docs/plan-moria-mithril.md §4）：
- secrets：三层校验阶梯（形状→结构→校验和）的密钥泄露，主源
- key_weakness：弱公钥（ROCA/共享素数/已知坏钥匙）——平台空白补齐
- boot：启动安全姿势（U-Boot env/FIT/AVB/UEFI）
- components：SBOM 恢复（ELF 版本横幅/libc 文件名/内核 banner）——
  补 Trivy 在无包管理元数据固件上的零组件痛点；CVE 段需
  MITHRIL_DB（--fetch-db 一次性联网），无库自动跳过。

best-effort：失败不阻塞 SCA 主链（MITHRIL_ENABLED=0 完全回退）。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

_FWGRAPH_ROOT = Path(__file__).resolve().parents[1]
TIMEOUT = int(os.getenv("MITHRIL_TIMEOUT", "600"))


class MithrilUnavailable(RuntimeError):
    pass


def enabled() -> bool:
    return os.getenv("MITHRIL_ENABLED", "1") not in ("0", "false", "no")


def bin_path() -> str:
    env = os.getenv("MITHRIL_BIN", "").strip()
    if env and Path(env).is_file():
        return env
    vendored = _FWGRAPH_ROOT / "vendor" / "bin" / "mithril"
    if vendored.is_file() and os.access(vendored, os.X_OK):
        return str(vendored)
    found = shutil.which("mithril")
    if found:
        return found
    raise MithrilUnavailable("mithril binary not found")


def db_dir() -> Path:
    env = os.getenv("MITHRIL_DB", "").strip()
    return Path(env) if env else Path(os.getenv("FWGRAPH_DATA",
                                                str(_FWGRAPH_ROOT / "data"))) / "mithril-db"


def _run(rootfs: Path, sections: list, timeout: float = TIMEOUT) -> dict:
    cmd = [bin_path(), *sections, "-j", str(rootfs)]
    env = dict(os.environ)
    if db_dir().is_dir():
        env["MITHRIL_DB"] = str(db_dir())
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                         env=env)
    if out.returncode != 0:
        # 无 CVE 库时全量模式会非零退出：降级为无 CVE 段重跑
        # （secrets/keys/boot/SBOM 无需数据库）
        if not sections and "no local vuln DB" in (out.stderr or ""):
            return _run(rootfs, ["--secrets", "--keys", "--boot"],
                        timeout=timeout)
        raise RuntimeError(f"mithril exited {out.returncode}: "
                           f"{(out.stderr or out.stdout)[-300:]}")
    return json.loads(out.stdout)


def _norm(items: list, cap: int = 400) -> list:
    out = []
    for it in items[:cap]:
        out.append({
            "path": str(it.get("path") or ""),
            "type": str(it.get("type") or ""),
            "category": str(it.get("category") or ""),
            "confidence": int(it.get("confidence") or 0),
            "tier": str(it.get("confidence_tier") or ""),
            "label": str(it.get("label") or ""),
            "evidence": str(it.get("evidence") or "")[:200],
            "description": str(it.get("description") or "")[:300],
        })
    return out


def scan_rootfs(rootfs: Path) -> dict:
    """全量语义扫描（无 CVE 库时 CVE 段为空，其余照常）。"""
    d = _run(rootfs, [])
    secrets = _norm(d.get("secrets") or [])
    # key_weakness：dict{checks:[], findings:[]} 或 list——归一为 findings
    kw = d.get("key_weakness") or {}
    if isinstance(kw, dict):
        kw_items = kw.get("findings") or kw.get("weak_keys") or []
    else:
        kw_items = kw
    weak_keys = _norm(kw_items)
    boot = _norm(d.get("boot_security")
                 or d.get("boot") or [])
    notable = _norm(d.get("notable") or [], cap=100)
    return {
        "tool": "mithril", "summary": d.get("summary") or "",
        "file_count": int(d.get("file_count") or 0),
        "secrets": secrets,
        "weak_keys": weak_keys,
        "boot": boot,
        "notable": notable,
        "errors": (d.get("errors") or [])[:20],
    }


def scan_sbom(rootfs: Path, out_dir: Path) -> dict:
    """SBOM（CycloneDX/SPDX 落盘）+ 组件清单（供 SCA 合并与 vulnlib）。"""
    out_dir.mkdir(parents=True, exist_ok=True)
    d = _run(rootfs, ["--sbom", "-C", str(out_dir)])
    comps = []
    sbom = d.get("sbom") or d.get("components") or {}
    items = sbom.get("components") if isinstance(sbom, dict) else sbom
    for c in (items or [])[:500]:
        if not isinstance(c, dict):
            continue
        comps.append({
            "name": str(c.get("name") or ""),
            "version": str(c.get("version") or ""),
            "purl": str(c.get("purl") or ""),
            "cpe": str(c.get("cpe") or ""),
            "evidence": str(c.get("evidence") or "")[:160],
            "source": "mithril",
        })
    cdx = out_dir / "sbom.cdx.json"
    return {"components": comps,
            "cyclonedx": str(cdx) if cdx.is_file() else "",
            "spdx": str(out_dir / "sbom.spdx.json")}


def scan_cves(rootfs: Path) -> list:
    """CVE（需 MITHRIL_DB；无库返回 []）。"""
    if not db_dir().is_dir():
        return []
    d = _run(rootfs, ["--cve"])
    cves = d.get("cves") or []
    if isinstance(cves, dict):
        cves = cves.get("findings") or []
    out = []
    for c in (cves or [])[:400]:
        if not isinstance(c, dict):
            continue
        out.append({
            "cve": str(c.get("cve") or c.get("id") or ""),
            "component": str(c.get("component") or c.get("package") or ""),
            "version": str(c.get("version") or ""),
            "severity": str(c.get("severity") or ""),
            "kev": bool(c.get("kev")),
            "epss": c.get("epss"),
            "confidence": str(c.get("confidence") or c.get("match_type") or ""),
            "description": str(c.get("description") or c.get("title")
                               or "")[:240],
        })
    return out
