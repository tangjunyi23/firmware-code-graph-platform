"""固件 SCA（软件成分分析）— 基于 Trivy 0.74.0

对解包后的 rootfs 运行 `trivy rootfs --scanners vuln`，汇总组件与已知
CVE，结果落盘 data/sca/<job>.json。Trivy 版本强约束为 0.74.x（需求指定），
不匹配直接报错并提示，避免 DB 格式/行为差异。
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

REQUIRED_TRIVY = (0, 74)
TRIVY_TIMEOUT = 900


def _trivy_bin() -> str:
    for cand in (os.getenv("TRIVY_BIN"), shutil.which("trivy"),
                 str(Path.home() / ".local/bin/trivy")):
        if cand and Path(cand).is_file():
            return cand
    return ""


def check_trivy() -> tuple[str, str | None]:
    """返回 (bin, 版本号)；版本不是 0.74.x 时返回错误说明。"""
    binary = _trivy_bin()
    if not binary:
        return "", ("服务器未找到 trivy，请安装 0.74.0："
                    "https://github.com/aquasecurity/trivy/releases/tag/v0.74.0")
    try:
        out = subprocess.run([binary, "--version"], capture_output=True,
                             text=True, timeout=30)
        m = re.search(r"Version:\s*v?(\d+)\.(\d+)", out.stdout)
        if not m:
            return binary, f"无法解析 trivy 版本：{out.stdout[:80]}"
        ver = (int(m.group(1)), int(m.group(2)))
        if ver != REQUIRED_TRIVY:
            return binary, (f"trivy 版本为 {m.group(1)}.{m.group(2)}，"
                            f"需求要求 {REQUIRED_TRIVY[0]}.{REQUIRED_TRIVY[1]}，"
                            "请替换二进制")
    except (subprocess.SubprocessError, OSError) as exc:
        return binary, f"trivy 探测失败：{exc}"
    return binary, None


def _rootfs_of(job_id: str, data_dir) -> Path:
    from pipeline.backdoor import find_rootfs
    extract_dir = Path(data_dir) / "extracted" / job_id
    rootfs = find_rootfs(extract_dir / "firmware") or find_rootfs(extract_dir)
    if rootfs is None:
        raise RuntimeError("未找到解包后的文件系统，无法做 SCA")
    return rootfs


def scan_sca(job_id: str, data_dir) -> dict:
    """同步执行 Trivy SCA；调用方负责线程与状态落盘。"""
    binary, err = check_trivy()
    if err:
        raise RuntimeError(err)
    rootfs = _rootfs_of(job_id, data_dir)
    out_dir = Path(data_dir) / "sca"
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = out_dir / f"{job_id}.raw.json"
    # vuln 组件识别 + secret 扫描：路由器固件常无包管理元数据，
    # 组件/CVE 可能为 0（如实呈现），但密钥泄漏检测对固件同样关键
    cmd = [binary, "rootfs", "--scanners", "vuln,secret", "--quiet",
           "--format", "json", "--output", str(raw_path), str(rootfs)]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True,
                       timeout=TRIVY_TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Trivy 扫描超时（>{TRIVY_TIMEOUT}s）") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "")[-400:]
        raise RuntimeError(f"Trivy 退出码 {exc.returncode}：{detail}") from exc

    try:
        raw = json.loads(raw_path.read_text(encoding="utf-8",
                                            errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Trivy 结果解析失败：{exc}") from exc

    sev_cn = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
              "LOW": "low", "UNKNOWN": "info"}
    vulns = []
    components = 0
    seen = set()
    for result in raw.get("Results") or []:
        components += len(result.get("Packages") or [])
        for v in result.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID") or "?"
            pkg = v.get("PkgName") or "?"
            key = (vid, pkg)
            if key in seen:
                continue
            seen.add(key)
            fixed = ""
            for fx in v.get("FixedVersion") or "":
                fixed = fx
                break
            vulns.append({
                "cve": vid,
                "severity": sev_cn.get((v.get("Severity") or "").upper(), "info"),
                "pkg": pkg,
                "installed": v.get("InstalledVersion") or "",
                "fixed": fixed or "—",
                "title": (v.get("Title") or vid)[:120],
            })
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulns.sort(key=lambda x: order.get(x["severity"], 9))
    by_sev = {}
    for v in vulns:
        by_sev[v["severity"]] = by_sev.get(v["severity"], 0) + 1

    secrets = []
    for result in raw.get("Results") or []:
        for sec in result.get("Secrets") or []:
            secrets.append({
                "rule": sec.get("RuleID") or sec.get("Title") or "?",
                "path": (sec.get("StartLine") is not None and
                         f"{result.get('Target')}:{sec.get('StartLine')}"
                         or result.get("Target") or ""),
                "match": (sec.get("Match") or "")[:120],
                "severity": "high",
            })
            if len(secrets) >= 100:
                break
    result = {
        "job_id": job_id,
        "trivy_version": "0.74.0",
        "rootfs": str(rootfs),
        "components": components,
        "cve_total": len(vulns),
        "by_severity": by_sev,
        "vulns": vulns[:300],
        "secrets": secrets,
        "note": ("Trivy 组件/CVE 识别依赖包管理元数据或已知库文件特征；"
                 "嵌入式固件通常没有包管理器，组件数为 0 属正常情况，"
                 "密钥泄漏与后门专项检测是主要产出。"),
    }

    # mithril 语义扫描（best-effort 增补）：secrets 三层校验阶梯为主源、
    # 弱公钥/启动安全为新增维度、SBOM 版本恢复补 Trivy 零组件痛点。
    from pipeline import mithril as mithril_scan
    if mithril_scan.enabled():
        try:
            m = mithril_scan.scan_rootfs(rootfs)
            try:
                sb = mithril_scan.scan_sbom(
                    rootfs, Path(data_dir) / "sbom" / job_id)
                m["components"] = sb["components"]
                m["sbom_cyclonedx"] = sb["cyclonedx"]
            except (RuntimeError, OSError, ValueError):
                pass
            try:
                m["cves"] = mithril_scan.scan_cves(rootfs)
            except (RuntimeError, OSError, ValueError):
                m["cves"] = []
            result["mithril"] = m
        except Exception as exc:  # noqa: BLE001 - 增补失败不影响 Trivy 主结果
            result["mithril_error"] = f"{type(exc).__name__}: {exc}"
    return result
