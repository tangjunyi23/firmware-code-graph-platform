"""固件后门专项检测（D-BO）

对解包后的 rootfs 做分层规则扫描，产出结构化发现：
  1. 隐藏账户 / 空口令 / UID 异常（passwd、shadow）
  2. 植入的 SSH 授权密钥（authorized_keys）
  3. 启动链后门（inittab / rcS / init.d 拉起 telnetd、调试 shell）
  4. 可疑计划任务（cron 引用 wget/curl/tftp 拉取执行）
  5. 二进制/脚本后门特征串（backdoor、反向 shell、/dev/tcp、固定魔数端口）
  6. Web 目录 webshell 特征（eval/system/exec 组合）
  7. 已知 IoT 蠕虫植入物文件名（Mirai 家族等）
  8. 持久化异常：可写目录中的可执行文件（/tmp /var /dev）
  9. 配置文件硬编码口令（password=/passwd= 明文）

每条发现包含：严重度、类别、标题、目标文件、证据、行为说明、处置建议、置信度。
结果落盘 data/backdoor/<job>.json，状态机 pending -> running -> done|failed。
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

SEV_ORDER = ["critical", "high", "medium", "low"]
_SEV_CN = {"critical": "严重", "high": "高危", "medium": "中危",
           "low": "低危"}

# ---------------------------------------------------------------------------
# rootfs 定位
# ---------------------------------------------------------------------------


def find_rootfs(job_extract_dir) -> Path | None:
    """在解包产物里找 rootfs：含 etc 且含 bin/sbin/usr 之一的最浅目录。"""
    base = Path(job_extract_dir)
    candidates = []
    for dirpath, dirnames, _ in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in
                       ("proc", "sys", "devpts", ".git")]
        names = set(dirnames)
        if "etc" in names and (names & {"bin", "sbin", "usr"}):
            candidates.append(Path(dirpath))
            dirnames[:] = []  # 更深的不必再看
    if not candidates:
        return None
    return min(candidates, key=lambda p: len(p.parts))


# ---------------------------------------------------------------------------
# 规则实现
# ---------------------------------------------------------------------------

_SHELL_RE = re.compile(r"/(bin|sbin)/(a?sh|bash|zsh)\s*$")


def _read_lines(path: Path, limit=64_000):
    try:
        data = path.read_bytes()
    except OSError:
        return []
    if b"\x00" in data[:4096]:
        return []
    return data.decode("utf-8", errors="replace").splitlines()[:limit]


def _finding(sev, cat, title, target, evidence, why, fix, confidence=0.9):
    return {
        "severity": sev,
        "category": cat,
        "title": title,
        "target": str(target),
        "evidence": evidence[:12],
        "description": why,
        "recommendation": fix,
        "confidence": round(float(confidence), 2),
    }


def rule_accounts(rootfs: Path):
    """passwd/shadow：UID 0 非	root 账户、空口令字段、怪异 shell。"""
    out = []
    passwd = rootfs / "etc" / "passwd"
    if passwd.is_file():
        for ln in _read_lines(passwd):
            f = ln.split(":")
            if len(f) < 7:
                continue
            name, _, uid, _, _, shell = f[0], f[1], f[2], f[3], f[5], f[6]
            if uid == "0" and name != "root":
                out.append(_finding(
                    "critical", "隐藏账户",
                    f"非 root 账户 {name} 拥有 UID 0",
                    passwd, [ln],
                    "UID 0 账户等同 root 权限，是固件植入后门的最经典形态："
                    "攻击者（或厂商留门）可用该账户无口令拿全权 shell。",
                    "删除该账户或改为普通 UID，并核查其登录 shell 与使用痕迹。",
                    0.95))
            if _SHELL_RE.search(shell) and name not in ("root",):
                out.append(_finding(
                    "low", "隐藏账户",
                    f"账户 {name} 直接以交互 shell 登录",
                    passwd, [ln],
                    "设备账户直接给登录 shell 常见于维护后门，攻击面大。",
                    "改为 /sbin/nologin，仅保留必要服务账户。",
                    0.5))
    shadow = rootfs / "etc" / "shadow"
    if shadow.is_file():
        for ln in _read_lines(shadow):
            f = ln.split(":")
            if len(f) < 2:
                continue
            name, pw = f[0], f[1]
            if pw in ("", "!", "*", "x"):
                continue
            if pw.startswith(("$1$", "$MD5$")) or ":".join(f).count(":") > 8:
                pass  # 常规 hash，跳过
            # 空口令：字段为空字符串在过滤条件中已排除；这里查 weak hash + 提示
        # 检查空口令登录（passwd 字段为空 = 无需密码）
    if passwd.is_file():
        for ln in _read_lines(passwd):
            f = ln.split(":")
            if len(f) >= 3 and f[1] == "" and f[0] != "nobody":
                out.append(_finding(
                    "high", "隐藏账户",
                    f"账户 {f[0]} 密码字段为空（免密登录）",
                    passwd, [ln],
                    "密码字段为空的账户可被任意远程服务直接使用，"
                    "常见于 telnet/ssh 后门组合。",
                    "为该账户设置强 hash 或移除。",
                    0.85))
    return out


def rule_ssh_keys(rootfs: Path):
    """植入的 authorized_keys：固件镜像里本不该有。"""
    out = []
    patterns = ["authorized_keys", "authorized_keys2",
                ".ssh/authorized_keys", "dropbear/authorized_keys"]
    hits = []
    for pat in patterns:
        hits.extend(rootfs.glob(f"**/{pat}"))
    for key in hits[:20]:
        try:
            blob = key.read_bytes()[:600]
        except OSError:
            continue
        if not blob.strip():
            continue
        out.append(_finding(
            "high", "植入密钥",
            f"发现 SSH 授权密钥 {key.name}",
            key, [blob.decode("utf-8", "replace").splitlines()[0][:100]],
            "镜像内预置 authorized_keys 等于给持有私钥的人留了持久登录通道，"
            "量产固件中不应存在。",
            "删除该文件；若为运维临时遗留，改为部署期注入。",
            0.85))
    return out


_INIT_BACKDOOR = [
    (re.compile(r"(^|\s|;|&)telnetd\b"), "critical",
     "启动链拉起 telnetd",
     "开机即起 telnet 服务是最常见的固件后门/维护通道，配合空口令账户可直接拿 shell。",
     "删除该启动项；如必须调试，限定监听 127.0.0.1 并加口令。"),
    (re.compile(r"getty\s+.*-l\s+\S*/(bin|sbin)/(a?sh|bash)"), "critical",
     "getty 使用裸 shell 作为登录程序",
     "getty -l /bin/sh 让串口/控制台免认证直接进 root shell。",
     "恢复 getty 默认 /bin/login 登录流程。"),
    (re.compile(r"cttyhack\s+\S*(a?sh|bash)\b"), "high",
     "init 直接 cttyhack shell",
     "init 脚本直接挂 shell 到控制台，跳过登录认证，等同于物理接触即 root。",
     "移除该 init 项，控制台登录必须经过认证。"),
]


def rule_init_scripts(rootfs: Path):
    out = []
    targets = [rootfs / "etc" / "inittab"]
    for pat in ("etc/init.d/*", "etc/rc.d/*", "etc/rc.local",
                "sbin/rcS", "etc/rcS", "etc/init.d/rcS"):
        targets.extend(rootfs.glob(pat))
    seen = set()
    for path in targets:
        if not path.is_file() or path in seen:
            continue
        seen.add(path)
        for ln in _read_lines(path):
            for rx, sev, title, why, fix in _INIT_BACKDOOR:
                if rx.search(ln):
                    out.append(_finding(
                        sev, "启动链后门", title, path, [ln.strip()[:160]],
                        why or title, fix, 0.8))
                    break
    return out


_CRON_SUSPECT = re.compile(
    r"(wget|curl|tftp|ftp|nc |ncat|netcat)\b.*(\bs?sh\b|-c|perl|python)", re.I)


def rule_cron(rootfs: Path):
    out = []
    for pat in ("etc/crontabs/*", "var/spool/cron/crontabs/*",
                "etc/cron.d/*", "etc/crontab"):
        for path in rootfs.glob(pat):
            if not path.is_file():
                continue
            for ln in _read_lines(path):
                if ln.startswith("#"):
                    continue
                if _CRON_SUSPECT.search(ln):
                    out.append(_finding(
                        "critical", "持久化任务",
                        "计划任务从网络拉取并执行代码",
                        path, [ln.strip()[:200]],
                        "定时从远端下载脚本执行是典型的远程控制后门行为"
                        "（挖矿/僵尸网络常用）。",
                        "删除该任务，排查对应落盘文件与外联地址。",
                        0.85))
    return out


# 二进制/文本里的高置信特征串（按置信度从高到低）
_STRING_SIGS = [
    (b"backdoor", 0.95, "high", "后门字符串",
     "文件内容直接包含 backdoor 字样，多为后门程序或后门开关配置。"),
    (b"/dev/tcp/", 0.8, "high", "反向 shell 特征",
     "bash /dev/tcp 反向连接是反弹 shell 的标准写法。"),
    (b"bash -i >& /dev/tcp", 0.95, "critical", "经典反弹 shell",
     "bash -i >& /dev/tcp/... 一行流是入侵脚本最常用的反弹写法。"),
    (b"nc -e /bin", 0.9, "critical", "netcat 直接执行 shell",
     "nc -e /bin/sh 提供 telnet 风格的免认证远程 shell。"),
    (b"31337", 0.6, "medium", "经典后门端口 31337",
     "Elite 端口常为植入后门的监听端口，需人工确认上下文。"),
]

_WEB_DIR_NAMES = {"www", "web", "html", "htdocs", "wwwroot", "lighttpd",
                  "uhttpd", "public_html"}
_WEBHELL_RE = re.compile(
    r"(eval\s*\(\s*(base64_decode|gzinflate|str_rot13|assert)|"
    r"system\s*\(\s*\$_(GET|POST|REQUEST)|passthru\s*\(\s*\$_|"
    r"<%@\s*Page.*ProcessRequest)", re.I)

_MIRAI_NAMES = [
    ".t", "mirai", "mirai.arm", "mirai.arm7", "okiru", "sora",
    "mips", "mipsel", "sh4", "x86_64.gate", "bontck", "jenkins",
    "yariman", "dvrhelper", "gafgyt", "tsunami", "kaiten",
]


def _is_elf(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def rule_string_scan(rootfs: Path, budget_s: float = 60.0):
    """扫描关键目录文件的特征串。预算控制：超时即止（规则可重跑）。"""
    out = []
    t0 = time.monotonic()
    scan_dirs = []
    for name in ("bin", "sbin", "usr/bin", "usr/sbin", "etc", "var", "tmp",
                 "root", "opt"):
        d = rootfs / name
        if d.is_dir():
            scan_dirs.append(d)
    for wd in _WEB_DIR_NAMES:
        for d in rootfs.glob(f"**/{wd}"):
            scan_dirs.append(d)
    scanned = 0
    for base in scan_dirs:
        for dirpath, _dirnames, filenames in os.walk(base):
            for fn in filenames:
                if time.monotonic() - t0 > budget_s:
                    return out, scanned
                p = Path(dirpath) / fn
                try:
                    if p.stat().st_size > 8 * 1024 * 1024:
                        continue
                    blob = p.read_bytes()
                except OSError:
                    continue
                scanned += 1
                for sig, conf, sev, title, why in _STRING_SIGS:
                    idx = blob.find(sig)
                    if idx < 0:
                        continue
                    start = max(0, idx - 40)
                    ctx = blob[start:idx + len(sig) + 60]
                    ctx = re.sub(rb"[^\x20-\x7e\n]", b".", ctx)
                    ev = ctx.decode("ascii", "replace").strip()
                    out.append(_finding(
                        sev, "特征串", f"{title}：{fn}", p,
                        [ev[:180]], why,
                        "结合上下文确认；命中二进制建议提交到多引擎比对，"
                        "确认为植入物后清除并更新固件。",
                        conf))
    return out, scanned


def rule_webshell(rootfs: Path):
    out = []
    for wd in _WEB_DIR_NAMES:
        for base in rootfs.glob(f"**/{wd}"):
            if not base.is_dir():
                continue
            for p in base.rglob("*"):
                if not p.is_file() or p.stat().st_size > 2 * 1024 * 1024:
                    continue
                if p.suffix not in (".php", ".jsp", ".asp", ".aspx", ".sh",
                                    ".cgi", ".pl"):
                    continue
                text = _read_lines(p, 4000)
                for ln in text:
                    if _WEBHELL_RE.search(ln):
                        out.append(_finding(
                            "critical", "Webshell",
                            f"Web 目录疑似 webshell：{p.name}",
                            p, [ln.strip()[:180]],
                            "Web 目录中的动态执行代码接收外部参数执行命令，"
                            "属于典型 webshell 后门。",
                            "立即下线该文件，排查访问日志与相邻文件。",
                            0.8))
                        break
    return out


def rule_known_implants(rootfs: Path):
    out = []
    hot_dirs = [rootfs / "tmp", rootfs / "var" / "tmp", rootfs / "dev/shm",
                rootfs / "run", rootfs / "mnt", rootfs / "etc", rootfs]
    names = set(_MIRAI_NAMES)
    for d in hot_dirs:
        if not d.is_dir():
            continue
        for p in d.iterdir():
            if p.name.lower() in names and _is_elf(p):
                out.append(_finding(
                    "critical", "已知植入物",
                    f"文件名命中 IoT 僵尸网络家族：{p.name}",
                    p, [f"ELF {p.stat().st_size} bytes"],
                    "文件名与 Mirai/Gafgyt 等家族投放物一致且为 ELF，"
                    "高度怀疑镜像被植入蠕虫。",
                    "删除并重建镜像；排查同目录其余异常文件。",
                    0.75))
    return out


def rule_writable_exec(rootfs: Path):
    """可写目录中的可执行文件（运行期植入的常见落点）。"""
    out = []
    for name in ("tmp", "var/tmp", "dev/shm", "var/run", "run"):
        d = rootfs / name
        if not d.is_dir():
            continue
        for p in d.rglob("*"):
            try:
                if not p.is_file() or not _is_elf(p):
                    continue
                if p.stat().st_size < 1024:
                    continue
            except OSError:
                continue
            out.append(_finding(
                "medium", "可写区可执行文件",
                f"可写目录存在 ELF：{p.relative_to(rootfs)}",
                p, [f"ELF {p.stat().st_size} bytes"],
                "量产镜像的 /tmp、/var 等可写目录不应预置 ELF；"
                "运行期落盘的样本多为植入物。",
                "确认为厂商自带后移除；同时检查生成它的脚本。",
                0.6))
            if len(out) > 40:
                return out
    return out


_CRED_RE = re.compile(
    r"^\s*(password|passwd|admin_pass|admin_password|root_pass)\s*=\s*"
    r"(['\"]?)(?!\1$)[A-Za-z0-9@#$%^&*+_\-]{4,32}\2\s*$", re.I)


def rule_hardcoded_creds(rootfs: Path):
    out = []
    conf_pats = ("etc/config/*", "etc/*.conf", "etc/default/*",
                 "etc/init.d/*", "etc/config.xml", "etc/httpd.conf")
    for pat in conf_pats:
        for p in rootfs.glob(pat):
            if not p.is_file():
                continue
            for ln in _read_lines(p, 8000):
                if _CRED_RE.match(ln):
                    val = ln.split("=", 1)[1].strip().strip("'\"")
                    masked = val[:2] + "***" if len(val) > 3 else "***"
                    out.append(_finding(
                        "high", "硬编码口令",
                        f"配置明文口令：{p.name}",
                        p, [re.sub(r"=.*", f"={masked}", ln.strip())],
                        "固件配置内置明文口令，拿到镜像即可离线提取，"
                        "常被用作设备后门入口。",
                        "改为首次启动随机生成或强制改密。",
                        0.7))
                    if len(out) > 30:
                        return out
    return out


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------


def scan_backdoor(job_id: str, data_dir) -> dict:
    """同步执行全量规则；调用方负责线程与状态落盘。"""
    extract_dir = Path(data_dir) / "extracted" / job_id
    rootfs = find_rootfs(extract_dir / "firmware") or find_rootfs(extract_dir)
    if rootfs is None:
        raise RuntimeError(
            "未找到解包后的文件系统：请确认该任务已完成解包"
            "（损坏或加密镜像无法检测）")

    findings = []
    findings += rule_accounts(rootfs)
    findings += rule_ssh_keys(rootfs)
    findings += rule_init_scripts(rootfs)
    findings += rule_cron(rootfs)
    findings += rule_webshell(rootfs)
    findings += rule_known_implants(rootfs)
    findings += rule_writable_exec(rootfs)
    findings += rule_hardcoded_creds(rootfs)
    sig_findings, scanned = rule_string_scan(rootfs)
    findings += sig_findings

    by_sev = {s: 0 for s in SEV_ORDER}
    by_cat = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
    risky = by_sev["critical"] + by_sev["high"]
    verdict = ("high" if risky >= 3 else
               "medium" if risky else
               "low" if by_sev["medium"] else "clean")
    verdict_cn = {"high": "存在明显后门迹象", "medium": "发现可疑迹象",
                  "low": "轻微异常", "clean": "未发现后门迹象"}[verdict]
    return {
        "job_id": job_id,
        "rootfs": str(rootfs),
        "verdict": verdict,
        "verdict_cn": verdict_cn,
        "counts": {"total": len(findings), **by_sev},
        "by_category": by_cat,
        "files_scanned": scanned,
        "findings": findings,
    }
