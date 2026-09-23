"""模拟环境自动清理（janitor）。

三类回收，周期后台线程执行（EMUL_JANITOR=0 可关，默认开；测试进程
首次运行前有延迟，不会被 TestClient 意外触发）：

1. TTL：stopped/failed 终态环境超过 EMUL_JANITOR_TTL_HOURS（默认 24h）
   → 删容器、删 workspace（rootfs 大头）、记录置 purged（保留线索，
   reconcile/详情接口据此知道不可再用）。
2. 磁盘高水位：全部环境 disk_bytes 合计超过全局配额的
   EMUL_JANITOR_HIGH_WATER（默认 0.85）→ 从最久未更新的终态环境开始
   逐个清，直到回落到水位线下或无可清对象。
3. 孤儿容器：docker 里 fwgraph-emul-* 容器不属于任何非 purged 环境的
   在册服务 → docker rm -f（环境记录被清理后残留的容器）。
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from pipeline.emul import store

ENABLED = os.getenv("EMUL_JANITOR", "1") not in ("0", "false", "no")
INTERVAL = int(os.getenv("EMUL_JANITOR_INTERVAL", "1800"))        # 30 分钟
FIRST_DELAY = int(os.getenv("EMUL_JANITOR_FIRST_DELAY", "300"))   # 首轮 5 分钟
TTL_HOURS = float(os.getenv("EMUL_JANITOR_TTL_HOURS", "24"))
HIGH_WATER = float(os.getenv("EMUL_JANITOR_HIGH_WATER", "0.85"))
GLOBAL_QUOTA_GB = float(os.getenv("EMUL_GLOBAL_GB", "60"))

_PURGED_NOTE = "自动清理：超过保留期（TTL/磁盘水位），容器与工作区已回收"

_stop = threading.Event()
_thread: threading.Thread | None = None
_lock = threading.Lock()


def _age_hours(rec: dict) -> float:
    ts = str(rec.get("updated_at") or "")
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).total_seconds() / 3600
    except ValueError:
        return 0.0


def _rm_container(container: str) -> bool:
    if not re.match(r"^[\w.-]{1,96}$", container or ""):
        return False
    try:
        out = subprocess.run(["docker", "rm", "-f", container],
                             capture_output=True, text=True, timeout=20)
        return out.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def purge_env(data_dir, env: dict, reason: str = "") -> dict:
    """清掉一个终态环境：容器、workspace；记录置 purged（幂等）。"""
    if env.get("status") == "purged":
        return env
    for svc in env.get("services") or []:
        _rm_container(svc.get("container") or "")
    ws = env.get("workspace") or ""
    if ws:
        shutil.rmtree(ws, ignore_errors=True)
    env["status"] = "purged"
    env["workspace"] = ""
    env["disk_bytes"] = 0
    for svc in env.get("services") or []:
        svc["status"] = "purged"
    store.env_note(env, _PURGED_NOTE + (f"（{reason}）" if reason else ""))
    store.save_env(data_dir, env)
    return env


def _disk_bytes_total(envs: list) -> int:
    return sum(int(e.get("disk_bytes") or 0) for e in envs)


def _orphans(data_dir, envs: list) -> list:
    """docker 里存在、但没有任何非 purged 环境在册的 fwgraph-emul 容器。"""
    known = {svc.get("container") for e in envs
             if e.get("status") != "purged"
             for svc in (e.get("services") or [])}
    known.discard(None)
    try:
        out = subprocess.run(
            ["docker", "ps", "-a", "--filter", "name=fwgraph-emul-",
             "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if out.returncode != 0:
        return []
    return [n for n in out.stdout.split() if n and n not in known]


def reap_once(data_dir) -> dict:
    """跑一趟清理；返回统计（供手动触发与日志）。"""
    stats = {"envs_purged": [], "containers_removed": [], "skipped": 0}
    with _lock:
        envs = store.list_envs(data_dir)
        live = [e for e in envs if e.get("status") != "purged"]
        # 1) TTL：终态过期环境
        for e in live:
            if e.get("status") in ("stopped", "failed") \
                    and _age_hours(e) > TTL_HOURS:
                purge_env(data_dir, e, reason="TTL")
                stats["envs_purged"].append(e["env_id"])
        # 2) 磁盘高水位：从最久未更新的终态环境开始回收
        envs = store.list_envs(data_dir)
        live = [e for e in envs if e.get("status") != "purged"]
        quota_bytes = GLOBAL_QUOTA_GB * 1024 ** 3
        candidates = sorted(
            (e for e in live if e.get("status") in ("stopped", "failed")),
            key=_age_hours, reverse=True)
        idx = 0
        while _disk_bytes_total(live) > quota_bytes * HIGH_WATER \
                and idx < len(candidates):
            e = candidates[idx]
            purge_env(data_dir, e, reason="磁盘水位")
            stats["envs_purged"].append(e["env_id"])
            for x in live:
                if x["env_id"] == e["env_id"]:
                    x["disk_bytes"] = 0
            idx += 1
        stats["skipped"] = len(candidates) - idx
        # 3) 孤儿容器
        envs = store.list_envs(data_dir)
        for name in _orphans(data_dir, envs):
            if _rm_container(name):
                stats["containers_removed"].append(name)
    return stats


def start(data_dir) -> None:
    """启动后台清理线程（幂等）。"""
    global _thread
    if not ENABLED or _thread is not None:
        return

    def _loop() -> None:
        _stop.wait(FIRST_DELAY)
        while not _stop.wait(INTERVAL):
            try:
                stats = reap_once(data_dir)
                if stats["envs_purged"] or stats["containers_removed"]:
                    print(f"[emul-janitor] purged={stats['envs_purged']} "
                          f"containers={stats['containers_removed']}",
                          flush=True)
            except Exception:  # noqa: BLE001 - 清理失败等下一轮
                pass

    _thread = threading.Thread(target=_loop, daemon=True,
                               name="emul-janitor")
    _thread.start()


def shutdown() -> None:
    _stop.set()
