"""固件模拟环境登记表与跨 agent 模拟请求的持久化。

两类记录，都在 data/emul/ 下：
- envs/{env_id}.json     模拟环境（进程簇）：状态机 building→booting→
                         ready/degraded/stopped/failed，含服务清单、端口
                         映射、迭代记录、磁盘占用、所属会话。
- requests/{req_id}.json 挖掘 agent → 模拟 agent 的模拟请求（平台总线）：
                         pending→working→ready/failed/cancelled，携带结构化
                         上下文（嫌疑结论、目标 binary、端口、种子）。

环境独立于模拟会话存活：会话结束（idle-reap/stop）后环境继续运行，供
挖掘 agent 通过 /emul/envs 与 fw_emul_send 消费。
"""
from __future__ import annotations

import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

_ENV_ID_RE = re.compile(r"^emul-[0-9a-f]{4,12}-[0-9a-f]{4}$")
_REQ_ID_RE = re.compile(r"^emulreq-[0-9a-f]{4,12}-[0-9a-f]{4}$")

ENV_STATUSES = ("building", "built", "booting", "ready", "degraded",
                "stopped", "failed", "purged")
REQ_STATUSES = ("pending", "working", "ready", "failed", "cancelled")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emul_root(data_dir) -> Path:
    return Path(data_dir) / "emul"


def envs_dir(data_dir) -> Path:
    return emul_root(data_dir) / "envs"


def requests_dir(data_dir) -> Path:
    return emul_root(data_dir) / "requests"


def new_env_id(job_id: str) -> str:
    return f"emul-{str(job_id)[:12]}-{secrets.token_hex(2)}"


def new_request_id(job_id: str) -> str:
    return f"emulreq-{str(job_id)[:12]}-{secrets.token_hex(2)}"


def _valid_sid(sid: str) -> bool:
    return bool(re.match(r"^[A-Za-z0-9_.-]{1,64}$", str(sid or "")))


def save_env(data_dir, env: dict) -> None:
    env["updated_at"] = _now()
    path = envs_dir(data_dir) / f"{env['env_id']}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(env, indent=2), encoding="utf-8")


def load_env(data_dir, env_id: str) -> dict | None:
    if not _ENV_ID_RE.match(str(env_id or "")):
        return None
    path = envs_dir(data_dir) / f"{env_id}.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def list_envs(data_dir, job_id: str | None = None,
              status: str | None = None) -> list:
    root = envs_dir(data_dir)
    if not root.is_dir():
        return []
    out = []
    for p in sorted(root.glob("emul-*.json")):
        try:
            env = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if job_id and env.get("job_id") != job_id:
            continue
        if status and env.get("status") != status:
            continue
        out.append(env)
    out.sort(key=lambda e: e.get("created_at") or "", reverse=True)
    return out


def save_request(data_dir, req: dict) -> None:
    req["updated_at"] = _now()
    path = requests_dir(data_dir) / f"{req['req_id']}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(req, indent=2), encoding="utf-8")


def load_request(data_dir, req_id: str) -> dict | None:
    if not _REQ_ID_RE.match(str(req_id or "")):
        return None
    path = requests_dir(data_dir) / f"{req_id}.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def list_requests(data_dir, job_id: str | None = None) -> list:
    root = requests_dir(data_dir)
    if not root.is_dir():
        return []
    out = []
    for p in sorted(root.glob("emulreq-*.json")):
        try:
            req = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if job_id and req.get("job_id") != job_id:
            continue
        out.append(req)
    out.sort(key=lambda r: r.get("created_at") or "", reverse=True)
    return out


def new_env_record(env_id: str, job_id: str, session_id: str,
                   workspace: str, arch: str, rootfs_source: str,
                   budget_bytes: int, request_id: str = "",
                   owner: str = "admin") -> dict:
    return {
        "env_id": env_id, "job_id": job_id, "session_id": session_id,
        "owner": owner, "request_id": request_id,
        "status": "building", "error": None,
        "arch": arch, "rootfs_source": rootfs_source,
        "workspace": workspace,
        "budget_bytes": int(budget_bytes),
        "disk_bytes": 0,
        "services": [],       # [{name, container, binary_md5, binary_path,
        #   argv, argv0, guest_port, host_port, status, boot_attempts}]
        "verified_endpoints": [],   # publish 复探通过的端点
        "iterations": 0,
        "notes": [],
        "created_at": _now(), "updated_at": _now(),
    }


def new_request_record(req_id: str, job_id: str, goal: str,
                       targets: dict, from_session: str,
                       from_agent: str = "vuln-miner",
                       owner: str = "admin") -> dict:
    return {
        "req_id": req_id, "job_id": job_id, "goal": str(goal or ""),
        "targets": dict(targets or {}),
        "from_session": str(from_session or ""),
        "from_agent": from_agent, "owner": owner,
        "status": "pending", "error": None,
        "emul_session": "", "env_id": "",
        "created_at": _now(), "updated_at": _now(),
    }


def env_note(env: dict, text: str) -> None:
    notes = env.setdefault("notes", [])
    notes.append({"at": _now(), "text": str(text)[:500]})
    if len(notes) > 40:
        del notes[:len(notes) - 40]


def service_of(env: dict, name: str):
    for svc in env.get("services", []):
        if svc.get("name") == name:
            return svc
    return None


def container_alive(container: str) -> bool:
    """docker 容器是否还在跑（编排器重启后的对账用）。"""
    import subprocess
    if not re.match(r"^[\w.-]{1,96}$", container or ""):
        return False
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container],
            capture_output=True, text=True, timeout=6)
        return out.returncode == 0 and out.stdout.strip() == "true"
    except (OSError, subprocess.TimeoutExpired):
        return False
