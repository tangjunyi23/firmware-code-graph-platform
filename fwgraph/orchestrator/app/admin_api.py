"""Admin console API: auth sessions, user/system/log/dashboard/report
management, and the one-shot auto chain.

Registered from main.py via setup(app, require_token, require_admin),
mirroring vulnagent_api. All data paths resolve FWGRAPH_DATA at call time
(through accounts.data_dir()) so tests can monkeypatch the env var.

Endpoints:
  POST /auth/login                 public, {username, password} -> {token, user}
  GET  /auth/me                    current principal
  POST /auth/logout                drop the current session token
  POST /auth/password              change own password (revokes other sessions)
  GET/POST /users, PATCH/DELETE /users/{username}   user CRUD (admin)
  GET  /system/info                host/component/resource inventory
  GET/PUT /system/config           whitelisted runtime config (PUT = admin)
  GET  /logs, /logs/tail           orchestrator/EMBA log listing + tail (admin)
  GET  /dashboard                  jobs/sessions/findings/reports counters
  POST/GET /jobs/{job_id}/report   deterministic综合报告 (pipeline/report.py)
  GET  /reports, /reports/{rid}[/download]         report aggregation
                                   (non-admin sees only own jobs'/sessions')
  GET  /reports/{rid}/export?fmt=docx|pdf          DOCX/PDF export
  POST /jobs/{job_id}/auto         mark job auto and resume the chain
"""

import json
import os
import platform
import re
import shutil
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Body, Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse

from . import accounts, config, extractor, report_export, vulnagent_api
from pipeline import report as job_report

# fwgraph/orchestrator/app/admin_api.py -> ../../.. = fwgraph/
FWGRAPH_ROOT = Path(__file__).resolve().parents[2]

# keys editable via GET/PUT /system/config (data/settings.json overrides env)
CONFIG_KEYS = [
    "AUTO_INPUTS", "AUTO_DECOMPILE", "AUTO_ATTACK", "AUTO_ROUTES",
    "AUTO_SURFACES", "AUTO_GRAPHEXT", "AUTO_ATTACK_AI", "AUTO_FULL",
    "VULNAGENT_ENGINE",
    "LLM_MODEL", "LLM_BASE_URL", "IDA_WORKERS",
    "EMBA_TIMEOUT",
]

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{2,32}$")
_RID_RE = re.compile(r"^job-[a-f0-9]{12}$|^sess-s-[a-z0-9]+-[a-f0-9]{4}$|^pf-[0-9a-f]{8}$")

_START_TS = time.time()


def _settings_path() -> Path:
    return accounts.data_dir() / "settings.json"


def load_settings() -> dict:
    try:
        doc = json.loads(_settings_path().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return doc if isinstance(doc, dict) else {}


def apply_settings():
    """Overlay data/settings.json onto os.environ (called at startup)."""
    for key, value in load_settings().items():
        if key in CONFIG_KEYS:
            os.environ[key] = str(value)


def _public_user(user: dict) -> dict:
    return {k: user.get(k) for k in ("username", "role", "disabled",
                                     "created_at")}


# ---------------------------------------------------------------------------
# system info helpers
# ---------------------------------------------------------------------------

def _ida_present() -> bool:
    """IDA_DIR env 优先；未配置时保留 ~/ida-pro* / ~/ida 的探测兜底。"""
    ida = config.ida_dir()
    if ida is not None:
        return (ida / "idat").exists()
    home = Path.home()
    return any(home.glob("ida-pro*")) or (home / "ida").exists()


def _dsh_present() -> bool:
    repo = vulnagent_api.DSH_REPO
    return any((repo / p).exists()
               for p in ("dist", "apps/cli/dist", "node_modules"))


def _frida_present() -> bool:
    try:
        import frida  # noqa: F401
        return True
    except Exception:  # noqa: BLE001 - any import failure means absent
        return False


def _mem_info() -> dict:
    total = available = None
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, _, rest = line.partition(":")
            if key == "MemTotal":
                total = int(rest.strip().split()[0]) // 1024
            elif key == "MemAvailable":
                available = int(rest.strip().split()[0]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return {"mem_total_mb": total, "mem_available_mb": available}


def _system_info() -> dict:
    data = accounts.data_dir()
    disk = shutil.disk_usage(str(data))
    try:
        loadavg = list(os.getloadavg())
    except OSError:
        loadavg = None
    api_key = os.getenv("LLM_API_KEY", "")
    afl = Path.home() / "AFLplusplus"
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "uptime_seconds": int(time.time() - _START_TS),
        "pid": os.getpid(),
        "components": {
            "ida": _ida_present(),
            "emba": Path(os.getenv("EMBA_DIR",
                                   extractor.EMBA_DIR_DEFAULT)).is_dir(),
            "cbm": (Path.home() / ".cache" / "codebase-memory-mcp").exists(),
            "frida": _frida_present(),
            "dsh": _dsh_present(),
            "afl_qemu": {arch: (afl / f"afl-qemu-trace-{arch}").exists()
                         for arch in ("arm", "aarch64", "mips", "mipsel")},
            "llm": {
                "base_url": os.getenv("LLM_BASE_URL", ""),
                "model": os.getenv("LLM_MODEL", ""),
                "api_key": ("sk-***" + api_key[-4:]) if api_key else "",
            },
            "resources": {
                "disk": {"total": disk.total, "used": disk.used,
                         "free": disk.free},
                **_mem_info(),
                "loadavg": loadavg,
            },
        },
    }


# ---------------------------------------------------------------------------
# logs helpers
# ---------------------------------------------------------------------------

def _collect_logs() -> dict:
    """{name: {name, path, size, mtime}}; name is the path relative to data."""
    data = accounts.data_dir()
    out = {}

    def add(path: Path):
        if not path.is_file():
            return
        rel = path.relative_to(data).as_posix()
        stat = path.stat()
        out[rel] = {"name": rel, "path": rel, "size": stat.st_size,
                    "mtime": datetime.fromtimestamp(
                        stat.st_mtime, timezone.utc).isoformat()}

    add(data / "orchestrator.log")
    for path in sorted(data.glob("*.log")):
        add(path)
    extracted = data / "extracted"
    if extracted.is_dir():
        for path in sorted(extracted.glob("*.emba.log")):
            add(path)
    return out


# ---------------------------------------------------------------------------
# reports helpers
# ---------------------------------------------------------------------------

def _list_reports() -> list:
    """data/reports/job-*.md + pf-*.md + vulnagent sessions/*/report.md,
    newest first."""
    data = accounts.data_dir()
    out = []
    reports_dir = data / "reports"
    if reports_dir.is_dir():
        for path in reports_dir.glob("job-*.md"):
            job_id = path.stem[4:]
            job = job_report._read_json(
                data / "firmware" / job_id / "job.json") or {}
            stat = path.stat()
            out.append({
                "report_id": path.stem,
                "kind": "job",
                "title": f"{job.get('firmware') or job_id} 综合报告",
                "ref_id": job_id,
                "owner": job.get("owner"),
                "created_at": datetime.fromtimestamp(
                    stat.st_mtime, timezone.utc).isoformat(),
                "size": stat.st_size,
            })
        for path in reports_dir.glob("pf-*.md"):
            run = job_report._read_json(
                data / "protofuzz" / path.stem / "run.json") or {}
            stat = path.stat()
            out.append({
                "report_id": path.stem,
                "kind": "protofuzz",
                "title": f"{run.get('name') or path.stem} 协议测试报告",
                "ref_id": path.stem,
                "owner": run.get("owner"),
                "created_at": datetime.fromtimestamp(
                    stat.st_mtime, timezone.utc).isoformat(),
                "size": stat.st_size,
            })
    sessions_dir = vulnagent_api.VULNAGENT_HOME / "sessions"
    if sessions_dir.is_dir():
        for sdir in sessions_dir.iterdir():
            report_file = sdir / "report.md"
            if not sdir.is_dir() or not report_file.is_file():
                continue
            state = vulnagent_api._read_state(sdir)
            task = (state.get("task") or "").strip()
            title = task[:40] + ("…" if len(task) > 40 else "") or sdir.name
            stat = report_file.stat()
            out.append({
                "report_id": f"sess-{sdir.name}",
                "kind": "session",
                "title": title,
                "ref_id": sdir.name,
                # sessions created before ownership existed count as admin's
                "owner": state.get("owner") or "admin",
                "created_at": datetime.fromtimestamp(
                    stat.st_mtime, timezone.utc).isoformat(),
                "size": stat.st_size,
            })
    out.sort(key=lambda r: r["created_at"], reverse=True)
    return out


def _report_owner(rid: str) -> str | None:
    """Owner of a report id: job reports take the job's owner (None = legacy,
    visible to all); session reports take the session owner (missing =
    admin-owned, the conservative default for pre-ownership sessions)."""
    if rid.startswith("job-"):
        job = job_report._read_json(
            accounts.data_dir() / "firmware" / rid[len("job-"):] / "job.json"
        ) or {}
        return job.get("owner")
    if rid.startswith("pf-"):
        run = job_report._read_json(
            accounts.data_dir() / "protofuzz" / rid / "run.json") or {}
        return run.get("owner")
    state = vulnagent_api._read_state(
        vulnagent_api.VULNAGENT_HOME / "sessions" / rid[len("sess-"):])
    return state.get("owner") or "admin"


def _check_report_access(rid: str, principal: dict):
    """404 (not 403) for other users' reports — no existence disclosure."""
    if not _RID_RE.match(rid):
        raise HTTPException(status_code=400, detail="bad report id format")
    if not accounts.can_access(principal, _report_owner(rid)):
        raise HTTPException(status_code=404, detail="report not found")


def _report_path(rid: str) -> Path:
    """Resolve a report id to its file (strict regex, no traversal)."""
    if not _RID_RE.match(rid):
        raise HTTPException(status_code=400, detail="bad report id format")
    if rid.startswith("job-") or rid.startswith("pf-"):
        path = accounts.data_dir() / "reports" / f"{rid}.md"
    else:
        path = (vulnagent_api.VULNAGENT_HOME / "sessions"
                / rid[len("sess-"):] / "report.md")
    if not path.is_file():
        raise HTTPException(status_code=404, detail="report not found")
    return path


def _auto_chain(job_id: str, start: str):
    """Resume the auto chain at graph (graph chains attack/routes/surfaces).

    `start` is kept for the call site; AILIFT was removed so every resume
    goes straight to graph.
    """
    from . import main as _main
    _main._graph_worker(job_id)


# ---------------------------------------------------------------------------
# route registration
# ---------------------------------------------------------------------------

def setup(app: FastAPI, require_token, require_admin) -> None:
    """Register admin routes. Call BEFORE webui.setup(app) so the SPA
    catch-all does not shadow them."""
    auth = [Depends(require_token)]

    # --- auth & sessions --------------------------------------------------

    @app.post("/auth/login")
    def login(request: Request, payload: dict = Body(...)):
        username = str(payload.get("username") or "")
        password = str(payload.get("password") or "")
        ip = request.client.host if request.client else "?"
        locked = accounts.login_lock_remaining(username, ip)
        if locked > 0:
            raise HTTPException(
                status_code=429,
                detail=f"失败次数过多，已临时锁定，请 {locked} 秒后重试")
        user = accounts.find_user(username)
        if user is None:
            # timing flatten: unknown users pay the same PBKDF2 cost so the
            # response time does not reveal whether the account exists
            accounts.hash_password(password, accounts.DUMMY_SALT)
        if (user is None or user.get("disabled")
                or not accounts.verify_password(
                    password, user["salt"], user["password_hash"])):
            accounts.record_login_failure(username, ip)
            accounts.audit(username or "?", "login_fail", f"ip={ip}")
            raise HTTPException(status_code=401, detail="用户名或密码错误")
        accounts.clear_login_failures(username, ip)
        token = accounts.create_session(user["username"], user["role"])
        accounts.audit(user["username"], "login_ok")
        return {"token": token,
                "user": {"username": user["username"], "role": user["role"],
                         "created_at": user.get("created_at"),
                         "must_change_password": bool(
                             user.get("must_change_password"))}}

    @app.get("/auth/me")
    def auth_me(principal: dict = Depends(require_token)):
        out = {k: v for k, v in principal.items() if k != "token"}
        user = (None if principal.get("legacy")
                else accounts.find_user(principal["username"]))
        out["must_change_password"] = bool(
            user and user.get("must_change_password"))
        return out

    @app.post("/auth/logout")
    def logout(principal: dict = Depends(require_token)):
        if not principal.get("legacy") and principal.get("token"):
            accounts.delete_session(principal["token"])
            accounts.audit(principal["username"], "logout")
        return {"ok": True}

    @app.post("/auth/password")
    def change_password(payload: dict = Body(...),
                        principal: dict = Depends(require_token)):
        if principal.get("legacy"):
            raise HTTPException(
                status_code=400,
                detail="legacy token principal has no password to change")
        old = str(payload.get("old_password") or "")
        new = str(payload.get("new_password") or "")
        policy_err = accounts.validate_password(new)
        if policy_err:
            raise HTTPException(status_code=400, detail=policy_err)
        user = accounts.find_user(principal["username"])
        if (user is None or not accounts.verify_password(
                old, user["salt"], user["password_hash"])):
            raise HTTPException(status_code=400, detail="旧密码错误")
        accounts.update_user(user["username"], password=new,
                             must_change_password=False)
        accounts.revoke_user_sessions(user["username"],
                                      keep_token=principal.get("token"))
        accounts.audit(user["username"], "password_change")
        return {"ok": True}

    # --- user management (admin) ------------------------------------------

    @app.get("/users")
    def list_users(principal: dict = Depends(require_admin)):
        return [_public_user(u) for u in accounts.load_users()["users"]]

    @app.post("/users", status_code=201)
    def create_user(payload: dict = Body(...),
                    principal: dict = Depends(require_admin)):
        username = str(payload.get("username") or "")
        password = str(payload.get("password") or "")
        role = str(payload.get("role") or "user")
        if not _USERNAME_RE.match(username):
            raise HTTPException(
                status_code=400,
                detail="username must match ^[a-zA-Z0-9_.-]{2,32}$")
        if role not in ("admin", "user"):
            raise HTTPException(status_code=400,
                                detail="role must be admin|user")
        policy_err = accounts.validate_password(password)
        if policy_err:
            raise HTTPException(status_code=400, detail=policy_err)
        if accounts.find_user(username) is not None:
            raise HTTPException(status_code=409, detail="user already exists")
        user = accounts.create_user(username, password, role)
        accounts.audit(principal["username"], "user_create",
                       f"{username} role={role}")
        return _public_user(user)

    @app.patch("/users/{username}")
    def update_user(username: str, payload: dict = Body(...),
                    principal: dict = Depends(require_admin)):
        target = accounts.find_user(username)
        if target is None:
            raise HTTPException(status_code=404, detail="user not found")
        role = payload.get("role")
        disabled = payload.get("disabled")
        password = payload.get("password")
        if role is not None and role not in ("admin", "user"):
            raise HTTPException(status_code=400,
                                detail="role must be admin|user")
        if password is not None:
            policy_err = accounts.validate_password(str(password))
            if policy_err:
                raise HTTPException(status_code=400, detail=policy_err)
        demoting = (role is not None and role != "admin"
                    and target.get("role") == "admin")
        disabling = disabled is True and not target.get("disabled")
        if disabling and username == principal["username"]:
            raise HTTPException(status_code=400,
                                detail="不能禁用当前登录账号")
        if (demoting or disabling) and not target.get("disabled") \
                and target.get("role") == "admin" \
                and len(accounts.active_admins()) <= 1:
            raise HTTPException(status_code=400,
                                detail="不能禁用/降级最后一个可用 admin")
        changed = []
        if role is not None:
            changed.append(f"role={role}")
        if disabled is not None:
            changed.append(f"disabled={bool(disabled)}")
        if password is not None:
            changed.append("password")
        user = accounts.update_user(
            username, role=role,
            disabled=bool(disabled) if disabled is not None else None,
            password=str(password) if password is not None else None)
        if password is not None:
            accounts.revoke_user_sessions(username)
        accounts.audit(principal["username"], "user_update",
                       f"{username} {' '.join(changed)}")
        return _public_user(user)

    @app.delete("/users/{username}")
    def delete_user(username: str, principal: dict = Depends(require_admin)):
        target = accounts.find_user(username)
        if target is None:
            raise HTTPException(status_code=404, detail="user not found")
        if username == principal["username"]:
            raise HTTPException(status_code=400,
                                detail="不能删除当前登录账号")
        if target.get("role") == "admin" and not target.get("disabled") \
                and len(accounts.active_admins()) <= 1:
            raise HTTPException(status_code=400,
                                detail="不能删除最后一个可用 admin")
        accounts.delete_user(username)
        accounts.revoke_user_sessions(username)
        accounts.audit(principal["username"], "user_delete", username)
        return {"ok": True}

    # --- system ------------------------------------------------------------

    @app.get("/system/info")
    def system_info(principal: dict = Depends(require_token)):
        info = _system_info()
        if principal.get("role") != "admin":
            # the masked api_key is still a partial secret — admins only
            info["components"]["llm"].pop("api_key", None)
        return info

    @app.get("/system/config", dependencies=auth)
    def get_config():
        settings = load_settings()
        return {key: settings.get(key, os.environ.get(key, ""))
                for key in CONFIG_KEYS}

    @app.put("/system/config")
    def put_config(payload: dict = Body(...),
                   principal: dict = Depends(require_admin)):
        unknown = sorted(k for k in payload if k not in CONFIG_KEYS)
        if unknown:
            raise HTTPException(
                status_code=400,
                detail=f"unknown config keys: {', '.join(unknown)}")
        settings = load_settings()
        for key, value in payload.items():
            settings[key] = str(value)
        settings_path = _settings_path()
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_path.write_text(json.dumps(settings, indent=2),
                                 encoding="utf-8")
        apply_settings()
        accounts.audit(principal["username"], "config_change",
                       ",".join(sorted(payload)))
        return {key: settings.get(key, os.environ.get(key, ""))
                for key in CONFIG_KEYS}

    # --- logs --------------------------------------------------------------

    @app.get("/logs")
    def list_logs(principal: dict = Depends(require_admin)):
        return sorted(_collect_logs().values(), key=lambda e: e["name"])

    @app.get("/logs/tail")
    def tail_log(name: str, lines: int = 200,
                 principal: dict = Depends(require_admin)):
        logs = _collect_logs()
        if name not in logs:
            if ".." in name or name.startswith("/"):
                raise HTTPException(status_code=400, detail="bad log name")
            raise HTTPException(status_code=404, detail="log not found")
        data_root = accounts.data_dir().resolve()
        path = (data_root / logs[name]["path"]).resolve()
        if data_root not in path.parents and path != data_root:
            raise HTTPException(status_code=400, detail="bad log name")
        lines = max(1, min(lines, 1000))
        with open(path, "rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - 1024 * 1024))
            tail = fh.read().decode("utf-8", errors="replace").splitlines()
        return {"name": name, "lines": tail[-lines:]}

    # --- audit ---------------------------------------------------------------

    @app.get("/audit")
    def list_audit(limit: int = 200,
                   principal: dict = Depends(require_admin)):
        limit = max(1, min(limit, 1000))
        path = accounts._audit_path()
        entries = []
        if path.is_file():
            for line in path.read_text(encoding="utf-8",
                                       errors="replace").splitlines():
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return entries[::-1][:limit]

    # --- dashboard -----------------------------------------------------------

    @app.get("/dashboard", dependencies=auth)
    def dashboard():
        from . import main as _main
        with _main._jobs_lock:
            jobs = [dict(j) for j in _main._jobs.values()]
        by_status = {}
        for job in jobs:
            status = job.get("status", "unknown")
            by_status[status] = by_status.get(status, 0) + 1
        running = [{"job_id": j["job_id"], "firmware": j.get("firmware"),
                    "status": j.get("status"),
                    "updated_at": j.get("updated_at")}
                   for j in jobs if j.get("status") in _main.STATUS_RUNNING]
        sessions_total = sessions_running = 0
        sessions_dir = vulnagent_api.VULNAGENT_HOME / "sessions"
        if sessions_dir.is_dir():
            for sdir in sessions_dir.iterdir():
                if not sdir.is_dir():
                    continue
                sessions_total += 1
                state = vulnagent_api._read_state(sdir)
                if vulnagent_api._effective_status(sdir.name,
                                                   state) == "running":
                    sessions_running += 1
        findings_dir = vulnagent_api.VULNAGENT_HOME / "findings"
        findings_total = (len(list(findings_dir.glob("F-*.json")))
                          if findings_dir.is_dir() else 0)
        data = accounts.data_dir()
        inputs_dir = data / "inputs"
        surfaces_dir = data / "surfaces"
        return {
            "jobs_total": len(jobs),
            "jobs_by_status": by_status,
            "running": running,
            "sessions_total": sessions_total,
            "sessions_running": sessions_running,
            "findings_total": findings_total,
            "reports_total": len(_list_reports()),
            "inputs_total": (len(list(inputs_dir.glob("*/identification.json")))
                             if inputs_dir.is_dir() else 0),
            "surfaces_total": (len(list(
                surfaces_dir.glob("*/information/AS-*.json")))
                if surfaces_dir.is_dir() else 0),
        }

    # --- reports -----------------------------------------------------------

    @app.post("/jobs/{job_id}/report")
    def generate_report(job_id: str,
                        principal: dict = Depends(require_token)):
        from . import main as _main
        data = accounts.data_dir()
        if _main._jobs.get(job_id) is None and not (
                data / "firmware" / job_id / "job.json").is_file():
            raise HTTPException(status_code=404, detail="job not found")
        job_report.generate_job_report(job_id, data)
        accounts.audit(principal["username"], "report_generate", job_id)
        return {"report_id": f"job-{job_id}"}

    @app.get("/jobs/{job_id}/report", dependencies=auth)
    def get_job_report(job_id: str):
        path = accounts.data_dir() / "reports" / f"job-{job_id}.md"
        if not path.is_file():
            raise HTTPException(status_code=404,
                                detail="report not generated yet")
        return PlainTextResponse(path.read_text(encoding="utf-8",
                                                errors="replace"))

    @app.get("/reports")
    def list_reports(principal: dict = Depends(require_token)):
        return [r for r in _list_reports()
                if accounts.can_access(principal, r.get("owner"))]

    @app.get("/reports/{rid}")
    def get_report(rid: str, principal: dict = Depends(require_token)):
        path = _report_path(rid)
        _check_report_access(rid, principal)
        return PlainTextResponse(path.read_text(encoding="utf-8",
                                                errors="replace"))

    @app.get("/reports/{rid}/download")
    def download_report(rid: str, principal: dict = Depends(require_token)):
        path = _report_path(rid)
        _check_report_access(rid, principal)
        accounts.audit(principal["username"], "report_download", rid)
        return FileResponse(path, filename=f"{rid}.md",
                            media_type="text/markdown")

    @app.get("/reports/{rid}/export")
    def export_report_file(rid: str, fmt: str = "docx",
                           principal: dict = Depends(require_token)):
        _check_report_access(rid, principal)
        path = report_export.export_report(rid, fmt, accounts.data_dir())
        accounts.audit(principal["username"], "report_export",
                       f"{rid} fmt={fmt}")
        return FileResponse(path, filename=f"{rid}.{fmt}",
                            media_type=report_export.MEDIA_TYPES[fmt])

    # --- one-shot auto chain -------------------------------------------------

    @app.post("/jobs/{job_id}/auto", status_code=202, dependencies=auth)
    def trigger_auto(job_id: str):
        from . import main as _main
        job = _main._jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        with _main._jobs_lock:
            if job["status"] in _main.STATUS_RUNNING:
                raise HTTPException(
                    status_code=409,
                    detail=f"job is {job['status']}, wait for it to finish")
            job["auto"] = True
            _main._save_job(job)
            status = job["status"]
        resumed = None
        if status in ("decompiled", "ailifted"):
            resumed = "graph"
        if resumed:
            threading.Thread(target=_auto_chain, args=(job_id, resumed),
                             daemon=True).start()
        return {"job_id": job_id, "status": status, "auto": True,
                "resumed": resumed}
