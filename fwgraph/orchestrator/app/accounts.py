"""Account, session and audit storage for the orchestrator admin console.

Users live in data/users.json (PBKDF2-HMAC-SHA256 password hashes), sessions
in data/sessions.json ("fws-" bearer tokens with a 7-day sliding TTL), the
audit trail is appended to data/audit.jsonl, login brute-force counters in
data/login_attempts.json and per-job daily trigger quotas in
data/quotas.json. All paths resolve FWGRAPH_DATA at call time (never at
import) so tests can monkeypatch the env var; every JSON read tolerates a
corrupt file by treating it as empty. The only non-stdlib import is
fastapi.HTTPException, raised by check_quota so callers (the trigger
endpoints) get a 429 for free.
"""

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import HTTPException

from . import config

SESSION_TTL_SECONDS = 7 * 24 * 3600
_PBKDF2_ITERATIONS = 100_000
_TOKEN_PREFIX = "fws-"

# Login brute-force guard: LOGIN_MAX_FAILS failures inside the window lock
# the (username, source-ip) pair for LOGIN_LOCK_SECONDS.
LOGIN_WINDOW_SECONDS = 600
LOGIN_MAX_FAILS = 5
LOGIN_LOCK_SECONDS = 600
# Fixed salt for the dummy PBKDF2 run on unknown usernames, so a login with
# a non-existent user costs the same as a wrong password (timing flatten).
DUMMY_SALT = "00" * 16

PASSWORD_MIN_LENGTH = 10
# Common weak passwords, matched case-insensitively (20 entries).
WEAK_PASSWORDS = frozenset({
    "password", "password1", "p@ssw0rd", "123456", "12345678",
    "123456789", "1234567890", "123123123", "11111111", "00000000",
    "qwerty", "qwerty123", "abc12345", "admin123", "admin1234",
    "root1234", "letmein", "iloveyou", "changeme", "fwgraph123",
})

# Per-job daily trigger quotas: kind -> (env var with the limit, default).
_QUOTA_LIMITS = {
    "trace": ("TRACE_DAILY_PER_JOB", 96),
    "fuzz": ("FUZZ_DAILY_PER_JOB", 12),
    "exec": ("EXEC_DAILY_PER_JOB", 48),
    "frida": ("FRIDA_DAILY_PER_JOB", 6),
    "protofuzz": ("PROTOFUZZ_DAILY", 8),
    "attack_ai": ("ATTACK_AI_DAILY_PER_JOB", 8),
}

_lock = threading.Lock()


def data_dir() -> Path:
    """Resolve the fwgraph data dir at call time (tests monkeypatch the env)."""
    return config.data_dir()


def _users_path() -> Path:
    return data_dir() / "users.json"


def _sessions_path() -> Path:
    return data_dir() / "sessions.json"


def _audit_path() -> Path:
    return data_dir() / "audit.jsonl"


def _attempts_path() -> Path:
    return data_dir() / "login_attempts.json"


def _quotas_path() -> Path:
    return data_dir() / "quotas.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _write_json(path: Path, doc):
    """Atomic write (tmp + rename) so a crash never leaves a half file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# passwords
# ---------------------------------------------------------------------------

def hash_password(password: str, salt: str) -> str:
    """PBKDF2-HMAC-SHA256 hex digest; salt is 16 random bytes hex-encoded."""
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt),
        _PBKDF2_ITERATIONS).hex()


def verify_password(password: str, salt: str, expected: str) -> bool:
    return hmac.compare_digest(hash_password(password, salt), expected)


def validate_password(password: str) -> str | None:
    """Password policy: returns a Chinese error message, or None when OK.

    Shared by registration, password change and admin reset so all three
    enforce the same rules: >= PASSWORD_MIN_LENGTH chars and not on the
    common weak-password blacklist.
    """
    if len(password) < PASSWORD_MIN_LENGTH:
        return f"密码至少 {PASSWORD_MIN_LENGTH} 位"
    if password.lower() in WEAK_PASSWORDS:
        return "密码过于常见（弱口令黑名单），请换一个更强的密码"
    return None


# ---------------------------------------------------------------------------
# users
# ---------------------------------------------------------------------------
# in-memory caches (single-process uvicorn; write-through / debounced)
# 每请求读写 sessions.json 的热点路径（前端 8 个视图 2-8s 轮询全部
# 经过这里）改为内存权威副本 + 去抖落盘：滑动续期合并写，结构性
# 变化（登录/登出/过期清理）立即落盘。重启最多丢一次未落盘的
# 续期滑动（TTL 7 天，无实际影响）。
# ---------------------------------------------------------------------------
_SESSIONS_FLUSH_INTERVAL = 60.0
_sessions_cache: tuple | None = None      # (path, doc)
_sessions_flush_at: float = 0.0
_quotas_cache: tuple | None = None        # (path, doc)
_audit_lock = threading.Lock()


def _sessions_state() -> dict:
    global _sessions_cache
    if _sessions_cache is None or _sessions_cache[0] != _sessions_path():
        _sessions_cache = (_sessions_path(), load_sessions())
    return _sessions_cache[1]


def _flush_sessions(force: bool = False) -> None:
    global _sessions_flush_at
    now = time.monotonic()
    if force or now - _sessions_flush_at > _SESSIONS_FLUSH_INTERVAL:
        if _sessions_cache is not None:
            _write_json(_sessions_cache[0], _sessions_cache[1])
        _sessions_flush_at = now


def _quotas_state() -> dict:
    global _quotas_cache
    if _quotas_cache is None or _quotas_cache[0] != _quotas_path():
        doc = _read_json(_quotas_path(), {})
        _quotas_cache = (_quotas_path(), doc if isinstance(doc, dict) else {})
    return _quotas_cache[1]

# ---------------------------------------------------------------------------

def load_users() -> dict:
    doc = _read_json(_users_path(), {"users": []})
    if not isinstance(doc, dict) or not isinstance(doc.get("users"), list):
        return {"users": []}
    return doc


def find_user(username: str) -> dict | None:
    for user in load_users()["users"]:
        if user.get("username") == username:
            return user
    return None


def create_user(username: str, password: str, role: str = "user") -> dict:
    # PBKDF2 (~100ms) computed OUTSIDE the lock: the auth hot path
    # (resolve_session) must not convoy behind user mutations.
    salt = secrets.token_hex(16)
    hashed = hash_password(password, salt)
    with _lock:
        doc = load_users()
        user = {
            "username": username,
            "password_hash": hashed,
            "salt": salt,
            "role": role,
            "disabled": False,
            "created_at": _now(),
        }
        doc["users"].append(user)
        _write_json(_users_path(), doc)
        return user


def update_user(username: str, **fields) -> dict | None:
    """Apply role/disabled/password changes; returns the updated user."""
    new_salt = new_hash = None
    if fields.get("password"):
        # PBKDF2 outside the lock (see create_user)
        new_salt = secrets.token_hex(16)
        new_hash = hash_password(fields["password"], new_salt)
    with _lock:
        doc = load_users()
        for user in doc["users"]:
            if user.get("username") != username:
                continue
            if fields.get("role") is not None:
                user["role"] = fields["role"]
            if fields.get("disabled") is not None:
                user["disabled"] = bool(fields["disabled"])
            if new_hash:
                user["salt"] = new_salt
                user["password_hash"] = new_hash
            if fields.get("must_change_password") is not None:
                user["must_change_password"] = bool(
                    fields["must_change_password"])
            _write_json(_users_path(), doc)
            return user
    return None


def delete_user(username: str) -> bool:
    with _lock:
        doc = load_users()
        kept = [u for u in doc["users"] if u.get("username") != username]
        if len(kept) == len(doc["users"]):
            return False
        doc["users"] = kept
        _write_json(_users_path(), doc)
        return True


def active_admins() -> list:
    """Enabled admins — the last one may never be disabled/demoted/deleted."""
    return [u for u in load_users()["users"]
            if u.get("role") == "admin" and not u.get("disabled")]


def ensure_initial_admin(log=None):
    """Create the bootstrap admin on first start (no users.json yet)."""
    if log is None:
        def log(msg):  # default: straight to the orchestrator log (stdout)
            print(msg, flush=True)
    with _lock:
        if _users_path().is_file():
            return
        password = os.getenv("ADMIN_INITIAL_PASSWORD")
        if password is None:
            # FWGRAPH_STRICT_SECRETS=1：拒绝以众所周知的默认口令引导 admin
            # （默认 0，不改变现有行为；已有 users.json 时不触发）
            if config.env_bool("FWGRAPH_STRICT_SECRETS"):
                raise RuntimeError(
                    "FWGRAPH_STRICT_SECRETS=1 但未设置 ADMIN_INITIAL_PASSWORD："
                    "拒绝使用默认初始口令创建 bootstrap admin")
            password = "admin123"
        salt = secrets.token_hex(16)
        doc = {"users": [{
            "username": "admin",
            "password_hash": hash_password(password, salt),
            "salt": salt,
            "role": "admin",
            "disabled": False,
            # force a password change at first login when the bootstrap
            # admin still uses the well-known default password
            "must_change_password": password == "admin123",
            "created_at": _now(),
        }]}
        _write_json(_users_path(), doc)
    log("[accounts] initialized data/users.json with bootstrap admin 'admin' "
        "(password from ADMIN_INITIAL_PASSWORD, default 'admin123')")


# ---------------------------------------------------------------------------
# sessions
# ---------------------------------------------------------------------------

def load_sessions() -> dict:
    doc = _read_json(_sessions_path(), {})
    return doc if isinstance(doc, dict) else {}


def create_session(username: str, role: str) -> str:
    with _lock:
        sessions = _sessions_state()
        token = _TOKEN_PREFIX + secrets.token_hex(24)
        sessions[token] = {
            "username": username,
            "role": role,
            "created_at": _now(),
            "expires_at": _expires_at(),
        }
        _flush_sessions(force=True)
        return token


def _expires_at() -> str:
    return datetime.fromtimestamp(
        datetime.now(timezone.utc).timestamp() + SESSION_TTL_SECONDS,
        timezone.utc).isoformat()


def resolve_session(token: str) -> dict | None:
    """Look up a session token; a hit slides the 7-day expiry forward."""
    with _lock:
        sessions = _sessions_state()
        session = sessions.get(token)
        if session is None:
            return None
        now = datetime.now(timezone.utc)
        try:
            expires = datetime.fromisoformat(session.get("expires_at", ""))
        except ValueError:
            expires = now
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires <= now:
            del sessions[token]
            _flush_sessions(force=True)
            return None
        session["expires_at"] = _expires_at()
        _flush_sessions()  # 滑动续期去抖合并（60s 内多次请求零磁盘写）
        return dict(session)


def delete_session(token: str) -> bool:
    with _lock:
        sessions = _sessions_state()
        if token not in sessions:
            return False
        del sessions[token]
        _flush_sessions(force=True)
        return True


def revoke_user_sessions(username: str, keep_token: str | None = None) -> int:
    """Drop every session of a user (except keep_token); returns the count."""
    with _lock:
        sessions = _sessions_state()
        doomed = [t for t, s in sessions.items()
                  if s.get("username") == username and t != keep_token]
        for token in doomed:
            del sessions[token]
        _flush_sessions(force=True)
        return len(doomed)


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------

def audit(user: str, action: str, detail: str = ""):
    """Append one JSON line to data/audit.jsonl (best-effort, never raises).

    Uses its own lock: audit appends must not convoy behind auth/user
    mutations on the shared _lock (audit fires on nearly every request).
    """
    record = {"ts": _now(), "user": user, "action": action, "detail": detail}
    try:
        with _audit_lock:
            path = _audit_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + chr(10))
    except OSError:
        pass


# ---------------------------------------------------------------------------
# login brute-force guard
# ---------------------------------------------------------------------------

def _attempts_key(username: str, ip: str) -> str:
    return f"{username}@{ip}"


def login_lock_remaining(username: str, ip: str) -> int:
    """Seconds left on the (username, ip) lockout; 0 means not locked."""
    now = time.time()
    with _lock:
        doc = _read_json(_attempts_path(), {})
        if not isinstance(doc, dict):
            return 0
        fails = doc.get(_attempts_key(username, ip))
        if not isinstance(fails, list):
            return 0
        fails = [t for t in fails
                 if isinstance(t, (int, float))
                 and now - t < LOGIN_WINDOW_SECONDS]
        if len(fails) < LOGIN_MAX_FAILS:
            return 0
        return max(0, int(fails[-1] + LOGIN_LOCK_SECONDS - now))


def record_login_failure(username: str, ip: str):
    """Record one failed login; the newest LOGIN_MAX_FAILS timestamps in the
    window are what the lock computation looks at."""
    now = time.time()
    with _lock:
        doc = _read_json(_attempts_path(), {})
        if not isinstance(doc, dict):
            doc = {}
        key = _attempts_key(username, ip)
        fails = [t for t in doc.get(key, [])
                 if isinstance(t, (int, float))
                 and now - t < LOGIN_WINDOW_SECONDS]
        fails.append(now)
        doc[key] = fails[-LOGIN_MAX_FAILS:]
        _write_json(_attempts_path(), doc)


def clear_login_failures(username: str, ip: str):
    """Reset the failure counter after a successful login."""
    with _lock:
        doc = _read_json(_attempts_path(), {})
        if not isinstance(doc, dict) or _attempts_key(username, ip) not in doc:
            return
        del doc[_attempts_key(username, ip)]
        _write_json(_attempts_path(), doc)


# ---------------------------------------------------------------------------
# per-job daily quotas
# ---------------------------------------------------------------------------

def quota_limit(kind: str) -> int:
    """Effective daily limit for a quota kind (env-overridable)."""
    env_key, default = _QUOTA_LIMITS[kind]
    try:
        return int(os.getenv(env_key, "") or default)
    except ValueError:
        return default


def check_quota(job_id: str, kind: str) -> None:
    """Consume one unit of the (job_id, kind, today) quota.

    Raises HTTPException 429 (Chinese detail with 当日已用/上限) when the
    daily limit for this job is already exhausted; the counter lives in an
    in-memory dict (single process) write-through to data/quotas.json.
    """
    if kind not in _QUOTA_LIMITS:
        raise HTTPException(status_code=400,
                            detail=f"未知配额类型 {kind!r}")
    limit = quota_limit(kind)
    day = datetime.now(timezone.utc).date().isoformat()
    key = f"{job_id}:{kind}:{day}"
    with _lock:
        doc = _quotas_state()
        try:
            used = int(doc.get(key, 0))
        except (TypeError, ValueError):
            used = 0
        if used >= limit:
            raise HTTPException(
                status_code=429,
                detail=f"任务 {job_id} 的 {kind} 当日配额已用完"
                       f"（当日已用 {used}/{limit}，次日重置）")
        doc[key] = used + 1
        _write_json(_quotas_path(), doc)  # 配额写透：宁可多写不超卖


# ---------------------------------------------------------------------------
# ownership check
# ---------------------------------------------------------------------------

def can_access(principal: dict, owner: str | None) -> bool:
    """True when the principal may see an object owned by `owner`.

    Admins see everything; objects without a recorded owner (None / "" /
    "legacy") stay visible to everyone (pre-ownership data); otherwise only
    the owner themselves.
    """
    if principal.get("role") == "admin":
        return True
    if owner is None or owner == "" or owner == "legacy":
        return True
    return principal.get("username") == owner
