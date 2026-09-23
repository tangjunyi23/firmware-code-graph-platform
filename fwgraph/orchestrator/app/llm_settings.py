"""LLM 主/备网关设置与自动切换。

主网关：vulnagent/.env 的 LLM_BASE_URL/LLM_API_KEY（opencode go）。
备用网关：data/settings.json 的 llm 段（默认 ark 火山方舟，anthropic 协议
——llm-deepseek messages 协议自拼 /v1/messages，base 即
https://ark.cn-beijing.volces.com/api/plan），用户可在系统设置页改写。

切换策略：dsh host 启动时对主网关做一次轻量探活（结果缓存
LLM_PROBE_CACHE_SECONDS，默认 300s），不通即整会话走备用；会话中途不切换
（dsh llm-retry 已有 5 次退避重试兜底）。LLM_FAILOVER_FORCE=primary|ark
可强制指定（测试用）。
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

import httpx

DEFAULT_FALLBACK = {
    "base": "https://ark.cn-beijing.volces.com/api/plan",
    "key": "",  # 从 LLM_FALLBACK_KEY 环境变量或 data/settings.json llm 段填入
    "model": "deepseek-v4.1-flash",
    "label": "火山方舟 ark（备用）",
}
PROBE_TIMEOUT = float(os.getenv("LLM_PROBE_TIMEOUT", "4"))
PROBE_CACHE = float(os.getenv("LLM_PROBE_CACHE_SECONDS", "300"))

_lock = threading.Lock()
_probe_cache: dict = {"at": 0.0, "ok": None}


def _fwgraph_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _data_dir() -> Path:
    env = os.getenv("FWGRAPH_DATA")
    if env:
        return Path(env)
    return _fwgraph_root() / "data"


def _settings_path() -> Path:
    return _data_dir() / "settings.json"


def load_llm_settings() -> dict:
    merged = {"primary_label": "opencode go（主）", **DEFAULT_FALLBACK}
    try:
        raw = json.loads(_settings_path().read_text(encoding="utf-8"))
        llm = raw.get("llm") or {}
        merged.update({k: llm[k] for k in DEFAULT_FALLBACK if k in llm})
    except (OSError, ValueError):
        pass
    # env 覆盖（部署级）
    for k, envk in (("base", "LLM_FALLBACK_BASE"), ("key", "LLM_FALLBACK_KEY"),
                    ("model", "LLM_FALLBACK_MODEL")):
        if os.getenv(envk):
            merged[k] = os.environ[envk]
    return merged


def save_llm_settings(section: dict) -> dict:
    cur = load_llm_settings()
    for k in DEFAULT_FALLBACK:
        if k in section and section[k] is not None:
            cur[k] = str(section[k]).strip()
    path = _settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    raw: dict = {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    raw["llm"] = {k: cur[k] for k in DEFAULT_FALLBACK}
    path.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    return cur


def _vulnagent_env() -> dict:
    from orchestrator.app import vulnagent_api
    return vulnagent_api._vulnagent_env()


def _strip_v1(url: str) -> str:
    base = (url or "").rstrip("/")
    return base[:-3] if base.endswith("/v1") else base


LLM_PROBE_TIMEOUT = float(os.getenv("LLM_PROBE_TIMEOUT", "12"))


def _llm_alive_openai(base_url: str, key: str, timeout: float) -> bool:
    """最小 chat 调用探活（opencode go，openai 协议 + 会话路由头）。
    200 = 网关与凭据均可用；网关间歇 AuthError/凭据失效在此暴露。"""
    try:
        resp = httpx.post(
            base_url.rstrip("/") + "/chat/completions",
            headers={"Authorization": f"Bearer {key}",
                     "Content-Type": "application/json",
                     "x-opencode-session": "fwgraph-probe"},
            json={"model": "deepseek-v4.1-flash",
                  "messages": [{"role": "user", "content": "hi"}],
                  "max_tokens": 1},
            timeout=timeout)
        return resp.status_code == 200
    except httpx.HTTPError:
        return False


def _llm_alive_anthropic(base_url: str, key: str, model: str,
                         timeout: float) -> bool:
    """最小 messages 调用探活（ark 备用，anthropic 协议）。
    订阅过期/凭据无效返回 4xx —— 网络可达但不可用，不能作为切换目标。"""
    try:
        resp = httpx.post(
            base_url.rstrip("/") + "/v1/messages",
            headers={"x-api-key": key,
                     "anthropic-version": "2023-06-01",
                     "Content-Type": "application/json"},
            json={"model": model or "deepseek-v4.1-flash",
                  "max_tokens": 1,
                  "messages": [{"role": "user", "content": "hi"}]},
            timeout=timeout)
        return resp.status_code == 200
    except httpx.HTTPError:
        return False


def probe_primary(base_url: str, timeout: float = LLM_PROBE_TIMEOUT) -> bool:
    """主网关探活（带缓存；真实最小调用 + 失败重试一次抗抖动）。"""
    now = time.monotonic()
    if _probe_cache["ok"] is not None and now - _probe_cache["at"] < PROBE_CACHE:
        return bool(_probe_cache["ok"])
    key = _vulnagent_env().get("LLM_API_KEY", "")
    ok = _llm_alive_openai(base_url, key, timeout)
    if not ok:
        time.sleep(1.0)
        ok = _llm_alive_openai(base_url, key, timeout)
    with _lock:
        _probe_cache.update({"at": now, "ok": ok})
    return ok


def probe_fallback(timeout: float = LLM_PROBE_TIMEOUT) -> bool:
    """备用网关应用层探活：真实最小调用通过才可作为切换目标
    （订阅过期/凭据无效 = 不可用，留在主网关由 llm-retry 兜底）。"""
    fb = load_llm_settings()
    return _llm_alive_anthropic(fb["base"], fb["key"], fb["model"], timeout)


def resolve_route() -> dict:
    """返回 {base, key, model, source, label}：主网关可达走主，否则备用。"""
    env_file = _vulnagent_env()
    primary_base_raw = env_file.get("LLM_BASE_URL", "")
    primary = {
        "base": _strip_v1(primary_base_raw),
        "key": env_file.get("LLM_API_KEY", ""),
        "model": "deepseek-v4.1-flash",
        "source": "primary",
        "label": "opencode go（主）",
    }
    fb = load_llm_settings()
    fallback = {
        "base": _strip_v1(fb["base"]),
        "key": fb["key"],
        "model": fb["model"] or "deepseek-v4.1-flash",
        "source": "fallback",
        "label": fb.get("label") or "备用网关",
    }
    force = os.getenv("LLM_FAILOVER_FORCE", "").strip().lower()
    if force in ("primary", "main", "opencode"):
        return primary
    if force in ("fallback", "ark", "backup"):
        return fallback
    if primary_base_raw and probe_primary(primary_base_raw):
        return primary
    # 主网关探活失败也不盲切：备用网关必须网络可达才切。备用订阅过期
    # 时切过去只会让整会话立即报错（2026-09-22 实测：主网关单次抖动
    # 误杀 + ark AgentPlan 过期 → 会话崩）；留在主网关交给 dsh llm-retry
    # 的 5 次退避兜底。
    if probe_fallback():
        return fallback
    primary["label"] += "（备用不可达，保持主网关）"
    return primary


def status() -> dict:
    env_file = _vulnagent_env()
    route = resolve_route()
    return {
        "primary_base": env_file.get("LLM_BASE_URL", ""),
        "primary_ok": probe_primary(env_file.get("LLM_BASE_URL", "")),
        "active_source": route["source"],
        "active_label": route["label"],
        "fallback": {k: v for k, v in load_llm_settings().items()
                     if k != "key"} | {"key_set": bool(
                         load_llm_settings().get("key"))},
    }


# ---------------- token 消耗统计 ----------------
# 数据源：vulnagent 会话目录的 events.sse 里逐条 model_usage 事件
# （{seq, ts, input_tokens, output_tokens}，每次 LLM 调用一条）。
# 挖掘会话在 sessions/，模拟会话在 emul-sessions/；聚合按 agent 与按日。

_usage_cache: dict = {"at": 0.0, "value": None}
USAGE_CACHE_SECONDS = 60.0


def _iter_usage_events(sse_path: Path):
    try:
        with sse_path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line.startswith("data: "):
                    continue
                body = line[6:].strip()
                if '"input_tokens"' not in body or '"output_tokens"' not in body:
                    continue
                try:
                    yield json.loads(body)
                except ValueError:
                    continue
    except OSError:
        return


def _count_usage() -> dict:
    root = _fwgraph_root().parent / "vulnagent"
    agents = {"mining": root / "sessions", "emul": root / "emul-sessions"}
    by_day: dict = {}
    by_agent = {k: {"calls": 0, "input_tokens": 0, "output_tokens": 0}
                for k in agents}
    top = []
    for agent, base in agents.items():
        if not base.is_dir():
            continue
        for sdir in base.iterdir():
            if not sdir.is_dir():
                continue
            sse = sdir / "events.sse"
            if not sse.is_file():
                continue
            calls = in_tot = out_tot = 0
            for ev in _iter_usage_events(sse):
                calls += 1
                in_tot += int(ev.get("input_tokens") or 0)
                out_tot += int(ev.get("output_tokens") or 0)
                day = str(ev.get("ts") or "")[:10]
                if day:
                    slot = by_day.setdefault(day, {"calls": 0,
                                                   "input_tokens": 0,
                                                   "output_tokens": 0})
                    slot["calls"] += 1
                    slot["input_tokens"] += int(ev.get("input_tokens") or 0)
                    slot["output_tokens"] += int(ev.get("output_tokens") or 0)
            if calls:
                agg = by_agent[agent]
                agg["calls"] += calls
                agg["input_tokens"] += in_tot
                agg["output_tokens"] += out_tot
                top.append({"session_id": sdir.name, "agent": agent,
                            "calls": calls, "input_tokens": in_tot,
                            "output_tokens": out_tot})
    top.sort(key=lambda r: r["input_tokens"] + r["output_tokens"], reverse=True)
    total_in = sum(a["input_tokens"] for a in by_agent.values())
    total_out = sum(a["output_tokens"] for a in by_agent.values())
    return {
        "total": {"calls": sum(a["calls"] for a in by_agent.values()),
                  "input_tokens": total_in, "output_tokens": total_out},
        "by_agent": by_agent,
        "by_day": dict(sorted(by_day.items())[-14:]),
        "top_sessions": top[:8],
    }


def usage_stats() -> dict:
    now = time.monotonic()
    if _usage_cache["value"] is not None and now - _usage_cache["at"] < USAGE_CACHE_SECONDS:
        return _usage_cache["value"]
    value = _count_usage()
    _usage_cache.update({"at": now, "value": value})
    return value


def setup(app, require_token) -> None:
    from fastapi import Body, Depends, HTTPException

    @app.get("/settings/llm")
    def get_llm(principal: dict = Depends(require_token)):
        if principal.get("role") != "admin":
            raise HTTPException(status_code=403, detail="仅管理员")
        return status()

    @app.get("/settings/token-usage")
    def get_token_usage(principal: dict = Depends(require_token)):
        if principal.get("role") != "admin":
            raise HTTPException(status_code=403, detail="仅管理员")
        return usage_stats()

    @app.put("/settings/llm")
    def put_llm(section: dict = Body(...),
                principal: dict = Depends(require_token)):
        if principal.get("role") != "admin":
            raise HTTPException(status_code=403, detail="仅管理员")
        saved = save_llm_settings(section)
        global _probe_cache
        with _lock:
            _probe_cache = {"at": 0.0, "ok": None}
        return {"saved": True,
                "fallback": {k: v for k, v in saved.items() if k != "key"}
                | {"key_set": bool(saved.get("key"))}}
