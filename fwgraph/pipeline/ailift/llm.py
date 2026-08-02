"""Async DeepSeek client for semantic function tags.

One chat completion per function. Concurrency is capped by an
asyncio.Semaphore(LLM_MAX_CONCURRENCY); transient failures (429 / 5xx /
timeouts / connection errors) are retried with exponential backoff via
tenacity (max 4 attempts), then the error is reported per function — one bad
function never fails the batch.

The model returns a strict JSON object with libc_equiv/domain tags. Function
identity is never changed by this module.
We first send response_format={"type":"json_object"}; if the backend rejects
that parameter (HTTP 400 mentioning it) we transparently drop it for the rest
of the process and rely on prompt enforcement + regex extraction.

Token usage is accumulated and flushed to llm_usage.json so partial runs keep
their accounting.
"""

import asyncio
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

MAX_PSEUDOCODE_CHARS = 4000
MAX_LIST_ITEMS = 40
MAX_STRING_CHARS = 120
SYSTEM_TEMPLATE = """You are a firmware reverse-engineering expert. Classify one \
function without renaming it. The original function name is immutable.

Allowed domain labels (closed vocabulary): {domains}

Hard rules:
- Answer with ONLY a JSON object, no markdown, no commentary:
  {{"libc_equiv": <"canonical_libc_name" or null>, "domain": \
<"allowed_domain" or null>, "confidence": <float 0.0-1.0>, "reason": \
"<one short sentence>"}}
- libc question: is this function itself a known libc/POSIX/compiler built-in \
implementation (e.g. strcpy, memcpy, sprintf, socket, __divdi3)? If yes, set \
"libc_equiv" to its canonical lowercase name (no prefix, e.g. "strcpy"); \
if it is merely a wrapper around one or you are unsure, set "libc_equiv" \
to null.
- domain describes the function's product/security role and must be one value \
from the closed vocabulary, or null when the evidence is insufficient.
- Both labels may be null. Never invent a symbol name.
"""

USER_TEMPLATE = """Binary: {binary_path} ({arch})
Function: {name} at {addr}, size={size} bytes, {lines} decompiled lines
Attack-surface tags: {tags}

Calls (callees): {calls}
Called by (callers): {callers}
Referenced strings: {strings}

Pseudo-C:
```c
{pseudocode}
```

Classify this function with semantic tags. JSON only."""


class JsonModeUnsupported(Exception):
    """Backend rejected response_format; caller drops it and retries."""


def _now():
    return datetime.now(timezone.utc).isoformat()


def _clip_list(items, limit=MAX_LIST_ITEMS):
    items = list(items or [])
    if len(items) > limit:
        items = items[:limit] + [f"... (+{len(items) - limit} more)"]
    return items


def build_system_prompt(domains):
    return SYSTEM_TEMPLATE.format(
        domains=", ".join(sorted(domains)) if domains else "(none)")


def build_user_prompt(func, pseudocode, callers, *, binary_path="", arch=""):
    strings = [s[:MAX_STRING_CHARS] for s in _clip_list(func.get("strings", []))]
    return USER_TEMPLATE.format(
        binary_path=binary_path or "?",
        arch=arch or "?",
        name=func.get("name", ""),
        addr=func.get("addr", ""),
        size=func.get("size", 0),
        lines=func.get("lines", 0),
        tags=", ".join(func.get("tags", [])) or "(none)",
        calls=", ".join(_clip_list(func.get("calls", []))) or "(none)",
        callers=", ".join(_clip_list(callers)) or "(none)",
        strings=json.dumps(strings, ensure_ascii=False) if strings else "(none)",
        pseudocode=(pseudocode or "")[:MAX_PSEUDOCODE_CHARS] or "(unavailable)",
    )


_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)

# libc_equiv schema: canonical lowercase symbol (leading underscores allowed
# for compiler built-ins like __divdi3) or null. Anything else is dropped.
LIBC_EQUIV_RE = re.compile(r"^[a-z_][a-z0-9_]*$")


def parse_libc_equiv(value):
    """Normalize the optional libc_equiv field: schema-valid string or None."""
    if value is None:
        return None
    text = str(value).strip()
    if not LIBC_EQUIV_RE.match(text):
        return None
    return text


def parse_json_object(content):
    """Parse one semantic-tag response; null labels are valid."""
    if not content:
        raise ValueError("empty content")
    text = content.strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        match = _JSON_BLOCK_RE.search(text)
        if not match:
            raise ValueError(f"no JSON object in response: {text[:120]!r}")
        data = json.loads(match.group(0))
    if not isinstance(data, dict):
        raise ValueError("response is not a JSON object")
    raw_conf = data.get("confidence", data.get("score", 0.0))
    try:
        confidence = float(raw_conf)
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))
    reason = str(data.get("reason") or "")[:300]
    domain = data.get("domain")
    domain = str(domain).strip() if domain is not None else None
    if not domain:
        domain = None
    return {"domain": domain, "confidence": confidence, "reason": reason,
            "libc_equiv": parse_libc_equiv(data.get("libc_equiv"))}


def _is_retryable(exc):
    if isinstance(exc, (httpx.TimeoutException, httpx.TransportError)):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        return code == 429 or code >= 500
    return False


class LLMClient:
    def __init__(self, base_url, api_key, model, concurrency=16,
                 usage_path=None, timeout=120.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.concurrency = max(1, int(concurrency))
        self.usage_path = Path(usage_path) if usage_path else None
        self._json_mode = True  # until the backend proves otherwise
        self.usage = {"model": model, "requests": 0, "errors": 0,
                      "prompt_tokens": 0, "completion_tokens": 0,
                      "total_tokens": 0, "updated_at": None}
        if self.usage_path and self.usage_path.is_file():
            try:
                saved = json.loads(self.usage_path.read_text(encoding="utf-8"))
                for key in ("requests", "errors", "prompt_tokens",
                            "completion_tokens", "total_tokens"):
                    self.usage[key] = int(saved.get(key, 0))
            except (OSError, json.JSONDecodeError, ValueError):
                pass

    @classmethod
    def from_env(cls, usage_path=None):
        return cls(
            base_url=os.getenv("LLM_BASE_URL", "https://api.siliconflow.cn/v1"),
            api_key=os.getenv("LLM_API_KEY", ""),
            model=os.getenv("LLM_MODEL", "deepseek-ai/DeepSeek-V4-Flash"),
            concurrency=int(os.getenv("LLM_MAX_CONCURRENCY", "16")),
            usage_path=usage_path,
        )

    async def chat(self, system, user, sem=None):
        """One completion -> parsed semantic tags.
        Raises on failure after retries. `sem` bounds concurrency; callers
        running a batch should share one semaphore created inside their event
        loop."""
        if sem is None:
            sem = asyncio.Semaphore(self.concurrency)
        async with sem:
            messages = [{"role": "system", "content": system},
                        {"role": "user", "content": user}]
            payload = {"model": self.model, "messages": messages,
                       "temperature": 0.1, "max_tokens": 240}
            if self._json_mode:
                payload["response_format"] = {"type": "json_object"}
            try:
                data = await self._post(payload)
            except JsonModeUnsupported:
                self._json_mode = False
                payload.pop("response_format", None)
                data = await self._post(payload)
            self._track(data)
            content = data["choices"][0]["message"]["content"]
            return parse_json_object(content)

    @retry(stop=stop_after_attempt(4),
           wait=wait_exponential(multiplier=1, min=2, max=30),
           retry=retry_if_exception(_is_retryable),
           reraise=True)
    async def _post(self, payload):
        headers = {"Authorization": f"Bearer {self.api_key}",
                   "Content-Type": "application/json"}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(f"{self.base_url}/chat/completions",
                                     json=payload, headers=headers)
        if resp.status_code == 400 and "response_format" in resp.text:
            raise JsonModeUnsupported(resp.text[:200])
        resp.raise_for_status()
        return resp.json()

    def _track(self, data):
        usage = data.get("usage") or {}
        self.usage["requests"] += 1
        self.usage["prompt_tokens"] += int(usage.get("prompt_tokens", 0))
        self.usage["completion_tokens"] += int(usage.get("completion_tokens", 0))
        self.usage["total_tokens"] += int(usage.get("total_tokens", 0))
        self.usage["updated_at"] = _now()

    def flush(self):
        if not self.usage_path:
            return
        self.usage_path.parent.mkdir(parents=True, exist_ok=True)
        self.usage_path.write_text(json.dumps(self.usage, indent=2),
                                   encoding="utf-8")


async def _gather(client, items):
    # created here, inside the batch's event loop: an asyncio.Semaphore is
    # bound to the loop that first blocks on it, so it must never be shared
    # across asyncio.run() calls
    sem = asyncio.Semaphore(client.concurrency)

    async def one(item):
        try:
            result = await client.chat(item["system"], item["user"], sem)
            return (item, result, None)
        except Exception as exc:  # noqa: BLE001 - per-function isolation
            return (item, None, f"{type(exc).__name__}: {exc}")
    return await asyncio.gather(*(one(item) for item in items))


def suggest_batch(client, items):
    """Synchronous facade: run all items concurrently, return
    [(item, result|None, error|None)] in input order."""
    if not items:
        return []
    results = asyncio.run(_gather(client, items))
    client.usage["errors"] += sum(1 for _, r, _ in results if r is None)
    client.flush()
    return results
