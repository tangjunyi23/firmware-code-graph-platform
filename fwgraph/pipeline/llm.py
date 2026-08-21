"""Minimal JSON chat client. Honors LLM_API_STYLE=openai|anthropic."""

from __future__ import annotations

import json
import os
import re

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential_jitter

_JSON_FENCE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


def enabled() -> bool:
    return bool(os.getenv("LLM_API_KEY", "").strip())


def _style() -> str:
    return os.getenv("LLM_API_STYLE", "openai").strip().lower()


def _endpoint() -> str:
    base = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    if _style() == "anthropic":
        if base.endswith("/messages"):
            return base
        return base + "/messages"
    if base.endswith("/chat/completions"):
        return base
    return base + "/chat/completions"


def _max_tokens(default: int) -> int:
    raw = os.getenv("LLM_MAX_TOKENS", "").strip()
    if not raw:
        return default
    try:
        return max(256, int(raw))
    except ValueError:
        return default


def parse_json(text: str):
    raw = (text or "").strip()
    if not raw:
        raise ValueError("empty LLM content")
    fence = _JSON_FENCE.search(raw)
    if fence:
        raw = fence.group(1).strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    start_obj, start_arr = raw.find("{"), raw.find("[")
    starts = [i for i in (start_obj, start_arr) if i >= 0]
    if not starts:
        raise ValueError("LLM content is not JSON")
    start = min(starts)
    try:
        return json.loads(raw[start:])
    except json.JSONDecodeError as exc:
        raise ValueError(f"LLM JSON parse failed: {exc}") from exc


def content_from_response(body: dict) -> str:
    """Extract assistant text from OpenAI or Anthropic response JSON."""
    if not isinstance(body, dict):
        return ""
    choices = body.get("choices") or []
    if choices:
        msg = (choices[0].get("message") or {})
        return str(msg.get("content") or msg.get("reasoning_content") or "")
    texts = []
    for block in body.get("content") or []:
        if not isinstance(block, dict):
            continue
        if block.get("type") in ("text", "output_text") and block.get("text"):
            texts.append(str(block["text"]))
    return "\n".join(texts)


@retry(stop=stop_after_attempt(3), wait=wait_exponential_jitter(1, 8),
       reraise=True)
def chat_json(system: str, user: str, *, timeout: float = 180.0,
              max_tokens: int | None = None):
    """Return parsed JSON (object or array) from a single chat turn."""
    key = os.getenv("LLM_API_KEY", "").strip()
    if not key:
        raise RuntimeError("LLM_API_KEY is not set")
    model = os.getenv("LLM_MODEL", "deepseek-v4-flash")
    tokens = max_tokens if max_tokens is not None else _max_tokens(16384)
    headers = {"Authorization": f"Bearer {key}",
               "Content-Type": "application/json"}
    if _style() == "anthropic":
        payload = {
            "model": model,
            "max_tokens": tokens,
            "temperature": 0.1,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        if os.getenv("LLM_THINKING", "0") != "1":
            payload["thinking"] = {"type": "disabled"}
        headers["x-api-key"] = key
        headers["anthropic-version"] = "2023-06-01"
    else:
        payload = {
            "model": model,
            "temperature": 0.1,
            "max_tokens": tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
    with httpx.Client(timeout=timeout) as client:
        resp = client.post(_endpoint(), json=payload, headers=headers)
        resp.raise_for_status()
        body = resp.json()
    return parse_json(content_from_response(body))
