/**
 * llm.js — Anthropic Messages client (gateway-compatible).
 *
 * The gateway (routatic-proxy on host:3456) supports native tool_use.
 * Output cap is per-model in the proxy config: deepseek-v4-flash is
 * clamped at 4096 (and ignores thinking:disabled on hard prompts —
 * observed 2026-08-06), deepseek-v4-pro allows 8192. Model/max_tokens
 * come from .env (LLM_MODEL / LLM_MAX_TOKENS).
 * Retries 429/5xx/network errors with exponential backoff.
 */
export class LLMError extends Error {
  constructor(message, { status, body } = {}) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class LLMClient {
  constructor({ baseUrl, apiKey, model, thinking = false, maxTokens = 4096, timeoutMs = 120000 }) {
    if (!apiKey) throw new LLMError("LLM_API_KEY is empty");
    this.baseUrl = baseUrl;
    this.apiKey = apiKey;
    this.model = model;
    this.thinking = thinking;
    this.maxTokens = maxTokens;
    this.timeoutMs = timeoutMs;
    this.usage = { requests: 0, errors: 0, input_tokens: 0, output_tokens: 0 };
  }

  /**
   * One Messages API call.
   * @param {object} p {system, messages, tools, maxTokens}
   * @returns the raw response JSON (content blocks may include thinking/text/tool_use)
   */
  async messages({ system, messages, tools, maxTokens }) {
    const body = {
      model: this.model,
      max_tokens: maxTokens ?? this.maxTokens,
      temperature: 0.2,
      messages,
      ...(system ? { system } : {}),
      ...(tools?.length ? { tools } : {}),
    };
    if (!this.thinking) body.thinking = { type: "disabled" };

    const maxAttempts = 4;
    let lastErr = null;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
      try {
        const resp = await fetch(`${this.baseUrl}/messages`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-api-key": this.apiKey,
            Authorization: `Bearer ${this.apiKey}`,
            "anthropic-version": "2023-06-01",
          },
          body: JSON.stringify(body),
          signal: ctrl.signal,
        });
        const text = await resp.text();
        if (resp.ok) {
          const data = JSON.parse(text);
          this._track(data);
          return data;
        }
        const retryable = resp.status === 429 || resp.status >= 500;
        lastErr = new LLMError(`LLM HTTP ${resp.status}: ${text.slice(0, 300)}`, {
          status: resp.status,
          body: text.slice(0, 1000),
        });
        if (!retryable) {
          this.usage.errors += 1;
          throw lastErr;
        }
      } catch (err) {
        if (err instanceof LLMError) throw err;
        lastErr = new LLMError(`LLM request failed: ${err.message}`);
      } finally {
        clearTimeout(timer);
      }
      if (attempt < maxAttempts) await sleep(1000 * 2 ** attempt);
    }
    this.usage.errors += 1;
    throw lastErr ?? new LLMError("LLM request failed");
  }

  _track(data) {
    const u = data.usage ?? {};
    this.usage.requests += 1;
    this.usage.input_tokens += Number(u.input_tokens ?? 0);
    this.usage.output_tokens += Number(u.output_tokens ?? 0);
  }
}
