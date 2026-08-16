/**
 * llm.js — LLM client with two wire styles (LLM_API_STYLE):
 *
 *   anthropic  POST {baseUrl}/messages   (Anthropic Messages gateways)
 *   openai     POST {baseUrl}/chat/completions  (OpenAI-compatible gateways,
 *              e.g. opencode go for deepseek-v4-flash; Anthropic-format
 *              messages/tools are converted both ways so callers never
 *              notice)
 *
 * Output cap is per-model: deepseek-v4-flash is clamped at 4096 on some
 * gateways (and ignores thinking:disabled on hard prompts — observed
 * 2026-08-06), deepseek-v4-pro allows 8192. Model/temperature/max_tokens come
 * from .env (LLM_MODEL / LLM_TEMPERATURE / LLM_MAX_TOKENS) when set, else
 * from agent.json's model block (session.js resolves the priority).
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
  constructor({ baseUrl, apiKey, model, style = "anthropic", thinking = false, maxTokens = 4096, timeoutMs = 120000, temperature = 0.2 }) {
    if (!apiKey) throw new LLMError("LLM_API_KEY is empty");
    this.baseUrl = baseUrl;
    this.apiKey = apiKey;
    this.model = model;
    this.style = style;
    this.thinking = thinking;
    this.maxTokens = maxTokens;
    this.timeoutMs = timeoutMs;
    this.temperature = Number.isFinite(Number(temperature)) ? Number(temperature) : 0.2;
    this.usage = { requests: 0, errors: 0, input_tokens: 0, output_tokens: 0 };
  }

  /**
   * One Messages API call.
   * @param {object} p {system, messages, tools, maxTokens}
   * @returns the raw response JSON (content blocks may include thinking/text/tool_use)
   */
  async messages({ system, messages, tools, maxTokens }) {
    if (this.style === "openai") {
      return this._chatCompletions({ system, messages, tools, maxTokens });
    }
    const body = {
      model: this.model,
      max_tokens: maxTokens ?? this.maxTokens,
      temperature: this.temperature,
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

  // ------------------------------------------------------------------
  // OpenAI chat-completions style (opencode go and other OAI gateways).
  // Anthropic-format messages/tools in, Anthropic-shaped response out, so
  // session.js never notices the difference.
  // ------------------------------------------------------------------

  static _toOpenAI(messages) {
    const out = [];
    for (const m of messages) {
      const content = m.content;
      if (typeof content === "string") {
        out.push({ role: m.role, content });
        continue;
      }
      const blocks = Array.isArray(content) ? content : [];
      if (m.role === "assistant") {
        const text = blocks.filter((b) => b.type === "text" && b.text)
          .map((b) => b.text).join("\n");
        const toolCalls = blocks.filter((b) => b.type === "tool_use")
          .map((b) => ({
            id: b.id,
            type: "function",
            function: { name: b.name, arguments: JSON.stringify(b.input ?? {}) },
          }));
        out.push({
          role: "assistant",
          content: text || null,
          ...(toolCalls.length ? { tool_calls: toolCalls } : {}),
        });
        continue;
      }
      // user role: tool_result blocks become role:"tool" messages
      const toolResults = blocks.filter((b) => b.type === "tool_result");
      const texts = blocks.filter((b) => b.type === "text" && b.text);
      for (const tr of toolResults) {
        const body = Array.isArray(tr.content)
          ? tr.content.filter((b) => b.type === "text").map((b) => b.text).join("\n")
          : String(tr.content ?? "");
        out.push({ role: "tool", tool_call_id: tr.tool_use_id, content: body });
      }
      if (texts.length || !toolResults.length) {
        out.push({ role: "user", content: texts.map((b) => b.text).join("\n") });
      }
    }
    return out;
  }

  static _fromOpenAI(data) {
    const choice = data.choices?.[0] ?? {};
    const msg = choice.message ?? {};
    const content = [];
    if (msg.content) content.push({ type: "text", text: msg.content });
    for (const tc of msg.tool_calls ?? []) {
      let input = {};
      try { input = JSON.parse(tc.function?.arguments || "{}"); } catch { /* keep {} */ }
      content.push({
        type: "tool_use",
        id: tc.id,
        name: tc.function?.name,
        input,
      });
    }
    const finishMap = { stop: "end_turn", tool_calls: "tool_use", length: "max_tokens" };
    return {
      content,
      stop_reason: finishMap[choice.finish_reason] ?? choice.finish_reason ?? "end_turn",
      usage: {
        input_tokens: data.usage?.prompt_tokens ?? 0,
        output_tokens: data.usage?.completion_tokens ?? 0,
      },
    };
  }

  async _chatCompletions({ system, messages, tools, maxTokens }) {
    const body = {
      model: this.model,
      max_tokens: maxTokens ?? this.maxTokens,
      temperature: this.temperature,
      messages: [
        ...(system ? [{ role: "system", content: system }] : []),
        ...LLMClient._toOpenAI(messages),
      ],
      ...(tools?.length ? {
        tools: tools.map((t) => ({
          type: "function",
          function: { name: t.name, description: t.description, parameters: t.input_schema },
        })),
      } : {}),
    };
    const maxAttempts = 4;
    let lastErr = null;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
      try {
        const resp = await fetch(`${this.baseUrl}/chat/completions`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${this.apiKey}`,
          },
          body: JSON.stringify(body),
          signal: ctrl.signal,
        });
        const text = await resp.text();
        if (resp.ok) {
          const data = LLMClient._fromOpenAI(JSON.parse(text));
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
