/**
 * config.js — load .env + agent/environment manifests.
 *
 * Managed Agents mapping:
 *   agent.json       -> Agent (model + system prompt + tools + skills)
 *   environment.json -> Environment (runtime, network policy, mounts)
 *   .env             -> Environment secrets (never committed)
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export function loadEnvFile(envPath = path.join(ROOT, ".env")) {
  const out = {};
  let text = "";
  try {
    text = readFileSync(envPath, "utf8");
  } catch {
    return out;
  }
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!m || line.trim().startsWith("#")) continue;
    out[m[1]] = m[2];
  }
  return out;
}

export function loadConfig() {
  const fileEnv = loadEnvFile();
  const env = (key, fallback = "") => process.env[key] ?? fileEnv[key] ?? fallback;
  // Track whether a value came from the environment/.env (priority) or the
  // built-in default, so agent.json's model block only fills the gaps (L1).
  const src = (key) => (process.env[key] ?? fileEnv[key]) !== undefined ? "env" : "default";
  return {
    fwgraph: {
      baseUrl: env("FWGRAPH_BASE_URL", "http://127.0.0.1:8000").replace(/\/+$/, ""),
      token: env("FWGRAPH_TOKEN"),
      defaultJobId: env("FWGRAPH_JOB_ID"),
      // root of the firmware extraction trees (<root>/<job_id>/); the dsh
      // fw_browse_firmware tool is jailed inside it
      extractedRoot: env("FWGRAPH_EXTRACTED_ROOT") || path.resolve(ROOT, "../fwgraph/data/extracted"),
    },
    llm: {
      baseUrl: env("LLM_BASE_URL", "http://127.0.0.1:3456/v1").replace(/\/+$/, ""),
      apiKey: env("LLM_API_KEY"),
      model: env("LLM_MODEL", "deepseek-v4-flash"),
      temperature: env("LLM_TEMPERATURE") ? Number(env("LLM_TEMPERATURE")) : undefined,
      // anthropic (default, /messages) | openai (/chat/completions, e.g.
      // opencode go gateway for deepseek-v4-flash)
      style: env("LLM_API_STYLE", "anthropic"),
      thinking: env("LLM_THINKING", "0") === "1",
      maxTokens: Number(env("LLM_MAX_TOKENS", "4096")),
      timeoutMs: Number(env("LLM_TIMEOUT_MS", "120000")),
      sources: {
        model: src("LLM_MODEL"),
        temperature: src("LLM_TEMPERATURE"),
        maxTokens: src("LLM_MAX_TOKENS"),
      },
    },
    dirs: {
      sessions: path.join(ROOT, "sessions"),
      findings: path.join(ROOT, "findings"),
    },
  };
}

export function loadManifest(name) {
  const p = path.join(ROOT, name);
  return JSON.parse(readFileSync(p, "utf8"));
}
