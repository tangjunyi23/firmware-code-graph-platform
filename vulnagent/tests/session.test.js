/**
 * session.js 单测（离线）：
 *  - H3: state.json 带 job_id（create 写入 / resume 回填）
 *  - L2: idle break 后 status=completed + note="idle timeout"（原来永远 running）
 *  - L1: agent.json model 块生效，.env 仍优先
 *  - 静态模式 enabledTools 过滤动态工具
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { Session } from "../src/session.js";

function makeConfig() {
  const root = mkdtempSync(path.join(tmpdir(), "va-sess-"));
  return {
    fwgraph: { baseUrl: "http://fw.test", token: "tok", defaultJobId: "job123" },
    llm: {
      baseUrl: "http://llm.test/v1", apiKey: "k", model: "env-model",
      style: "anthropic", thinking: false, maxTokens: 4096, timeoutMs: 1000,
      sources: { model: "env", temperature: "default", maxTokens: "default" },
    },
    dirs: { sessions: path.join(root, "sessions"), findings: path.join(root, "findings") },
  };
}

const AGENT = {
  id: "agent-x",
  model: { name: "manifest-model", temperature: 0.7, max_tokens: 2048 },
  tools: [],
  system_prompt: "sys",
};
const ENV = { id: "env-x" };

test("Session.create writes job_id into state.json (H3)", () => {
  const config = makeConfig();
  const s = Session.create({ config, agent: AGENT, environment: ENV, task: "t", quiet: true, mode: "static" });
  const state = JSON.parse(readFileSync(path.join(s.dir, "state.json"), "utf8"));
  assert.equal(state.job_id, "job123");
  assert.equal(state.mode, "static");
  s.events.close();
});

test("agent.json model block is honored when env did not set it (L1); env wins otherwise", () => {
  // temperature/maxTokens 来自 default → agent.json 生效
  let config = makeConfig();
  let s = Session.create({ config, agent: AGENT, environment: ENV, task: "t", quiet: true });
  assert.equal(s.llm.model, "env-model");          // model 来源 env，优先
  assert.equal(s.llm.temperature, 0.7);            // 来自 agent.json
  assert.equal(s.llm.maxTokens, 2048);             // 来自 agent.json
  s.events.close();

  // model 无 env 来源 → 用 agent.json 的 name
  config = makeConfig();
  config.llm.sources.model = "default";
  s = Session.create({ config, agent: AGENT, environment: ENV, task: "t", quiet: true });
  assert.equal(s.llm.model, "manifest-model");
  s.events.close();
});

test("idle break marks state completed with note (L2)", async () => {
  const config = makeConfig();
  const s = Session.create({ config, agent: AGENT, environment: ENV, task: "t", quiet: true });
  // stub LLM：直接 end_turn、无工具调用 → 立即 idle
  s.llm = {
    usage: { requests: 0, input_tokens: 0, output_tokens: 0 },
    messages: async () => ({
      content: [{ type: "text", text: "没有更多可做的" }],
      stop_reason: "end_turn",
      usage: { input_tokens: 1, output_tokens: 1 },
    }),
  };
  const result = await s.run({ maxTurns: 5 });
  assert.equal(result.state.status, "completed");
  assert.equal(result.state.note, "idle timeout");
  const state = JSON.parse(readFileSync(path.join(s.dir, "state.json"), "utf8"));
  assert.equal(state.status, "completed");
});

test("static mode strips dynamic tools from the advertised list", () => {
  const config = makeConfig();
  const s = Session.create({
    config,
    agent: { ...AGENT, tools: ["fw_search", "fw_request_trace", "record_finding"] },
    environment: ENV, task: "t", quiet: true, mode: "static",
  });
  const names = s.enabledTools.map((t) => t.name);
  assert.deepEqual(names.sort(), ["fw_search", "record_finding"].sort());
  s.events.close();
});
