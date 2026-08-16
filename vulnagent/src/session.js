/**
 * session.js — Session = Agent + Environment, one concrete execution.
 *
 * Stateful and persistent: every step appends to messages.json (atomic) and
 * events.sse, so a crashed/interrupted session can be resumed with
 * `node src/cli.js resume <session_id>`. Long-running by design (max turns
 * is a guardrail, not a design limit).
 */
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { LLMClient } from "./llm.js";
import { EventStream, truncate } from "./events.js";
import { TOOL_DEFS, DYNAMIC_ONLY_TOOLS, executeTool } from "./tools.js";

function atomicWrite(file, text) {
  const tmp = file + ".tmp";
  writeFileSync(tmp, text, "utf8");
  renameSync(tmp, file);
}

// The gateway ignores thinking:disabled on hard prompts, so a long thinking
// block can burn the whole 4096-token output cap before any tool_use is
// emitted (observed 2026-08-06, session s-msh8j3c9-3d5b). Instead of going
// idle, nudge the model to continue — bounded, to avoid an infinite loop.
const MAX_TOK_NUDGES = 2;
const TRUNC_NUDGE = "你的上一条输出达到 token 上限被截断，且没有产生任何工具调用。请收敛推理，立即给出下一步：工具调用，或不超过 200 字的结论。";
const RESUME_NUDGE = "会话从中断处恢复。请继续推进任务：工具调用，或不超过 200 字的结论。";

// P1 历史压缩：旧工具结果（单条上限 16KB）在消息历史里永久驻留，每轮全量
// 重发给 LLM，是上下文一次性吞吐的最大来源。超过阈值的旧 tool_result 替换
// 为首尾摘录占位（原文随时可用更精确的参数重查，图谱检索优先）。最近
// KEEP_RECENT 条消息保持原文，首轮任务（messages[0]）永不压缩。
const COMPACT_THRESHOLD = Number(process.env.VULNAGENT_COMPACT_THRESHOLD ?? 1200);
const COMPACT_KEEP_RECENT = Number(process.env.VULNAGENT_COMPACT_KEEP_RECENT ?? 6);
const COMPACT_MARK = "[已归档]";

export function compactHistory(messages, { threshold = COMPACT_THRESHOLD, keepRecent = COMPACT_KEEP_RECENT } = {}) {
  const toolNames = new Map();
  for (const m of messages) {
    if (m.role === "assistant" && Array.isArray(m.content)) {
      for (const b of m.content) {
        if (b && b.type === "tool_use") toolNames.set(b.id, b.name);
      }
    }
  }
  const keepFrom = messages.length - keepRecent;
  let compacted = 0;
  for (let i = 1; i < Math.max(1, keepFrom); i++) {
    const m = messages[i];
    if (m.role !== "user" || !Array.isArray(m.content)) continue;
    for (const block of m.content) {
      if (!block || block.type !== "tool_result") continue;
      const parts = Array.isArray(block.content) ? block.content : [];
      for (const part of parts) {
        if (!part || part.type !== "text" || typeof part.text !== "string") continue;
        if (part.text.length <= threshold || part.text.startsWith(COMPACT_MARK)) continue;
        const name = toolNames.get(block.tool_use_id) ?? "tool";
        const head = part.text.slice(0, 300);
        const tail = part.text.slice(-200);
        part.text = `${COMPACT_MARK} ${name} 结果原 ${part.text.length} 字符，首尾摘录如下；`
          + `需要原文请用更精确的参数重新查询（图谱检索/fw_get_function_source 均可重入）。\n`
          + `--- 头部 ---\n${head}\n…\n--- 尾部 ---\n${tail}`;
        compacted += 1;
      }
    }
  }
  return compacted;
}

export class Session {
  static create({ config, agent, environment, task, sessionId, quiet, mode }) {
    const id = sessionId ?? `s-${Date.now().toString(36)}-${randomBytes(2).toString("hex")}`;
    const dir = path.join(config.dirs.sessions, id);
    mkdirSync(dir, { recursive: true });
    const session = new Session({ config, agent, environment, id, dir, quiet });
    session.task = task;
    session.mode = mode || "dynamic";
    session.messages = [{ role: "user", content: task }];
    session.state = {
      session_id: id,
      agent_id: agent.id,
      environment_id: environment.id,
      task,
      status: "running",
      mode: session.mode,
      // server-side finding attribution + report association key off this
      job_id: config.fwgraph.defaultJobId ?? process.env.FWGRAPH_JOB_ID ?? "",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      turns: 0,
      usage: { requests: 0, input_tokens: 0, output_tokens: 0 },
      findings: [],
    };
    session.persist();
    session.events.emit("session_start", { session_id: id, agent_id: agent.id, task });
    return session;
  }

  static resume({ config, agent, environment, sessionId, quiet }) {
    const dir = path.join(config.dirs.sessions, sessionId);
    if (!existsSync(path.join(dir, "state.json"))) throw new Error(`no such session: ${sessionId}`);
    const session = new Session({ config, agent, environment, id: sessionId, dir, quiet });
    session.state = JSON.parse(readFileSync(path.join(dir, "state.json"), "utf8"));
    session.messages = JSON.parse(readFileSync(path.join(dir, "messages.json"), "utf8"));
    session.task = session.state.task;
    // restore mode so static-mode tool filtering survives a resume
    session.mode = session.state.mode ?? "dynamic";
    // backfill job_id for sessions written before the field existed
    session.state.job_id = session.state.job_id ?? config.fwgraph.defaultJobId ?? process.env.FWGRAPH_JOB_ID ?? "";
    // NOTE: do NOT reassign session.findings here — the constructor already
    // created the array and toolCtx.findings aliases it; reassigning would
    // silently drop this run's record_finding entries from state.json.
    session.events.emit("session_start", { session_id: sessionId, agent_id: agent.id, task: `(resume) ${session.task}` });
    return session;
  }

  constructor({ config, agent, environment, id, dir, quiet }) {
    this.config = config;
    this.agent = agent;
    this.environment = environment;
    this.id = id;
    this.dir = dir;
    this.events = new EventStream(path.join(dir, "events.sse"), { quiet });
    // agent.json's model block is the manifest-level default; env vars
    // (LLM_MODEL / LLM_TEMPERATURE / LLM_MAX_TOKENS) still take priority.
    const agentModel = agent?.model ?? {};
    this.llm = new LLMClient({
      ...config.llm,
      model: config.llm.sources?.model === "env" ? config.llm.model : (agentModel.name ?? config.llm.model),
      temperature: config.llm.sources?.temperature === "env" ? config.llm.temperature : (agentModel.temperature ?? config.llm.temperature),
      maxTokens: config.llm.sources?.maxTokens === "env" ? config.llm.maxTokens : (agentModel.max_tokens ?? config.llm.maxTokens),
    });
    this.findings = [];
    this.finished = false;
    this.finishSummary = "";
    this._maxTokNudges = 0;
    // Tool execution context handed to every tool. Tools mutate session
    // state through `session` (finish) and collect output via `findings`.
    this.toolCtx = { config, sessionId: id, findings: this.findings, session: this };
  }

  get enabledTools() {
    const wanted = new Set(this.agent.tools ?? TOOL_DEFS.map((t) => t.name));
    // 纯静态挖掘模式：动态类工具（fuzz/frida/trace）对 agent 不可见
    const mode = this.mode ?? this.state?.mode ?? "dynamic";
    return TOOL_DEFS.filter((t) => wanted.has(t.name)
      && (mode !== "static" || !DYNAMIC_ONLY_TOOLS.has(t.name)));
  }

  persist() {
    this.state.updated_at = new Date().toISOString();
    this.state.usage = { ...this.llm.usage };
    this.state.findings = this.state.findings ?? [];
    for (const f of this.findings) {
      if (!this.state.findings.includes(f.id)) this.state.findings.push(f.id);
    }
    if (this.finished) this.state.status = "done";
    atomicWrite(path.join(this.dir, "state.json"), JSON.stringify(this.state, null, 2));
    atomicWrite(path.join(this.dir, "messages.json"), JSON.stringify(this.messages, null, 2));
  }

  /** Run the agent loop until finish / end_turn / maxTurns. */
  async run({ maxTurns = 40 } = {}) {
    const system = this.agent.system_prompt;
    const tools = this.enabledTools;
    try {
      // Resuming an idled session leaves an assistant message on top; the
      // Messages API expects a user turn, so append a continuation nudge.
      const tailMsg = this.messages[this.messages.length - 1];
      if (tailMsg && tailMsg.role === "assistant") {
        this.messages.push({ role: "user", content: [{ type: "text", text: RESUME_NUDGE }] });
      }
      for (let turn = this.state.turns; turn < maxTurns; turn++) {
        this.state.turns = turn + 1;
        const compacted = compactHistory(this.messages);
        if (compacted) {
          this.events.emit("text", { text: `[harness] 历史压缩：归档 ${compacted} 条旧工具结果（保留首尾摘录，原文可重查）` });
          this.persist();
        }
        const resp = await this.llm.messages({ system, messages: this.messages, tools });
        const content = resp.content ?? [];
        this.messages.push({ role: "assistant", content });

        for (const block of content) {
          if (block.type === "thinking" && block.thinking) {
            this.events.emit("thinking", { text: truncate(block.thinking, 1200) });
          } else if (block.type === "text" && block.text) {
            this.events.emit("text", { text: block.text });
          }
        }
        this.events.emit("model_usage", {
          input_tokens: resp.usage?.input_tokens ?? 0,
          output_tokens: resp.usage?.output_tokens ?? 0,
          total_input: this.llm.usage.input_tokens,
          total_output: this.llm.usage.output_tokens,
        });

        const calls = content.filter((b) => b.type === "tool_use");
        if (!calls.length) {
          // Output hit the token cap without a single tool call (typically
          // an over-long thinking block). Nudge and continue instead of
          // going idle, up to MAX_TOK_NUDGES times in a row.
          if (resp.stop_reason === "max_tokens" && this._maxTokNudges < MAX_TOK_NUDGES) {
            this._maxTokNudges += 1;
            this.events.emit("text", { text: `[harness] 输出达 token 上限被截断且无工具调用，自动催促继续（${this._maxTokNudges}/${MAX_TOK_NUDGES}）` });
            this.messages.push({ role: "user", content: [{ type: "text", text: TRUNC_NUDGE }] });
            this.persist();
            continue;
          }
          this.state.status = "completed";
          this.state.note = "idle timeout";
          this.persist();
          this.events.emit("session_idle", { session_id: this.id, reason: `stop_reason=${resp.stop_reason ?? "end_turn"}, no tool calls` });
          break;
        }
        this._maxTokNudges = 0;

        const results = [];
        for (const call of calls) {
          this.events.emit("tool_call", { id: call.id, name: call.name, input: call.input });
          let text;
          let isError = false;
          try {
            text = await executeTool(this.toolCtx, call.name, call.input);
          } catch (err) {
            text = `TOOL_ERROR: ${err.message}`;
            isError = true;
            this.events.emit("error", { message: `${call.name}: ${err.message}` });
          }
          this.events.emit("tool_result", { id: call.id, name: call.name, is_error: isError, preview: truncate(text, 400) });
          results.push({
            type: "tool_result",
            tool_use_id: call.id,
            content: [{ type: "text", text }],
            ...(isError ? { is_error: true } : {}),
          });
        }
        this.messages.push({ role: "user", content: results });
        this.persist();

        if (this.finished) {
          this.events.emit("session_end", { session_id: this.id, summary: this.finishSummary });
          break;
        }
      }
      if (this.state.turns >= maxTurns && !this.finished) {
        this.events.emit("session_idle", { session_id: this.id, reason: `max turns (${maxTurns}) reached — resume to continue` });
      }
    } catch (err) {
      this.state.status = "error";
      this.persist();
      this.events.emit("error", { message: err.message });
      throw err;
    } finally {
      this.persist();
      this.writeReport();
      this.events.close();
    }
    return { sessionId: this.id, findings: this.findings.map((f) => f.id), state: this.state };
  }

  /**
   * Standard-format Chinese vulnerability report covering every finding this
   * session recorded (all runs). Per-finding sections follow the fixed
   * template: 漏洞类型/危害等级/影响组件/漏洞位置/可达性/漏洞描述/攻击路径/
   * 消毒与防护现状/漏洞证据/利用思路/修复建议.
   */
  writeReport() {
    const ids = this.state.findings ?? [];
    if (!ids.length) return;
    const SEV_LABEL = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "提示" };
    const findings = [];
    for (const fid of ids) {
      try {
        findings.push(JSON.parse(readFileSync(
          path.join(this.config.dirs.findings, `${fid}.json`), "utf8")));
      } catch { /* finding file missing — skip */ }
    }
    if (!findings.length) return;
    const sevRank = (s) => ["critical", "high", "medium", "low", "info"].indexOf(s);
    findings.sort((a, b) =>
      (sevRank(a.severity) - sevRank(b.severity)) || ((b.confidence ?? 0) - (a.confidence ?? 0)));
    const counts = {};
    for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;

    const lines = [
      "# 漏洞挖掘报告",
      "",
      "## 一、任务信息",
      "",
      `- 会话：${this.id}`,
      `- 任务：${this.task}`,
      `- 分析 Agent：${this.agent.id}（模型 ${this.llm.model}）`,
      `- 固件任务：${this.config.fwgraph.defaultJobId}`,
      `- 报告时间：${new Date().toISOString()}`,
      "",
      "## 二、发现统计",
      "",
      `- 共 ${findings.length} 个漏洞：` +
        Object.entries(counts).map(([sev, n]) => `${SEV_LABEL[sev] ?? sev} ${n} 个`).join("，"),
      "",
      "## 三、漏洞详情",
      "",
    ];
    findings.forEach((f, i) => {
      lines.push(`### 漏洞 ${i + 1}：${f.title}（${f.id}）`, "");
      lines.push(`- **漏洞类型**：${f.vuln_class}${f.cwe ? `（${f.cwe}）` : ""}`);
      lines.push(`- **危害等级**：${SEV_LABEL[f.severity] ?? f.severity}（置信度 ${f.confidence}）`);
      lines.push(`- **影响组件**：${f.binary_path ?? f.binary_md5}（md5: ${f.binary_md5}）`);
      lines.push(`- **漏洞位置**：${f.function_name ?? "?"} @ ${f.function_addr}`);
      lines.push(`- **可达性**：${f.reachability ?? "static-only"}`);
      lines.push(`- **漏洞描述**：${f.summary}`);
      if (f.source_summary || f.sink_function) {
        lines.push(`- **攻击路径**：${f.source_summary ?? "?"} → sink：${f.sink_function ?? "?"}`);
      }
      if (f.sanitization) lines.push(`- **消毒与防护现状**：${f.sanitization}`);
      lines.push("- **漏洞证据**：");
      for (const [j, e] of (f.evidence ?? []).entries()) lines.push(`  ${j + 1}. ${e}`);
      if (f.exploit_sketch) lines.push(`- **利用思路**：${f.exploit_sketch}`);
      if (f.remediation) lines.push(`- **修复建议**：${f.remediation}`);
      lines.push("");
    });
    writeFileSync(path.join(this.dir, "report.md"), lines.join("\n"), "utf8");
  }
}
