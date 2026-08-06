/**
 * tools.js — the agent's toolbelt.
 *
 * Managed Agents mapping: Agent.tools. Most tools are thin read-only wrappers
 * over the downstream fwgraph platform (attack-surface identification +
 * function retrieval/decompilation). Two tools are the agent's own output
 * channel: record_finding (structured vuln record) and finish (end session).
 *
 * All fwgraph calls are GETs or the read-only /graph/query proxy, with one
 * controlled exception: fw_request_trace starts a coverage trace
 * (POST /jobs/{id}/trace) so the agent can confirm routes, upgrade
 * reachability, or observe crashes — bounded per session, see
 * MAX_TRACES_PER_SESSION. The agent never mutates analysis artifacts.
 */
import { mkdirSync, writeFileSync, appendFileSync, readdirSync, readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import path from "node:path";
import { truncate } from "./events.js";

const MAX_RESULT_CHARS = 16000;
const MAX_TRACES_PER_SESSION = 5;

// ---------------------------------------------------------------------------
// fwgraph HTTP helper
// ---------------------------------------------------------------------------

async function fw(ctx, method, urlPath, body) {
  const { baseUrl, token } = ctx.config.fwgraph;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 60000);
  try {
    const resp = await fetch(`${baseUrl}${urlPath}`, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: ctrl.signal,
    });
    const text = await resp.text();
    if (!resp.ok) {
      throw new Error(`fwgraph ${method} ${urlPath} -> HTTP ${resp.status}: ${text.slice(0, 300)}`);
    }
    const ct = resp.headers.get("content-type") ?? "";
    return ct.includes("application/json") ? JSON.parse(text) : text;
  } finally {
    clearTimeout(timer);
  }
}

function graphQuery(ctx, jobId, op, args = {}) {
  return fw(ctx, "POST", "/graph/query", { job_id: jobId, op, ...args });
}

function jobOf(ctx, input) {
  const jobId = input.job_id || ctx.config.fwgraph.defaultJobId;
  if (!jobId) throw new Error("job_id missing and no FWGRAPH_JOB_ID default configured");
  return jobId;
}

// ---------------------------------------------------------------------------
// Tool executors
// ---------------------------------------------------------------------------

const executors = {
  async fw_list_jobs(ctx) {
    return fw(ctx, "GET", "/jobs");
  },

  async fw_get_manifest(ctx, input) {
    const jobId = jobOf(ctx, input);
    const manifest = await fw(ctx, "GET", `/jobs/${jobId}/manifest`);
    // Slim the manifest: the agent needs binary identity + hardening, not
    // every extracted file path.
    let binaries = (manifest.binaries ?? []).map((b) => ({
      md5: b.md5,
      path: b.path,
      arch: b.arch,
      bits: b.bits,
      checksec: b.checksec,
    }));
    // With 274+ binaries the full list hits the result truncation cap and can
    // cut off the very entry the agent needs — always filter to the target
    // binary when its md5 is known.
    if (input.binary_md5) {
      binaries = binaries.filter((b) => b.md5 === input.binary_md5);
    }
    return { job_id: jobId, binary_count: binaries.length, binaries };
  },

  async fw_list_functions(ctx, input) {
    const jobId = jobOf(ctx, input);
    const data = await fw(ctx, "GET", `/jobs/${jobId}/functions`);
    let fns = data.functions ?? [];
    if (input.binary_md5) fns = fns.filter((f) => f.binary === input.binary_md5);
    if (input.tag) fns = fns.filter((f) => (f.tags ?? []).includes(input.tag));
    if (input.on_attack_path) fns = fns.filter((f) => f.on_attack_path);
    if (input.observed_in_trace) fns = fns.filter((f) => f.observed_in_trace);
    if (input.verified_reachable) fns = fns.filter((f) => f.verified_reachable);
    if (input.name_pattern) {
      const re = new RegExp(input.name_pattern, "i");
      fns = fns.filter((f) => re.test(f.name ?? "") || re.test(f.ai_name ?? ""));
    }
    const limit = Math.min(Number(input.limit ?? 100), 500);
    const total = fns.length;
    fns = fns.slice(0, limit);
    return { total_matched: total, returned: fns.length, binaries: data.binaries, functions: fns };
  },

  async fw_get_function_source(ctx, input) {
    const jobId = jobOf(ctx, input);
    if (!input.md5 || !input.addr) throw new Error("md5 and addr are required");
    if (input.asm) {
      // Function-level assembly: the ground truth for recovering call-site
      // arguments (MIPS o32: $a0-$a3 then stack) when Hex-Rays collapses them.
      const src = await fw(ctx, "GET", `/jobs/${jobId}/functions/${input.md5}/${input.addr}/source?asm=1`);
      return { addr: input.addr, md5: input.md5, source_kind: "asm", source: src };
    }
    const wantAi = input.ai !== false;
    if (wantAi) {
      try {
        const src = await fw(ctx, "GET", `/jobs/${jobId}/functions/${input.md5}/${input.addr}/source?ai=1`);
        return { addr: input.addr, md5: input.md5, source_kind: "ai_overlay", source: src };
      } catch (err) {
        if (!/HTTP 404/.test(err.message)) throw err;
      }
    }
    const src = await fw(ctx, "GET", `/jobs/${jobId}/functions/${input.md5}/${input.addr}/source`);
    return { addr: input.addr, md5: input.md5, source_kind: "hexrays", source: src };
  },

  async fw_attack_surface(ctx, input) {
    return graphQuery(ctx, jobOf(ctx, input), "attack_surface", {
      ...(input.source ? { source: input.source } : {}),
      ...(input.sink ? { sink: input.sink } : {}),
      verified_only: Boolean(input.verified_only),
      limit: Math.min(Number(input.limit ?? 20), 50),
    });
  },

  async fw_search(ctx, input) {
    if (!input.pattern) throw new Error("pattern is required");
    return graphQuery(ctx, jobOf(ctx, input), "search", {
      pattern: input.pattern,
      ...(input.label ? { label: input.label } : {}),
      ...(input.limit ? { limit: Number(input.limit) } : {}),
    });
  },

  async fw_call_trace(ctx, input) {
    if (!input.name) throw new Error("name is required");
    return graphQuery(ctx, jobOf(ctx, input), "trace", {
      name: input.name,
      direction: input.direction ?? "both",
    });
  },

  async fw_snippet(ctx, input) {
    if (!input.name) throw new Error("name is required");
    return graphQuery(ctx, jobOf(ctx, input), "snippet", { name: input.name });
  },

  async fw_dangerous_callsites(ctx, input) {
    return graphQuery(ctx, jobOf(ctx, input), "dangerous", {
      ...(input.functions?.length ? { functions: input.functions } : {}),
      limit: Math.min(Number(input.limit ?? 50), 200),
    });
  },

  async fw_trace_flow(ctx, input) {
    if (!input.trace_id) throw new Error("trace_id is required");
    return graphQuery(ctx, jobOf(ctx, input), "trace_flow", { trace_id: input.trace_id });
  },

  async fw_list_traces(ctx, input) {
    return fw(ctx, "GET", `/jobs/${jobOf(ctx, input)}/traces`);
  },

  async fw_routes(ctx, input) {
    return graphQuery(ctx, jobOf(ctx, input), "routes", {
      ...(input.pattern ? { pattern: input.pattern } : {}),
      ...(input.method ? { method: input.method } : {}),
      ...(input.binary_md5 ? { binary_md5: input.binary_md5 } : {}),
      limit: Math.min(Number(input.limit ?? 50), 200),
    });
  },

  async fw_cypher(ctx, input) {
    if (!input.query) throw new Error("query is required");
    return graphQuery(ctx, jobOf(ctx, input), "cypher", { query: input.query });
  },

  async fw_get_trace(ctx, input) {
    if (!input.trace_id || !/^[0-9a-f]{12}$/.test(input.trace_id)) {
      throw new Error("trace_id must be 12 lowercase hex chars");
    }
    const t = await fw(ctx, "GET", `/jobs/${jobOf(ctx, input)}/traces/${input.trace_id}`);
    // Slim view: the raw baseline/trigger function dumps always blow the
    // result size cap; the agent needs status, trigger_result, counts and
    // the diff (trigger-only) function identities for reachability upgrades.
    return {
      trace_id: t.trace_id, status: t.status, error: t.error,
      created_at: t.created_at, elapsed_seconds: t.elapsed_seconds,
      binary: t.binary, argv: t.argv, request: t.request,
      trigger_result: t.trigger?.trigger_result ?? null,
      baseline_tb: t.baseline?.tb_count ?? null,
      trigger_tb: t.trigger?.tb_count ?? null,
      baseline_functions: t.baseline?.functions ?? null,
      trigger_functions: t.trigger?.functions ?? null,
      diff_function_count: t.diff?.function_count ?? 0,
      diff_functions: (t.diff?.functions ?? []).map((f) => ({
        addr: f.addr, name: f.ai_name ?? f.name, libc_equiv: f.libc_equiv ?? null,
      })),
    };
  },

  async fw_request_trace(ctx, input) {
    const jobId = jobOf(ctx, input);
    if (!/^[0-9a-f]{32}$/.test(input.binary_md5 ?? "")) {
      throw new Error("binary_md5 must be a 32-char lowercase md5");
    }
    if (!Array.isArray(input.argv) || !input.argv.length
        || input.argv.some((a) => typeof a !== "string" && typeof a !== "number")) {
      throw new Error("argv must be a non-empty array of strings");
    }
    if (input.port !== undefined
        && (!Number.isInteger(input.port) || input.port < 1 || input.port > 65535)) {
      throw new Error("port must be an integer in 1..65535");
    }
    if (input.request_path !== undefined
        && (typeof input.request_path !== "string" || !input.request_path.startsWith("/"))) {
      throw new Error('request_path must start with "/" (a single GET is sent)');
    }
    if ((ctx.traceCount ?? 0) >= MAX_TRACES_PER_SESSION) {
      throw new Error(`trace budget exhausted (${MAX_TRACES_PER_SESSION} per session); mine existing traces instead`);
    }
    const resp = await fw(ctx, "POST", `/jobs/${jobId}/trace`, {
      binary_md5: input.binary_md5,
      argv: input.argv,
      ...(input.port !== undefined ? { port: input.port } : {}),
      ...(input.request_path !== undefined ? { request_path: input.request_path } : {}),
      ...(input.argv0 !== undefined ? { argv0: String(input.argv0) } : {}),
    });
    ctx.traceCount = (ctx.traceCount ?? 0) + 1;
    return resp;
  },

  async record_finding(ctx, input) {
    const required = ["title", "severity", "vuln_class", "binary_md5", "function_addr", "summary", "evidence", "confidence", "reachability"];
    const missing = required.filter((k) => input[k] === undefined || input[k] === null || input[k] === "");
    if (missing.length) throw new Error(`record_finding missing required fields: ${missing.join(", ")}`);
    if (!["critical", "high", "medium", "low", "info"].includes(input.severity)) {
      throw new Error(`bad severity: ${JSON.stringify(input.severity)}`);
    }
    if (!["static-only", "observed", "verified"].includes(input.reachability)) {
      throw new Error(`bad reachability: ${JSON.stringify(input.reachability)} (must be static-only|observed|verified)`);
    }
    const conf = Number(input.confidence);
    if (!Number.isFinite(conf) || conf < 0 || conf > 1) {
      throw new Error(`bad confidence: ${JSON.stringify(input.confidence)} (must be a number in 0..1)`);
    }
    if (input.cwe !== undefined && !/^CWE-\d+$/.test(input.cwe)) {
      throw new Error(`bad cwe: ${JSON.stringify(input.cwe)} (expected e.g. CWE-121)`);
    }
    if (!Array.isArray(input.evidence) || !input.evidence.length
        || input.evidence.some((e) => typeof e !== "string" || !e.trim())) {
      throw new Error("evidence must be a non-empty array of non-empty strings");
    }
    // Dedup link: one (binary, function, vuln_class) should have one canonical
    // record; a later review must reference the earlier finding explicitly.
    const norm = (v) => String(v ?? "").toLowerCase();
    const related = [];
    try {
      for (const f of readdirSync(ctx.config.dirs.findings)) {
        if (!/^F-.*\.json$/.test(f)) continue;
        try {
          const old = JSON.parse(readFileSync(path.join(ctx.config.dirs.findings, f), "utf8"));
          if (norm(old.binary_md5) === norm(input.binary_md5)
              && norm(old.function_addr) === norm(input.function_addr)
              && norm(old.vuln_class) === norm(input.vuln_class)) {
            related.push(old.id);
          }
        } catch { /* skip unreadable finding file */ }
      }
    } catch { /* findings dir does not exist yet */ }
    const finding = {
      id: `F-${Date.now().toString(36)}-${randomBytes(2).toString("hex")}`,
      recorded_at: new Date().toISOString(),
      session_id: ctx.sessionId,
      job_id: jobOf(ctx, input),
      ...input,
    };
    if (related.length) finding.related_findings = related;
    delete finding.job_id_input;
    mkdirSync(ctx.config.dirs.findings, { recursive: true });
    const file = path.join(ctx.config.dirs.findings, `${finding.id}.json`);
    writeFileSync(file, JSON.stringify(finding, null, 2), "utf8");
    appendFileSync(path.join(ctx.config.dirs.findings, "index.jsonl"), JSON.stringify(finding) + "\n", "utf8");
    ctx.findings.push(finding);
    return {
      recorded: true, finding_id: finding.id, file,
      ...(related.length ? {
        related_findings: related,
        note: "existing finding(s) for the same function+vuln_class; record only when this adds new evidence, and set supersedes when it replaces an earlier one",
      } : {}),
    };
  },

  async finish(ctx, input) {
    ctx.session.finished = true;
    ctx.session.finishSummary = input.summary ?? "";
    return { finished: true, summary: ctx.session.finishSummary };
  },
};

// ---------------------------------------------------------------------------
// Tool schemas (Anthropic tool format)
// ---------------------------------------------------------------------------

const JOB_ID_PROP = { job_id: { type: "string", description: "Firmware job id; omit to use the configured default job" } };

export const TOOL_DEFS = [
  {
    name: "fw_list_jobs",
    description: "List firmware analysis jobs on the fwgraph platform (id, firmware, status).",
    input_schema: { type: "object", properties: {} },
  },
  {
    name: "fw_get_manifest",
    description: "Get the job's binary manifest: every ELF with arch/bits and its checksec hardening profile (canary/NX/PIE/RELRO/FORTIFY). Zero-hardening binaries make memory-corruption findings more severe. Pass binary_md5 to fetch just one binary — the full list can exceed the result size cap and cut off the entry you need.",
    input_schema: {
      type: "object",
      properties: {
        ...JOB_ID_PROP,
        binary_md5: { type: "string", description: "Filter to a single binary by its md5" },
      },
    },
  },
  {
    name: "fw_list_functions",
    description: "List decompiled functions with attack-surface metadata (tags, asrc/asink, on_attack_path, observed_in_trace, verified_reachable, libc_equiv, domain). Use filters to narrow.",
    input_schema: {
      type: "object",
      properties: {
        ...JOB_ID_PROP,
        binary_md5: { type: "string" },
        tag: { type: "string", description: "e.g. network_facing, auth_related, calls_dangerous, entrypoint" },
        on_attack_path: { type: "boolean" },
        observed_in_trace: { type: "boolean" },
        verified_reachable: { type: "boolean" },
        name_pattern: { type: "string", description: "Regex over name/ai_name" },
        limit: { type: "integer", description: "Max rows (default 100, cap 500)" },
      },
    },
  },
  {
    name: "fw_get_function_source",
    description: "Retrieve decompiled pseudo-C of one function by md5+addr. Returns the AI-enriched overlay (recovered call args, readable names) when available, else raw Hex-Rays. This is THE primary evidence for vulnerability reasoning. When Hex-Rays collapses call-site arguments (e.g. `strcat();`), set asm=true to get the function-level assembly and recover $a0-$a3/stack arguments yourself.",
    input_schema: {
      type: "object",
      properties: {
        ...JOB_ID_PROP,
        md5: { type: "string", description: "Binary md5" },
        addr: { type: "string", description: "Function address, e.g. 0x43785c" },
        ai: { type: "boolean", description: "Prefer AI overlay (default true), auto-fallback to Hex-Rays" },
        asm: { type: "boolean", description: "Return function-level assembly instead of pseudo-C (for call-site argument recovery)" },
      },
      required: ["md5", "addr"],
    },
  },
  {
    name: "fw_attack_surface",
    description: "Ranked source->sink attack paths (score, functions, observed/verified cross-validation). Start vulnerability mining here: verified_only=true for runtime-confirmed chains, then the top-scored unverified ones.",
    input_schema: {
      type: "object",
      properties: {
        ...JOB_ID_PROP,
        source: { type: "string", description: "Filter by source function addr" },
        sink: { type: "string", description: "Filter by sink function addr" },
        verified_only: { type: "boolean" },
        limit: { type: "integer", description: "Max paths (default 20, cap 50)" },
      },
    },
  },
  {
    name: "fw_search",
    description: "Search graph nodes by name pattern (regex).",
    input_schema: {
      type: "object",
      properties: {
        ...JOB_ID_PROP,
        pattern: { type: "string" },
        label: { type: "string", description: "Node label, e.g. Function" },
        limit: { type: "integer" },
      },
      required: ["pattern"],
    },
  },
  {
    name: "fw_call_trace",
    description: "Call-graph neighborhood of a function: inbound callers / outbound callees. Use to walk from a sink back to its network-facing entry.",
    input_schema: {
      type: "object",
      properties: {
        ...JOB_ID_PROP,
        name: { type: "string", description: "Function name" },
        direction: { type: "string", enum: ["both", "inbound", "outbound"] },
      },
      required: ["name"],
    },
  },
  {
    name: "fw_snippet",
    description: "Get source snippet of a function by NAME (resolves qualified name via the graph). Prefer fw_get_function_source when you know md5+addr.",
    input_schema: {
      type: "object",
      properties: { ...JOB_ID_PROP, name: { type: "string" } },
      required: ["name"],
    },
  },
  {
    name: "fw_dangerous_callsites",
    description: "Find all callers of dangerous libc functions (strcpy/sprintf/system/popen/...), matching by name AND libc_equiv so statically-linked stripped binaries are covered. Good for widening a confirmed pattern.",
    input_schema: {
      type: "object",
      properties: {
        ...JOB_ID_PROP,
        functions: { type: "array", items: { type: "string" }, description: "Dangerous names; defaults to the standard list" },
        limit: { type: "integer", description: "Default 50, cap 200" },
      },
    },
  },
  {
    name: "fw_trace_flow",
    description: "Ordered request-handling path of one qemu-user coverage trace, with dangerous libc_equiv highlights. This is the runtime evidence behind observed/verified marks.",
    input_schema: {
      type: "object",
      properties: { ...JOB_ID_PROP, trace_id: { type: "string" } },
      required: ["trace_id"],
    },
  },
  {
    name: "fw_list_traces",
    description: "List coverage traces of the job (trace_id, status, baseline/trigger TB counts, diff functions).",
    input_schema: { type: "object", properties: { ...JOB_ID_PROP } },
  },
  {
    name: "fw_get_trace",
    description: "Slimmed view of one coverage trace: status, trigger_result (HTTP status/bytes/transport error), TB/function counts, and the diff (trigger-only) function identities. Use after fw_request_trace to read the outcome.",
    input_schema: {
      type: "object",
      properties: { ...JOB_ID_PROP, trace_id: { type: "string", description: "12 hex chars" } },
      required: ["trace_id"],
    },
  },
  {
    name: "fw_request_trace",
    description: "Start ONE controlled qemu-user coverage trace (baseline/trigger diff): boots the target binary in its chroot and sends one GET to request_path. Write operation, budget-limited per session — use it to (a) confirm which route reaches a handler (function appears in diff => upgrade reachability to observed), (b) probe a suspected bug (crash => trace failed / service gone is a dynamic signal worth recording). Poll with fw_list_traces/fw_get_trace; takes ~1 min; HTTP 409 means another trace is running, retry later.",
    input_schema: {
      type: "object",
      properties: {
        ...JOB_ID_PROP,
        binary_md5: { type: "string", description: "Target binary (must be decompiled in this job)" },
        argv: { type: "array", items: { type: "string" }, description: "Guest argv, e.g. [\"-c\",\"/tmp/sysapihttpdconf/sysapihttpd.conf\"]" },
        port: { type: "integer", description: "Service port to probe, e.g. 8098" },
        request_path: { type: "string", description: "GET path sent as the trigger, e.g. /index.html; omit for a bare TCP connect" },
        argv0: { type: "string", description: "Forge guest argv[0] (busybox multicall binaries)" },
      },
      required: ["binary_md5", "argv"],
    },
  },
  {
    name: "fw_routes",
    description: "HTTP route map (path, method, handler function, binary). Links a vulnerable function to the URL that triggers it.",
    input_schema: {
      type: "object",
      properties: {
        ...JOB_ID_PROP,
        pattern: { type: "string", description: "Filter by path pattern" },
        method: { type: "string" },
        binary_md5: { type: "string" },
        limit: { type: "integer" },
      },
    },
  },
  {
    name: "fw_cypher",
    description: "Raw read-only Cypher against the code graph (CBM subset: Function/File/Module nodes, CALLS/CONTAINS edges). For custom queries the other tools cannot express.",
    input_schema: {
      type: "object",
      properties: { ...JOB_ID_PROP, query: { type: "string" } },
      required: ["query"],
    },
  },
  {
    name: "record_finding",
    description: "Record ONE confirmed vulnerability finding with its evidence. Call once per distinct vulnerability. Every finding must cite concrete evidence (function addr, pseudocode lines, attack path, trace id). Do NOT record speculative non-issues (socket accept, connection success, empty diffs, transport errors are NOT vulnerabilities). All natural-language fields MUST be written in Chinese (code, symbols, addresses, paths stay verbatim).",
    input_schema: {
      type: "object",
      properties: {
        ...JOB_ID_PROP,
        title: { type: "string" },
        severity: { type: "string", enum: ["critical", "high", "medium", "low", "info"] },
        vuln_class: { type: "string", description: "e.g. stack_buffer_overflow, command_injection, format_string, path_traversal, integer_overflow" },
        cwe: { type: "string", description: "CWE id in Chinese-standard reports, e.g. CWE-121 (stack overflow), CWE-78 (command injection), CWE-134 (format string), CWE-22 (path traversal), CWE-190 (integer overflow)" },
        binary_md5: { type: "string" },
        binary_path: { type: "string" },
        function_addr: { type: "string" },
        function_name: { type: "string" },
        summary: { type: "string", description: "What the bug is and why it is exploitable" },
        evidence: { type: "array", items: { type: "string" }, description: "Concrete citations: pseudocode line content, attack path id, trace id, route, checksec fact" },
        confidence: { type: "number", description: "0.0-1.0" },
        reachability: { type: "string", enum: ["static-only", "observed", "verified"], description: "verified = whole chain seen in ONE coverage run; observed = function seen in a trace; static-only = no runtime evidence" },
        source_summary: { type: "string", description: "Where attacker-controlled data enters" },
        sink_function: { type: "string", description: "The dangerous call, e.g. strcpy" },
        sanitization: { type: "string", description: "Bounds checks / filters found on the path, or 'none found'" },
        exploit_sketch: { type: "string", description: "How an attacker would trigger it (HTTP request shape etc.)" },
        remediation: { type: "string" },
        supersedes: { type: "string", description: "ID of an earlier finding this one replaces (same function+class, new decisive evidence)" },
      },
      required: ["title", "severity", "vuln_class", "binary_md5", "function_addr", "summary", "evidence", "confidence", "reachability"],
    },
  },
  {
    name: "finish",
    description: "End the session when mining is complete. Provide a summary of what was analyzed and which findings were recorded.",
    input_schema: {
      type: "object",
      properties: { summary: { type: "string" } },
      required: ["summary"],
    },
  },
];

/**
 * Execute one tool_call block. Returns a JSON string for the tool_result.
 */
export async function executeTool(ctx, name, input) {
  const exec = executors[name];
  if (!exec) throw new Error(`unknown tool ${name}`);
  const result = await exec(ctx, input ?? {});
  let text = typeof result === "string" ? result : JSON.stringify(result, null, 1);
  if (text.length > MAX_RESULT_CHARS) {
    text = text.slice(0, MAX_RESULT_CHARS) + `\n…[truncated, ${text.length - MAX_RESULT_CHARS} more chars]`;
  }
  return text;
}
