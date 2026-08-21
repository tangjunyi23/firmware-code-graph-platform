/**
 * tools.js — the agent's toolbelt.
 *
 * Managed Agents mapping: Agent.tools. Most tools are thin read-only wrappers
 * over the downstream fwgraph platform (attack-surface identification +
 * function retrieval/decompilation). Two tools are the agent's own output
 * channel: record_finding (POSTs to the server-side /vulnagent/findings API —
 * the server is the authoritative store and validator, a cache copy lands in
 * findings/) and finish (end session).
 *
 * All fwgraph calls are GETs or the read-only /graph/query proxy, with one
 * controlled exception: fw_request_trace starts a coverage trace
 * (POST /jobs/{id}/trace) so the agent can confirm routes, upgrade
 * reachability, or observe crashes — bounded per session, see
 * MAX_TRACES_PER_SESSION. The agent never mutates analysis artifacts.
 */
import { mkdirSync, writeFileSync, appendFileSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";

const MAX_RESULT_CHARS = 16000;
const MAX_TRACES_PER_SESSION = 5;
const MAX_FUZZ_PER_SESSION = 3;
// 纯静态模式禁用的动态类工具（动静结合模式才开放）
export const DYNAMIC_ONLY_TOOLS = new Set([
  "fw_request_trace", "fw_request_fuzz", "fw_request_frida",
]);

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
      // 校验类错误（422）的 detail 原文足够长地透传给 AI，便于一次修正
      throw new Error(`fwgraph ${method} ${urlPath} -> HTTP ${resp.status}: ${text.slice(0, 500)}`);
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
    if (input.brief) {
      // 分级检索（P2）：先拿 ~1KB 分诊卡（签名头部/危险调用行/出边/攻击面标记），
      // 命中疑点再拉全文，避免每个函数都把 16KB 伪代码灌进上下文。
      const brief = await fw(ctx, "GET", `/jobs/${jobId}/functions/${input.md5}/${input.addr}/brief`);
      return { addr: input.addr, md5: input.md5, source_kind: "brief", ...brief };
    }
    if (input.asm) {
      // Function-level assembly: the ground truth for recovering call-site
      // arguments (MIPS o32: $a0-$a3 then stack) when Hex-Rays collapses them.
      const src = await fw(ctx, "GET", `/jobs/${jobId}/functions/${input.md5}/${input.addr}/source?asm=1`);
      return { addr: input.addr, md5: input.md5, source_kind: "asm", source: src };
    }
    const src = await fw(ctx, "GET", `/jobs/${jobId}/functions/${input.md5}/${input.addr}/source`);
    return { addr: input.addr, md5: input.md5, source_kind: "hexrays", source: src };
  },

  async fw_compose_evidence(ctx, input) {
    if (!input.md5 || !input.addr) throw new Error("md5 and addr are required");
    return graphQuery(ctx, jobOf(ctx, input), "compose_evidence", {
      binary_md5: input.md5,
      addr: input.addr,
      ...(input.static_block ? { static_block: input.static_block } : {}),
      ...(input.decompile_text ? { decompile_text: input.decompile_text } : {}),
      ...(input.dynamic_envelope ? { dynamic_envelope: input.dynamic_envelope } : {}),
    });
  },

  async fw_attack_surface(ctx, input) {
    return graphQuery(ctx, jobOf(ctx, input), "attack_surface", {
      ...(input.source ? { source: input.source } : {}),
      ...(input.sink ? { sink: input.sink } : {}),
      verified_only: Boolean(input.verified_only),
      ...(input.brief ? { brief: true } : {}),
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

  async fw_get_identification(ctx, input) {
    // M6a: every public external input (IN-xxx) with processing/dispatch
    // chains — the starting inventory for input-driven vuln mining
    const doc = await fw(ctx, "GET", `/jobs/${jobOf(ctx, input)}/identification`);
    if (input.full) return doc;
    return {
      metadata: doc.metadata,
      inputs: (doc.inputs || []).map((i) => ({
        id: i.id, protocol: i.protocol, service: i.service,
        address: i.address, port: i.port, transport: i.transport,
        input_types: i.input_types, entry_files: i.entry_files,
        processing_chain: (i.processing_chain || []).map((p) => ({
          file: p.file, libs: p.libs,
          unresolved_needed: p.unresolved_needed || [],
          needed_complete: !(p.unresolved_needed || []).length,
        })),
      })),
    };
  },

  async fw_list_surfaces(ctx, input) {
    const jobId = jobOf(ctx, input);
    const out = await fw(ctx, "GET", `/jobs/${jobId}/surfaces`);
    if (!input.include_docs) {
      delete out.summary?.gate_warnings;
      return out;
    }
    const files = out.files || [];
    const docs = [];
    for (const name of files.slice(0, Number(input.limit ?? 80))) {
      if (!/^AS(-AUTH)?-[0-9A-Za-z]+\.json$/.test(name)) continue;
      docs.push(await fw(ctx, "GET",
        `/jobs/${jobId}/surfaces/${name.replace(/\.json$/, "")}`));
    }
    return { ...out, documents: docs };
  },

  async fw_get_surface(ctx, input) {
    if (!input.surface_id || !/^AS-(AUTH-)?[0-9A-Za-z]{1,8}$/.test(input.surface_id)) {
      throw new Error("surface_id like AS-014 or AS-AUTH-001 is required");
    }
    return fw(ctx, "GET", `/jobs/${jobOf(ctx, input)}/surfaces/${input.surface_id}`);
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

  async fw_request_fuzz(ctx, input) {
    const jobId = jobOf(ctx, input);
    if (!/^[0-9a-f]{32}$/.test(input.binary_md5 ?? "")) {
      throw new Error("binary_md5 must be a 32-char lowercase md5");
    }
    if ((ctx.fuzzCount ?? 0) >= MAX_FUZZ_PER_SESSION) {
      throw new Error(`fuzz budget exhausted (${MAX_FUZZ_PER_SESSION} per session)`);
    }
    const body = {
      binary_md5: input.binary_md5,
      seconds: Math.min(Number(input.seconds ?? 60), 300),
    };
    if (input.function) body.function = String(input.function);
    if (Array.isArray(input.args) && input.args.length) body.args = input.args.map(String);
    if (Array.isArray(input.argv) && input.argv.length) body.argv = input.argv.map(String);
    const resp = await fw(ctx, "POST", `/jobs/${jobId}/fuzz`, body);
    ctx.fuzzCount = (ctx.fuzzCount ?? 0) + 1;
    return resp;
  },

  async fw_request_frida(ctx, input) {
    const jobId = jobOf(ctx, input);
    if (!input.process) throw new Error("process is required");
    if (!Array.isArray(input.functions) || !input.functions.length) {
      throw new Error("functions must be a non-empty array");
    }
    if ((ctx.fuzzCount ?? 0) >= MAX_FUZZ_PER_SESSION) {
      throw new Error(`dynamic budget exhausted (${MAX_FUZZ_PER_SESSION} per session)`);
    }
    const resp = await fw(ctx, "POST", `/jobs/${jobId}/frida`, {
      host: String(input.host ?? ""),
      process: String(input.process),
      functions: input.functions,
      seconds: Math.min(Number(input.seconds ?? 60), 300),
      spawn: Boolean(input.spawn),
    });
    ctx.fuzzCount = (ctx.fuzzCount ?? 0) + 1;
    return resp;
  },

  async fw_get_cfg(ctx, input) {
    if (!/^[0-9a-f]{32}$/.test(input.md5 ?? "")) throw new Error("md5 required");
    if (!/^(0x)?[0-9a-fA-F]+$/.test(input.addr ?? "")) throw new Error("addr required");
    return graphQuery(ctx, jobOf(ctx, input), "cfg", { md5: input.md5, addr: input.addr,
      ...(input.max_nodes ? { max_nodes: Number(input.max_nodes) } : {}) });
  },

  async fw_get_ast(ctx, input) {
    if (!/^[0-9a-f]{32}$/.test(input.md5 ?? "")) throw new Error("md5 required");
    if (!/^(0x)?[0-9a-fA-F]+$/.test(input.addr ?? "")) throw new Error("addr required");
    return graphQuery(ctx, jobOf(ctx, input), "ast", { md5: input.md5, addr: input.addr,
      ...(input.max_nodes ? { max_nodes: Number(input.max_nodes) } : {}),
      ...(input.max_depth ? { max_depth: Number(input.max_depth) } : {}) });
  },

  async fw_get_fuzz_run(ctx, input) {
    const jobId = jobOf(ctx, input);
    if (!/^(fuzz|frida)$/.test(input.kind ?? "")) throw new Error("kind must be fuzz|frida");
    if (!/^(fz|fs)-[0-9a-f]{8}$/.test(input.run_id ?? "")) throw new Error("bad run_id");
    return fw(ctx, "GET", `/jobs/${jobId}/${input.kind}/${input.run_id}`);
  },

  async record_finding(ctx, input) {
    // 服务端权威校验（POST /vulnagent/findings，id/status/owner/recorded_at
    // 由服务端生成）；本地只做镜像预检，省一次明显违规的往返。服务端 422 时
    // fw() 把中文 detail 原文抛出，AI 按提示修正后重交即可。
    const required = ["title", "severity", "confidence", "vuln_class", "cwe", "binary_md5", "binary_path", "reachability", "summary", "evidence"];
    const missing = required.filter((k) => input[k] === undefined || input[k] === null || input[k] === "");
    if (missing.length) throw new Error(`record_finding missing required fields: ${missing.join(", ")}`);
    if (!["critical", "high", "medium", "low", "info"].includes(input.severity)) {
      throw new Error(`bad severity: ${JSON.stringify(input.severity)} (must be critical|high|medium|low|info)`);
    }
    if (!["static-only", "observed", "verified"].includes(input.reachability)) {
      throw new Error(`bad reachability: ${JSON.stringify(input.reachability)} (must be static-only|observed|verified)`);
    }
    const conf = Number(input.confidence);
    if (!Number.isFinite(conf) || conf < 0 || conf > 1) {
      throw new Error(`bad confidence: ${JSON.stringify(input.confidence)} (must be a number in 0..1)`);
    }
    if (input.reachability === "static-only" && conf > 0.7) {
      throw new Error(`confidence ${conf} exceeds the static-only cap 0.7 (服务端锚点封顶；先补动态证据再提高置信度)`);
    }
    if (!/^CWE-\d+$/.test(String(input.cwe))) {
      throw new Error(`bad cwe: ${JSON.stringify(input.cwe)} (严格单个 CWE-<数字>，如 CWE-121；禁止 "CWE-78 / CWE-121" 混填)`);
    }
    if (/[/，、]/.test(String(input.vuln_class))) {
      throw new Error(`bad vuln_class: ${JSON.stringify(input.vuln_class)} (服务端拒收含 "/"，"、"，" 的混类；一类一条，分开记录)`);
    }
    if (!Array.isArray(input.evidence) || !input.evidence.length
        || input.evidence.some((e) => typeof e !== "string" || !e.trim())) {
      throw new Error("evidence must be a non-empty array of non-empty strings");
    }
    if (input.reachability !== "static-only" && !input.trace_id) {
      throw new Error(`reachability=${input.reachability} 必须带 trace_id（服务端会校验该 trace 存在）`);
    }
    const body = {
      job_id: jobOf(ctx, input),
      session_id: ctx.sessionId,
      title: input.title,
      severity: input.severity,
      confidence: conf,
      vuln_class: input.vuln_class,
      cwe: input.cwe,
      binary_md5: input.binary_md5,
      binary_path: input.binary_path,
      reachability: input.reachability,
      summary: input.summary,
      evidence: input.evidence,
    };
    for (const k of ["function_addr", "function_name", "preconditions", "exploit_sketch", "remediation", "trace_id", "poc", "call_chain", "source_summary", "sink_function", "sanitization"]) {
      if (input[k] !== undefined && input[k] !== null && input[k] !== "") body[k] = input[k];
    }
    const finding = await fw(ctx, "POST", "/vulnagent/findings", body);
    if (!finding || typeof finding !== "object" || !finding.id) {
      throw new Error(`server did not return a finding id: ${JSON.stringify(finding)?.slice(0, 300)}`);
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
    // 服务端是权威存储；本地缓存一份（含仅本地字段），session 报告与查重读它。
    // 服务端字段（id/status/owner/recorded_at/封顶后的 confidence）覆盖本地输入。
    const record = { ...input, ...finding };
    if (related.length) record.related_findings = related;
    delete record.job_id_input;
    mkdirSync(ctx.config.dirs.findings, { recursive: true });
    const file = path.join(ctx.config.dirs.findings, `${record.id}.json`);
    writeFileSync(file, JSON.stringify(record, null, 2), "utf8");
    appendFileSync(path.join(ctx.config.dirs.findings, "index.jsonl"), JSON.stringify(record) + "\n", "utf8");
    ctx.findings.push(record);
    return {
      recorded: true,
      finding_id: record.id,
      status: record.status ?? "draft",
      confidence: record.confidence,
      file,
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
    description: "Retrieve decompiled pseudo-C of one function by md5+addr (for screening many functions, prefer brief=true). Returns raw Hex-Rays output — join other artifacts only via evidence_address (job_id + binary_md5 + canonical 0x addr), never by path or symbol name. decompile_gap=true means missing pseudo-C, not missing machine code. When Hex-Rays collapses call-site arguments (e.g. `strcat();`), set asm=true to get the function-level assembly and recover $a0-$a3/stack arguments yourself.",
    input_schema: {
      type: "object",
      properties: {
        ...JOB_ID_PROP,
        md5: { type: "string", description: "Binary md5" },
        addr: { type: "string", description: "Function address, e.g. 0x43785c" },
        brief: { type: "boolean", description: "Return the compact triage card (~1KB: signature head, dangerous calls with line numbers, callees, attack-surface flags) instead of full pseudo-C. ALWAYS triage with brief=true first when screening multiple functions; fetch full source only for suspicious ones." },
        asm: { type: "boolean", description: "Return function-level assembly instead of pseudo-C (for call-site argument recovery)" },
      },
      required: ["md5", "addr"],
    },
  },
  {
    name: "fw_attack_surface",
    description: "Ranked source->sink attack paths. Each node has evidence_address (job_id+md5+addr) — the only cross-tool join key. attribution: verified_in_single_trace | observed_in_window | static_only; never request-caused. Prefer verified_only, then ai_review P0/P1, then high danger_calls×entry_outdegree. ai_review is a triage hint, never a finding.",
    input_schema: {
      type: "object",
      properties: {
        ...JOB_ID_PROP,
        source: { type: "string", description: "Filter by source function addr" },
        sink: { type: "string", description: "Filter by sink function addr" },
        verified_only: { type: "boolean" },
        brief: { type: "boolean", description: "Omit per-path chain nodes — only path_id/score/source/sink/flags. Use for wide scans; refetch with the source/sink filters and brief=false for the chains you actually dig." },
        limit: { type: "integer", description: "Max paths (default 20, cap 50)" },
      },
    },
  },
  {
    name: "fw_compose_evidence",
    description: "Join already-fetched facts at one Evidence Address (job_id + binary_md5 + canonical addr). Does not query other producers. Pass static_block / decompile_text / dynamic_envelope you already have.",
    input_schema: {
      type: "object",
      properties: {
        ...JOB_ID_PROP,
        md5: { type: "string", description: "Binary md5" },
        addr: { type: "string", description: "Function address, e.g. 0x43785c" },
        static_block: { type: "object", description: "Already-fetched attack-surface node" },
        decompile_text: { type: "string", description: "Already-fetched Hex-Rays text" },
        dynamic_envelope: { type: "object", description: "Already-fetched trace/frida envelope" },
      },
      required: ["md5", "addr"],
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
    description: "Ordered request-handling path of one qemu-user coverage trace, with dangerous libc_equiv highlights. Envelope attribution is observed_in_window: seen in that trace window, not request-caused, not a coverage percentage. Do not merge two traces into one path. Truncated pages (analysis_complete=false) are incomplete.",
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
    name: "fw_get_identification",
    description: "External-input inventory (M6a identification.json): every public, non-loopback input of the firmware (IN-xxx) with protocol/port, input types, entry files, processing-chain libraries (needed_complete / unresolved_needed) and dispatch chains. Start vuln mining here. unresolved_needed is a quality gap, not a reason to pick another firmware tree.",
    input_schema: {
      type: "object",
      properties: {
        ...JOB_ID_PROP,
        full: { type: "boolean", description: "Return the complete document including evidence/notes (large)" },
      },
    },
  },
  {
    name: "fw_list_surfaces",
    description: "List per-input attack-surface files (AS-xxx.json / AS-AUTH-xxx.json, M6b). Each surface documents routing path, dispatchers, parsers, normalizers, final handler, carrier bindings and referenced auth chains for one external input.",
    input_schema: {
      type: "object",
      properties: {
        ...JOB_ID_PROP,
        include_docs: { type: "boolean", description: "Also fetch every surface document (large)" },
        limit: { type: "integer" },
      },
    },
  },
  {
    name: "fw_get_surface",
    description: "Fetch one attack-surface document by id (AS-014, AS-AUTH-001). Contains routing_path/dispatchers/parsers/normalizers/final_handler/carrier_bindings for vuln chaining.",
    input_schema: {
      type: "object",
      properties: {
        ...JOB_ID_PROP,
        surface_id: { type: "string", description: "AS-014 or AS-AUTH-001" },
      },
      required: ["surface_id"],
    },
  },
  {
    name: "fw_cypher",
    description: "Cypher queries against the code graph (CBM subset: Function/File/Module nodes, CALLS/CONTAINS edges). 服务端强制只读（MATCH/RETURN 类），写语句会被拒。For custom queries the other tools cannot express.",
    input_schema: {
      type: "object",
      properties: { ...JOB_ID_PROP, query: { type: "string" } },
      required: ["query"],
    },
  },
  {
    name: "fw_request_fuzz",
    description: "Request a function-level AFL++ fuzz run on a binary (dynamic, arm/mips via qemu persistent hook; x86 handled by frida instead). Use only in dynamic mode with a concrete hypothesis. Returns run_id; poll /jobs/{id}/fuzz/{run_id} via fw_get_fuzz_run.",
    input_schema: {
      type: "object",
      properties: {
        ...JOB_ID_PROP,
        binary_md5: { type: "string" },
        function: { type: "string", description: "hex address like 0x131b4 (omit for whole-binary @@ mode)" },
        args: { type: "array", items: { type: "string" }, description: "arg spec e.g. [buf,len]" },
        argv: { type: "array", items: { type: "string" } },
        seconds: { type: "integer" },
      },
      required: ["binary_md5"],
    },
  },
  {
    name: "fw_request_frida",
    description: "Request a frida instrumentation run on an x86 process (dynamic). host empty = local. functions: [{module, symbol | offset, label}].",
    input_schema: {
      type: "object",
      properties: {
        ...JOB_ID_PROP,
        host: { type: "string" },
        process: { type: "string" },
        functions: { type: "array", items: { type: "object" } },
        seconds: { type: "integer" },
        spawn: { type: "boolean" },
      },
      required: ["process", "functions"],
    },
  },
  {
    name: "fw_get_fuzz_run",
    description: "Fetch one fuzz/frida run result (execs/crashes/hangs or hooked/hits).",
    input_schema: {
      type: "object",
      properties: {
        ...JOB_ID_PROP,
        kind: { type: "string", enum: ["fuzz", "frida"] },
        run_id: { type: "string" },
      },
      required: ["kind", "run_id"],
    },
  },
  {
    name: "fw_get_cfg",
    description: "Control-flow graph of one function (basic blocks + branch edges, from IDA asm). Use to reason about loops/branches reaching a sink. Big functions: pass max_nodes to truncate (entry blocks kept first).",
    input_schema: {
      type: "object",
      properties: {
        ...JOB_ID_PROP,
        md5: { type: "string" },
        addr: { type: "string", description: "function address 0x..." },
        max_nodes: { type: "integer", description: "Keep at most N basic blocks (0/absent = full)" },
      },
      required: ["md5", "addr"],
    },
  },
  {
    name: "fw_get_ast",
    description: "Abstract syntax tree of one function's pseudo-C (tree-sitter). Use for precise data-flow reasoning over the decompiled source. Big functions: pass max_depth/max_nodes to truncate.",
    input_schema: {
      type: "object",
      properties: {
        ...JOB_ID_PROP,
        md5: { type: "string" },
        addr: { type: "string" },
        max_depth: { type: "integer", description: "Prune AST below this depth (0/absent = full)" },
        max_nodes: { type: "integer", description: "Keep at most N nodes (0/absent = full)" },
      },
      required: ["md5", "addr"],
    },
  },
  {
    name: "record_finding",
    description: "Record ONE confirmed vulnerability finding via the server-side findings API (POST /vulnagent/findings). The server is the authoritative validator and store: it generates the finding id (F-xxx) and status=draft, and rejects (HTTP 422, Chinese detail) when a field breaks a rule — read the detail, fix the field, resubmit. Server rules: job must exist; binary_md5 must be in the job manifest; function_addr (when given) must be in symbols; cwe is REQUIRED and must be exactly one `CWE-<digits>` (never combos like `CWE-78 / CWE-121`); vuln_class is a SINGLE class — values containing `/`, `，`, `、` are rejected; severity ∈ critical|high|medium|low|info; reachability ∈ static-only|observed|verified; confidence 0..1 with anchor caps — static-only is capped at 0.7, observed/verified REQUIRE an existing trace_id. Call once per distinct vulnerability; every finding must cite concrete evidence (function addr, pseudocode lines, attack path, trace id). Do NOT record speculative non-issues (socket accept, connection success, empty diffs, transport errors are NOT vulnerabilities). All natural-language fields MUST be written in Chinese (code, symbols, addresses, paths stay verbatim).",
    input_schema: {
      type: "object",
      properties: {
        ...JOB_ID_PROP,
        title: { type: "string" },
        severity: { type: "string", enum: ["critical", "high", "medium", "low", "info"] },
        vuln_class: { type: "string", description: "SINGLE class, e.g. stack_buffer_overflow, command_injection, format_string, path_traversal, integer_overflow. No `/`, `，`, `、` combos." },
        cwe: { type: "string", description: "REQUIRED, exactly one CWE-<digits>: CWE-121 (stack overflow), CWE-78 (command injection), CWE-134 (format string), CWE-22 (path traversal), CWE-190 (integer overflow)" },
        binary_md5: { type: "string" },
        binary_path: { type: "string" },
        function_addr: { type: "string", description: "Must exist in the job's symbol table when given" },
        function_name: { type: "string" },
        summary: { type: "string", description: "What the bug is and why it is exploitable" },
        evidence: { type: "array", items: { type: "string" }, description: "具体引用：伪代码行、攻击路径 id、trace id、路由、checksec。用中文写说明，代码/地址保持原文。" },
        call_chain: { type: "string", description: "REQUIRED in the report: 从入口到 sink 的调用链，函数名+地址，用 → 连接，每跳用中文说明" },
        poc: { type: "string", description: "REQUIRED in the report: 可复现漏洞 PoC（HTTP 请求/命令行/输入构造）。中文说明 + 原文 payload" },
        confidence: { type: "number", description: "0.0-1.0. Anchors: static-only ≤0.7 (server-capped); observed/verified need trace_id; memory-corruption without checksec evidence ≤0.6" },
        reachability: { type: "string", enum: ["static-only", "observed", "verified"], description: "verified = whole chain seen in ONE coverage run; observed = function seen in a trace; static-only = no runtime evidence" },
        trace_id: { type: "string", description: "Coverage trace id (12 hex chars); REQUIRED when reachability is observed/verified" },
        preconditions: { type: "string", description: "Trigger preconditions / exploit constraints" },
        source_summary: { type: "string", description: "Where attacker-controlled data enters (local cache only, not sent to server)" },
        sink_function: { type: "string", description: "The dangerous call, e.g. strcpy (local cache only)" },
        sanitization: { type: "string", description: "Bounds checks / filters found on the path, or 'none found' (local cache only)" },
        exploit_sketch: { type: "string", description: "若未填 poc，则用此字段作为漏洞 PoC（触发方式/请求形状）" },
        remediation: { type: "string" },
        supersedes: { type: "string", description: "ID of an earlier finding this one replaces (local cache only)" },
      },
      required: ["title", "severity", "confidence", "vuln_class", "cwe", "binary_md5", "binary_path", "reachability", "summary", "evidence"],
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
 * Mode isolation is enforced HERE, not only in the advertised tool list:
 * a static-mode session can never run dynamic tools, even if the model
 * hallucinates or gets injected into calling one (H2).
 */
export async function executeTool(ctx, name, input) {
  const exec = executors[name];
  if (!exec) throw new Error(`unknown tool ${name}`);
  const mode = ctx.session?.mode ?? ctx.session?.state?.mode ?? "dynamic";
  if (mode === "static" && DYNAMIC_ONLY_TOOLS.has(name)) {
    throw new Error(`tool ${name} is unavailable in static mode（静态挖掘模式禁用动态类工具 fw_request_trace/fw_request_fuzz/fw_request_frida；如需动态验证请用 dynamic 模式重开会话）`);
  }
  const result = await exec(ctx, input ?? {});
  let text = typeof result === "string" ? result : JSON.stringify(result, null, 1);
  if (text.length > MAX_RESULT_CHARS) {
    text = text.slice(0, MAX_RESULT_CHARS) + `\n…[truncated, ${text.length - MAX_RESULT_CHARS} more chars]`;
  }
  return text;
}
