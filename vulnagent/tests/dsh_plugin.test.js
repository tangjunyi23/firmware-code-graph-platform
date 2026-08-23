/**
 * dsh/plugin（@fwgraph/dsh-fwgraph-tools）离线单测：
 *  - S1: 注册 fw_* 系列含 fw_browse_firmware；static 模式不收动态工具；
 *        全局 guard 按名拦截 shell/文件写/web/子代理类工具
 *  - S2/H3: record_finding POST 服务端 API 并带 session_id；422 detail 透传
 *  - fw_browse_firmware: 根监禁（防穿越/防 symlink 逃逸）、64KB 上限、
 *        扩展名白名单拒绝二进制扩展名；无扩展名文件由 NUL 嗅探把关
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { apply, browseFirmware, compactTrace, huntNextFromTrace, summarizeTraceList, huntNextFromExec } from "../dsh/plugin/src/index.js";

function mockCtx() {
  const tools = [];
  const guards = [];
  return {
    tools: {
      register: (def) => { tools.push(def); return () => {}; },
      guard: (g) => { guards.push(g); return () => {}; },
    },
    _tools: tools,
    _guards: guards,
  };
}

const BASE_CFG = {
  baseUrl: "http://fw.test", token: "tok", jobId: "job123",
  findingsDir: "/tmp/x-findings", mode: "dynamic",
  sessionId: "dsh-sess-1", extractedRoot: "",
};

test("registers the fw_* series incl. fw_browse_firmware; static mode drops dynamic tools (S1)", () => {
  const ctx = mockCtx();
  apply(ctx, { ...BASE_CFG });
  const names = ctx._tools.map((t) => t.name);
  for (const required of [
    "fw_get_identification", "fw_list_surfaces", "fw_get_surface",
    "fw_get_function_source", "fw_attack_surface", "fw_compose_evidence",
    "fw_search", "fw_call_trace",
    "fw_routes", "fw_list_traces", "fw_get_trace", "fw_browse_firmware",
    "fw_request_trace", "fw_request_fuzz", "fw_request_frida",
    "fw_qemu_exec", "fw_get_qemu_exec", "fw_list_binaries",
    "fw_get_fuzz_run", "fw_get_cfg", "fw_get_ast",
    "record_finding",
  ]) {
    assert.ok(names.includes(required), `missing ${required}`);
  }
  // 插件自身不得注册任何通用工具
  for (const n of names) assert.ok(n.startsWith("fw_") || n === "record_finding", `unexpected tool ${n}`);

  const sctx = mockCtx();
  apply(sctx, { ...BASE_CFG, mode: "static" });
  const snames = sctx._tools.map((t) => t.name);
  for (const dyn of ["fw_request_trace", "fw_request_fuzz", "fw_request_frida", "fw_qemu_exec"]) {
    assert.ok(!snames.includes(dyn), `${dyn} must not register in static mode`);
  }
  assert.ok(snames.includes("fw_browse_firmware"));
});

test("global guard denies web/subagent; sandbox bash/write stay allowed", () => {
  const ctx = mockCtx();
  apply(ctx, { ...BASE_CFG });
  assert.equal(ctx._guards.length, 1);
  const guard = ctx._guards[0];
  for (const bad of ["pwsh", "run_code", "web_search", "web_fetch", "subagent", "subagent_fork",
    "send_message", "list_agents", "ralph", "workflow"]) {
    assert.ok(guard({ name: bad }) !== undefined, `guard must deny ${bad}`);
  }
  for (const ok of ["fw_search", "fw_browse_firmware", "record_finding", "todo_write",
    "bash", "write", "edit", "read", "glob", "grep"]) {
    assert.equal(guard({ name: ok }), undefined, `guard must allow ${ok}`);
  }
});

function mockFetch(handler) {
  const calls = [];
  const old = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    calls.push({ url: String(url), opts });
    return handler(String(url), opts);
  };
  return { calls, restore: () => { globalThis.fetch = old; } };
}

const resp = (status, body = {}) => ({
  ok: status >= 200 && status < 300,
  status,
  text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
});

const FINDING = {
  title: "httpd 栈溢出", severity: "high", confidence: 0.6,
  vuln_class: "stack_buffer_overflow", cwe: "CWE-121",
  binary_md5: "a".repeat(32), binary_path: "/usr/sbin/httpd",
  reachability: "static-only", summary: "摘要", evidence: ["行"],
  call_chain: "main@0x401000 → handle_req@0x402000 → strcpy",
  poc: "POST /goform/x HTTP/1.1\\n\\nmac=AAAA",
};

test("fw_get_identification compact view keeps binary_md5/entry_md5s", async () => {
  const ctx = mockCtx();
  apply(ctx, { ...BASE_CFG });
  const def = ctx._tools.find((t) => t.name === "fw_get_identification");
  const md5 = "a".repeat(32);
  const m = mockFetch(async () => resp(200, {
    metadata: { total_inputs: 1 },
    inputs: [{
      id: "IN-013", protocol: "ssh", service: "dropbear", port: 22,
      transport: "tcp", input_types: ["SSH handshake/KEX", `binary_md5=${md5}`],
      entry_files: ["usr/bin/dropbear"], binary_md5: md5,
      entry_md5s: [{ path: "usr/bin/dropbear", md5 }],
      processing_chain: [{ file: "usr/bin/dropbear", libs: [], md5 }],
    }],
  }));
  try {
    const out = await def.execute({});
    assert.equal(out.inputs[0].binary_md5, md5);
    assert.equal(out.inputs[0].entry_md5s[0].md5, md5);
    assert.equal(out.inputs[0].processing_chain[0].md5, md5);
    assert.ok(out.inputs[0].input_types.some((t) => t.startsWith("binary_md5=")));
  } finally {
    m.restore();
  }
});

test("dsh record_finding POSTs to server API with session_id (S2/H3)", async () => {
  const ctx = mockCtx();
  apply(ctx, { ...BASE_CFG });
  const def = ctx._tools.find((t) => t.name === "record_finding");
  const m = mockFetch(async () => resp(200, { id: "F-100", status: "draft", confidence: 0.6 }));
  try {
    const out = await def.execute({ ...FINDING });
    assert.equal(out.finding_id, "F-100");
    const { url, opts } = m.calls[0];
    assert.equal(url, "http://fw.test/vulnagent/findings");
    const body = JSON.parse(opts.body);
    assert.equal(body.session_id, "dsh-sess-1");
    assert.equal(body.job_id, "job123");
    assert.equal(body.cwe, "CWE-121");
    assert.match(body.call_chain, /→|->/);
    assert.ok(body.poc);
  } finally {
    m.restore();
  }
});

test("dsh record_finding surfaces 422 detail verbatim; local precheck rejects bad input", async () => {
  const ctx = mockCtx();
  apply(ctx, { ...BASE_CFG });
  const def = ctx._tools.find((t) => t.name === "record_finding");
  const detail = "字段 vuln_class 不合规：禁止混类";
  const m = mockFetch(async () => resp(422, { detail }));
  try {
    await assert.rejects(def.execute({ ...FINDING }), (err) => {
      assert.match(err.message, /HTTP 422/);
      assert.match(err.message, new RegExp(detail));
      return true;
    });
    // 本地预检：混填 CWE（dsh 侧原来连枚举都不查的实证来源）
    await assert.rejects(def.execute({ ...FINDING, cwe: "CWE-78 / CWE-121" }), /cwe/i);
    await assert.rejects(def.execute({ ...FINDING, vuln_class: "a/b" }), /vuln_class/);
    await assert.rejects(def.execute({ ...FINDING, reachability: "verified" }), /trace_id/);
    await assert.rejects(def.execute({ ...FINDING, call_chain: "" }), /call_chain/);
    await assert.rejects(def.execute({ ...FINDING, poc: "" }), /poc/);
    assert.equal(m.calls.length, 1); // 本地预检均未发 HTTP
  } finally {
    m.restore();
  }
});

// ---------- fw_browse_firmware ----------

function makeExtractedRoot() {
  const root = mkdtempSync(path.join(tmpdir(), "va-extracted-"));
  const job = path.join(root, "job123");
  mkdirSync(path.join(job, "etc", "config"), { recursive: true });
  writeFileSync(path.join(job, "etc", "config", "network.conf"), "option ip 192.168.1.1\n", "utf8");
  writeFileSync(path.join(job, "banner.txt"), "hello firmware\n", "utf8");
  writeFileSync(path.join(job, "busybox.bin"), Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x00]), "binary");
  writeFileSync(path.join(job, "passwd"), "root:x:0:0::/:/bin/sh\n", "utf8"); // 无扩展名文本
  writeFileSync(path.join(job, "rawdump"), Buffer.from([0x01, 0x00, 0x02]), "binary"); // 无扩展名二进制
  writeFileSync(path.join(job, "big.log"), "A".repeat(65 * 1024), "utf8"); // >64KB
  return root;
}

test("fw_browse_firmware lists directories and reads whitelisted text files", async () => {
  const extractedRoot = makeExtractedRoot();
  const cfg = { ...BASE_CFG, extractedRoot };
  const listing = await browseFirmware(cfg, {});
  assert.equal(listing.path, ".");
  assert.ok(listing.entries.some((e) => e.name === "etc" && e.type === "dir"));

  const read = await browseFirmware(cfg, { path: "etc/config/network.conf" });
  assert.match(read.content, /192\.168\.1\.1/);
  assert.ok(read.bytes < 64 * 1024);
});

test("fw_browse_firmware rejects traversal, binary/unknown extensions, oversized files", async () => {
  const extractedRoot = makeExtractedRoot();
  const cfg = { ...BASE_CFG, extractedRoot };
  await assert.rejects(browseFirmware(cfg, { path: "../../../etc/passwd" }), /escapes/);
  await assert.rejects(browseFirmware(cfg, { path: "/etc/passwd" }), /escapes|not found/);
  await assert.rejects(browseFirmware(cfg, { path: "busybox.bin" }), /whitelist/);
  await assert.rejects(browseFirmware(cfg, { path: "rawdump" }), /NUL/); // 无扩展名但含 NUL -> 二进制拒读
  // 无扩展名文本文件（etc/passwd 风格）放行，由 NUL 嗅探把关
  const noext = await browseFirmware(cfg, { path: "passwd" });
  assert.match(noext.content, /root:x:0:0/);
  await assert.rejects(browseFirmware(cfg, { path: "big.log" }), /64KB/);
  await assert.rejects(browseFirmware(cfg, { path: "nope.txt" }), /not found/);
  // job 根不存在
  await assert.rejects(browseFirmware(cfg, { job_id: "no-such-job" }), /not found/);
});

test("fw_browse_firmware rejects symlink escape from the job root", async (t) => {
  const extractedRoot = makeExtractedRoot();
  const outside = mkdtempSync(path.join(tmpdir(), "va-outside-"));
  writeFileSync(path.join(outside, "secret.txt"), "top secret\n", "utf8");
  const link = path.join(extractedRoot, "job123", "escape");
  try {
    symlinkSync(path.join(outside, "secret.txt"), link);
  } catch (err) {
    t.skip(`symlink unavailable on this platform: ${err.message}`);
    return;
  }
  await assert.rejects(
    browseFirmware({ ...BASE_CFG, extractedRoot }, { path: "escape" }),
    /symlink|escapes/,
  );
});

test("fw_list_traces empty result tells the model to call fw_request_trace", async () => {
  const ctx = mockCtx();
  apply(ctx, { ...BASE_CFG });
  const def = ctx._tools.find((t) => t.name === "fw_list_traces");
  const m = mockFetch(async () => resp(200, { job_id: "job123", total: 0, traces: [] }));
  try {
    const out = await def.execute({});
    assert.equal(out.total, 0);
    assert.match(out.hint, /fw_request_trace/);
  } finally {
    m.restore();
  }
});

test("static tools nudge fw_request_trace after several calls without a trace", async () => {
  const ctx = mockCtx();
  apply(ctx, { ...BASE_CFG });
  const src = ctx._tools.find((t) => t.name === "fw_get_function_source");
  const req = ctx._tools.find((t) => t.name === "fw_request_trace");
  const m = mockFetch(async (url) => {
    if (String(url).includes("/trace")) return resp(200, { trace_id: "aaaaaaaaaaaa" });
    return resp(200, "// source");
  });
  try {
    const first = await src.execute({ md5: "a".repeat(32), addr: "0x1" });
    assert.equal(first.hint, undefined);
    await src.execute({ md5: "a".repeat(32), addr: "0x2" });
    const third = await src.execute({ md5: "a".repeat(32), addr: "0x3" });
    assert.match(third.hint, /fw_request_trace/);
    await req.execute({ binary_md5: "a".repeat(32) });
    const after = await src.execute({ md5: "a".repeat(32), addr: "0x4" });
    assert.equal(after.hint, undefined);
  } finally {
    m.restore();
  }
});

test("fw_request_trace enforces the per-session budget (S1)", async () => {
  const ctx = mockCtx();
  apply(ctx, { ...BASE_CFG });
  const def = ctx._tools.find((t) => t.name === "fw_request_trace");
  const m = mockFetch(async () => resp(200, { trace_id: "aaaaaaaaaaaa" }));
  try {
    const args = { binary_md5: "a".repeat(32), argv: ["-c", "x"] };
    for (let i = 0; i < 192; i++) await def.execute(args);
    await assert.rejects(def.execute(args), /budget exhausted/);
    assert.equal(m.calls.length, 192);
  } finally {
    m.restore();
  }
});

test("fw retries fetch failed then succeeds", async () => {
  const ctx = mockCtx();
  apply(ctx, { ...BASE_CFG });
  const def = ctx._tools.find((t) => t.name === "fw_get_trace");
  let n = 0;
  const m = mockFetch(async () => {
    n += 1;
    if (n < 3) throw new TypeError("fetch failed");
    return resp(200, { trace_id: "bbbbbbbbbbbb", status: "ok_empty_diff" });
  });
  try {
    const out = await def.execute({ trace_id: "bbbbbbbbbbbb" });
    assert.equal(out.status, "ok_empty_diff");
    assert.equal(n, 3);
  } finally {
    m.restore();
  }
});

test("fw_get_trace compact return has hunt_next and sink flags", async () => {
  const ctx = mockCtx();
  apply(ctx, { ...BASE_CFG });
  const def = ctx._tools.find((t) => t.name === "fw_get_trace");
  const m = mockFetch(async () => resp(200, {
    trace_id: "a432876827e2",
    status: "ok",
    binary: { md5: "a".repeat(32) },
    request: { via: "file", input_path: "/tmp/poc.bin" },
    diff: {
      function_count: 2,
      functions: [
        { name: ".memcpy", addr: "0x4382b0", libc_equiv: "memcpy" },
        { name: "sub_41F614", addr: "0x41f614" },
      ],
    },
    trigger: { trigger_result: { kind: "input_path", sent: 10 } },
    rootfs: "/huge", linker: { skip: true }, cbm_ingest: { attempted: true },
  }));
  try {
    const out = await def.execute({ trace_id: "a432876827e2" });
    assert.equal(out.status, "ok");
    assert.equal(out.diff.function_count, 2);
    assert.equal(out.diff.functions[0].sink, true);
    assert.equal(out.rootfs, undefined);
    assert.match(out.hunt_next, /fw_get_function_source/);
    assert.match(out.hunt_next, /a432876827e2/);
    assert.match(out.hunt_next, /不要把差分表贴给用户/);
  } finally {
    m.restore();
  }
});

test("empty-diff net trace hunt_next retries via=stdin", () => {
  const next = huntNextFromTrace({
    trace_id: "aaaaaaaaaaaa", status: "ok_empty_diff",
    request: { via: "net", port: 80 },
    diff: { function_count: 0, functions: [] },
  });
  assert.match(next, /via=stdin/);
  assert.match(next, /禁止向用户/);
});

test("fw_list_traces with diffs points hunt_next at those ids", async () => {
  const ctx = mockCtx();
  apply(ctx, { ...BASE_CFG });
  const def = ctx._tools.find((t) => t.name === "fw_list_traces");
  const m = mockFetch(async () => resp(200, {
    job_id: "job123", total: 2, traces: [
      { trace_id: "a432876827e2", status: "ok", diff_functions: 45, binary_md5: "aa" },
      { trace_id: "f55640905b63", status: "ok_empty_diff", diff_functions: 0 },
    ],
  }));
  try {
    const out = await def.execute({});
    assert.equal(out.total, 2);
    assert.equal(out.traces, undefined);
    assert.equal(out.with_diff[0].trace_id, "a432876827e2");
    assert.match(out.hunt_next, /a432876827e2/);
    assert.match(out.hunt_next, /fw_get_trace/);
  } finally {
    m.restore();
  }
});

test("diff hunt_next sticks on later static tools until record_finding", async () => {
  const ctx = mockCtx();
  apply(ctx, { ...BASE_CFG });
  const getTrace = ctx._tools.find((t) => t.name === "fw_get_trace");
  const search = ctx._tools.find((t) => t.name === "fw_search");
  const rec = ctx._tools.find((t) => t.name === "record_finding");
  const m = mockFetch(async (url) => {
    if (String(url).includes("/traces/")) {
      return resp(200, {
        trace_id: "a432876827e2", status: "ok",
        binary: { md5: "a".repeat(32) },
        diff: { function_count: 1, functions: [{ name: ".memcpy", addr: "0x1" }] },
      });
    }
    if (String(url).includes("/graph/query")) return resp(200, { hits: [] });
    if (String(url).includes("/vulnagent/findings")) {
      return resp(200, { id: "F-test", status: "draft", confidence: 0.6 });
    }
    return resp(200, {});
  });
  try {
    await getTrace.execute({ trace_id: "a432876827e2" });
    const nudged = await search.execute({ pattern: "strcpy" });
    assert.match(nudged.hint, /fw_get_function_source/);
    await rec.execute({ ...FINDING, reachability: "observed", trace_id: "a432876827e2", confidence: 0.8 });
    const after = await search.execute({ pattern: "strcpy" });
    assert.match(after.hint, /fw_request_trace/);
  } finally {
    m.restore();
  }
});

test("compactTrace drops rootfs and keeps hunt_next", () => {
  const out = compactTrace({
    trace_id: "bbbbbbbbbbbb", status: "ok_empty_diff",
    request: { via: "stdin" },
    diff: { function_count: 0, functions: [] },
    rootfs: "/x", linker: {},
  });
  assert.equal(out.rootfs, undefined);
  assert.match(out.hunt_next, /空差分不是漏洞/);
});

test("summarizeTraceList empty keeps fw_request_trace hint", () => {
  const out = summarizeTraceList({ job_id: "job123", total: 0, traces: [] });
  assert.equal(out.total, 0);
  assert.match(out.hint, /fw_request_trace/);
});

test("startup qemu crash hunt_next does not abandon the ELF", () => {
  const next = huntNextFromExec({
    status: "crash", signal: 11, crash_kind: "startup", stdin_bytes: 0,
  });
  assert.match(next, /禁止放弃/);
  assert.match(next, /fw_request_trace/);
  assert.match(next, /禁止 record_finding/);
});

test("payload qemu crash hunt_next records the finding", () => {
  const next = huntNextFromExec({
    status: "crash", signal: 11, crash_kind: "payload", stdin_bytes: 4,
  });
  assert.match(next, /record_finding/);
});

test("fw_request_trace forwards via=stdin", async () => {
  const ctx = mockCtx();
  apply(ctx, { ...BASE_CFG });
  const def = ctx._tools.find((t) => t.name === "fw_request_trace");
  const m = mockFetch(async () => resp(200, { trace_id: "dddddddddddd" }));
  try {
    await def.execute({
      binary_md5: "a".repeat(32), via: "stdin", payload_hex: "4142",
    });
    const body = JSON.parse(m.calls[0].opts.body);
    assert.equal(body.via, "stdin");
    assert.equal(body.payload_hex, "4142");
  } finally {
    m.restore();
  }
});

test("fw_request_trace forwards payloads_hex", async () => {
  const ctx = mockCtx();
  apply(ctx, { ...BASE_CFG });
  const def = ctx._tools.find((t) => t.name === "fw_request_trace");
  const m = mockFetch(async () => resp(200, { trace_id: "cccccccccccc" }));
  try {
    await def.execute({
      binary_md5: "a".repeat(32), port: 22,
      payloads_hex: ["5353480d0a", "6b6578"],
    });
    const body = JSON.parse(m.calls[0].opts.body);
    assert.deepEqual(body.payloads_hex, ["5353480d0a", "6b6578"]);
  } finally {
    m.restore();
  }
});

test("fw_browse_firmware rejects path-carrying job_id (jail bypass)", async () => {
  const extractedRoot = makeExtractedRoot();
  const cfg = { ...BASE_CFG, extractedRoot };
  await assert.rejects(browseFirmware(cfg, { job_id: "../../.." }), /bad job_id/);
  await assert.rejects(browseFirmware(cfg, { job_id: "../outside" }), /bad job_id/);
});
