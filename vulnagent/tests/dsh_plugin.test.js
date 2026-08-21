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
import { apply, browseFirmware } from "../dsh/plugin/src/index.js";

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
    "fw_routes", "fw_list_traces", "fw_browse_firmware",
    "fw_request_trace", "fw_request_fuzz", "fw_request_frida",
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
  for (const dyn of ["fw_request_trace", "fw_request_fuzz", "fw_request_frida"]) {
    assert.ok(!snames.includes(dyn), `${dyn} must not register in static mode`);
  }
  assert.ok(snames.includes("fw_browse_firmware"));
});

test("global guard denies shell/file-write/web/subagent classes by name (S1)", () => {
  const ctx = mockCtx();
  apply(ctx, { ...BASE_CFG });
  assert.equal(ctx._guards.length, 1);
  const guard = ctx._guards[0];
  for (const bad of ["bash", "pwsh", "run_code", "read", "write", "edit", "glob", "grep",
    "str_replace_editor", "web_search", "web_fetch", "subagent", "subagent_fork",
    "send_message", "list_agents", "ralph", "workflow", "job_kill"]) {
    assert.ok(guard({ name: bad }) !== undefined, `guard must deny ${bad}`);
  }
  for (const ok of ["fw_search", "fw_browse_firmware", "record_finding", "todo_write"]) {
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
};

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
    assert.equal(m.calls.length, 1); // 本地预检的三次均未发 HTTP
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

test("fw_request_trace enforces the per-session budget (S1)", async () => {
  const ctx = mockCtx();
  apply(ctx, { ...BASE_CFG });
  const def = ctx._tools.find((t) => t.name === "fw_request_trace");
  const m = mockFetch(async () => resp(200, { trace_id: "aaaaaaaaaaaa" }));
  try {
    const args = { binary_md5: "a".repeat(32), argv: ["-c", "x"] };
    for (let i = 0; i < 5; i++) await def.execute(args);
    await assert.rejects(def.execute(args), /budget exhausted/);
    assert.equal(m.calls.length, 5);
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
