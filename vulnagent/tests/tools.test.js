/**
 * tools.js 单测（离线，mock fetch）：
 *  - S2: record_finding 走服务端 POST /vulnagent/findings；422 detail 原文透传；
 *        本地镜像预检（cwe 混填 / vuln_class 混类 / observed 无 trace_id / static-only 超锚点）
 *  - H2: executeTool 在 static 模式硬拒动态类工具（不止工具列表层）
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { executeTool } from "../src/tools.js";

function makeCtx({ mode = "dynamic" } = {}) {
  const findingsDir = mkdtempSync(path.join(tmpdir(), "va-findings-"));
  return {
    config: {
      fwgraph: { baseUrl: "http://fw.test", token: "tok", defaultJobId: "job123" },
      dirs: { findings: findingsDir },
    },
    sessionId: "s-test",
    findings: [],
    session: { mode },
  };
}

const VALID = {
  title: "httpd 栈溢出", severity: "high", confidence: 0.6,
  vuln_class: "stack_buffer_overflow", cwe: "CWE-121",
  binary_md5: "a".repeat(32), binary_path: "/usr/sbin/httpd",
  reachability: "static-only", summary: "摘要", evidence: ["伪代码行 x"],
};

/** Replace global fetch with a mock; returns captured calls. */
function mockFetch(handler) {
  const calls = [];
  const old = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    calls.push({ url: String(url), opts });
    return handler(String(url), opts);
  };
  return { calls, restore: () => { globalThis.fetch = old; } };
}

function jsonResponse(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Map([["content-type", "application/json"]]),
    text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
  };
}

test("record_finding POSTs to /vulnagent/findings with session_id, caches server record", async () => {
  const ctx = makeCtx();
  const m = mockFetch(async () => jsonResponse(200, {
    id: "F-001", status: "draft", owner: "agent", recorded_at: "2026-08-15T00:00:00Z",
    confidence: 0.6,
  }));
  try {
    const out = JSON.parse(await executeTool(ctx, "record_finding", { ...VALID }));
    assert.equal(out.recorded, true);
    assert.equal(out.finding_id, "F-001");
    assert.equal(out.status, "draft");
    assert.equal(m.calls.length, 1);
    const { url, opts } = m.calls[0];
    assert.equal(url, "http://fw.test/vulnagent/findings");
    assert.equal(opts.method, "POST");
    assert.equal(opts.headers.Authorization, "Bearer tok");
    const body = JSON.parse(opts.body);
    assert.equal(body.job_id, "job123");
    assert.equal(body.session_id, "s-test");
    assert.equal(body.cwe, "CWE-121");
    assert.equal(body.vuln_class, "stack_buffer_overflow");
    // 仅本地字段不得上送（契约 body 之外）
    assert.equal(body.source_summary, undefined);
    assert.equal(body.supersedes, undefined);
    // 本地缓存：服务端 id 落盘，session findings 跟踪
    assert.ok(existsSync(path.join(ctx.config.dirs.findings, "F-001.json")));
    assert.equal(ctx.findings[0].id, "F-001");
  } finally {
    m.restore();
  }
});

test("record_finding passes through server 422 detail verbatim", async () => {
  const ctx = makeCtx();
  const detail = "字段 cwe 不合规：必须是单个 CWE-<数字>";
  const m = mockFetch(async () => jsonResponse(422, { detail }));
  try {
    await assert.rejects(
      executeTool(ctx, "record_finding", { ...VALID }),
      (err) => {
        assert.match(err.message, /HTTP 422/);
        assert.match(err.message, new RegExp(detail));
        return true;
      },
    );
    // 失败不得产生本地缓存
    assert.equal(ctx.findings.length, 0);
  } finally {
    m.restore();
  }
});

test("record_finding local precheck mirrors server rules (no HTTP round-trip)", async () => {
  const ctx = makeCtx();
  const m = mockFetch(async () => jsonResponse(200, { id: "F-x" }));
  try {
    // 混填 CWE（S2 实证入过库的非法值）
    await assert.rejects(executeTool(ctx, "record_finding", { ...VALID, cwe: "CWE-78 / CWE-121" }), /cwe/i);
    // 混类 vuln_class
    await assert.rejects(executeTool(ctx, "record_finding", { ...VALID, vuln_class: "命令注入/栈溢出" }), /vuln_class/);
    await assert.rejects(executeTool(ctx, "record_finding", { ...VALID, vuln_class: "a、b" }), /vuln_class/);
    // observed/verified 必须带 trace_id
    await assert.rejects(executeTool(ctx, "record_finding", { ...VALID, reachability: "observed" }), /trace_id/);
    // static-only 置信度锚点封顶 0.7
    await assert.rejects(executeTool(ctx, "record_finding", { ...VALID, confidence: 0.9 }), /0\.7/);
    // severity/reachability 枚举
    await assert.rejects(executeTool(ctx, "record_finding", { ...VALID, severity: "严重" }), /severity/);
    await assert.rejects(executeTool(ctx, "record_finding", { ...VALID, reachability: "static" }), /reachability/);
    // 以上全部本地拒绝，零 HTTP 调用
    assert.equal(m.calls.length, 0);
  } finally {
    m.restore();
  }
});

test("executeTool hard-rejects dynamic-only tools in static mode (H2)", async () => {
  const ctx = makeCtx({ mode: "static" });
  const m = mockFetch(async () => jsonResponse(200, {}));
  try {
    for (const name of ["fw_request_trace", "fw_request_fuzz", "fw_request_frida"]) {
      await assert.rejects(
        executeTool(ctx, name, { binary_md5: "a".repeat(32), argv: ["x"], process: "p", functions: [{}] }),
        (err) => {
          assert.match(err.message, /static mode/);
          return true;
        },
      );
    }
    assert.equal(m.calls.length, 0); // 从未触网
  } finally {
    m.restore();
  }
});

test("executeTool allows dynamic tools in dynamic mode", async () => {
  const ctx = makeCtx({ mode: "dynamic" });
  const m = mockFetch(async (url) => {
    assert.match(url, /\/jobs\/job123\/trace$/);
    return jsonResponse(200, { trace_id: "abc123def456" });
  });
  try {
    const out = JSON.parse(await executeTool(ctx, "fw_request_trace", {
      binary_md5: "a".repeat(32), argv: ["-c", "/etc/x.conf"],
    }));
    assert.equal(out.trace_id, "abc123def456");
    assert.equal(m.calls.length, 1);
  } finally {
    m.restore();
  }
});

test("executeTool reads mode from resumed state (session.state.mode)", async () => {
  const ctx = makeCtx();
  ctx.session = { state: { mode: "static" } }; // resume 前的瞬间形态
  await assert.rejects(
    executeTool(ctx, "fw_request_fuzz", { binary_md5: "a".repeat(32) }),
    /static mode/,
  );
});
