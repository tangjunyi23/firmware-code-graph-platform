/**
 * playbook.js 单测（离线，mock fetch）：
 *  - S3: Phase3 结论落库（dropped→retracted PATCH）、Phase4 末行精确判定、
 *        记忆写回 clamp [0.1,0.95]、Phase5 FINAL.md（PASS/LOOP 均产出）
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  clampConfidence,
  extractVerdict,
  parsePhase3Json,
  patchFinding,
  writebackMemory,
  writeFinalReport,
} from "../src/playbook.js";

const CFG = { fwgraph: { baseUrl: "http://fw.test", token: "tok" } };

function mockFetch(handler) {
  const calls = [];
  const old = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    calls.push({ url: String(url), opts });
    return handler(String(url), opts);
  };
  return { calls, restore: () => { globalThis.fetch = old; } };
}

const resp = (status, body = "") => ({
  ok: status >= 200 && status < 300,
  status,
  text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
});

// ---------- Phase 3 JSON 解析 ----------

test("parsePhase3Json extracts the trailing verdict JSON from prose", () => {
  const text = [
    "逐条复核完成。F-001 证据闭合，F-002 的载体不可控，剔除。",
    "",
    "{\"verified\":[\"F-001\"],\"dropped\":[\"F-002\"],\"notes\":\"F-002 输入长度被上层截断\"}",
  ].join("\n");
  const out = parsePhase3Json(text);
  assert.deepEqual(out.verified, ["F-001"]);
  assert.deepEqual(out.dropped, ["F-002"]);
  assert.equal(out.notes, "F-002 输入长度被上层截断");
});

test("parsePhase3Json returns null when no verdict JSON present", () => {
  assert.equal(parsePhase3Json("没有任何 JSON"), null);
  assert.equal(parsePhase3Json(""), null);
  assert.equal(parsePhase3Json("{\"foo\":1}"), null); // 无 verified/dropped 字段
});

// ---------- Phase 3 落库（retracted/verified PATCH） ----------

test("patchFinding PATCHes status=retracted with note (S3)", async () => {
  const m = mockFetch(async () => resp(200, "{}"));
  try {
    const r = await patchFinding(CFG, "F-002", { status: "retracted", note: "Phase3 剔除：证据不足" });
    assert.equal(r.ok, true);
    assert.equal(m.calls.length, 1);
    assert.equal(m.calls[0].url, "http://fw.test/vulnagent/findings/F-002");
    assert.equal(m.calls[0].opts.method, "PATCH");
    assert.equal(m.calls[0].opts.headers.Authorization, "Bearer tok");
    assert.deepEqual(JSON.parse(m.calls[0].opts.body), { status: "retracted", note: "Phase3 剔除：证据不足" });
  } finally {
    m.restore();
  }
});

test("patchFinding never throws: server 404/网络错误都返回 ok:false", async () => {
  const m404 = mockFetch(async () => resp(404, '{"detail":"未找到该 finding"}'));
  try {
    const r = await patchFinding(CFG, "F-999", { status: "retracted", note: "x" });
    assert.equal(r.ok, false);
    assert.match(r.error, /404/);
  } finally {
    m404.restore();
  }
  const mErr = mockFetch(async () => { throw new Error("conn refused"); });
  try {
    const r = await patchFinding(CFG, "F-001", { note: "x" });
    assert.equal(r.ok, false);
    assert.match(r.error, /conn refused/);
  } finally {
    mErr.restore();
  }
  // 非法 fid 不进 URL
  const r = await patchFinding(CFG, "../../etc", { note: "x" });
  assert.equal(r.ok, false);
});

// ---------- Phase 4 末行精确判定 ----------

test("extractVerdict: last-line exact match only", () => {
  assert.equal(extractVerdict("分析……\noverall_verdict: PASS"), "PASS");
  assert.equal(extractVerdict("分析……\noverall_verdict: PASS  \n"), "PASS"); // 尾部空白容忍
  assert.equal(extractVerdict("overall_verdict: PASS\n但还有疑点没查完"), "LOOP"); // 非末行
  assert.equal(extractVerdict("我认为可以 overall_verdict: PASS"), "LOOP"); // 前缀污染
  assert.equal(extractVerdict("verdict: PASS"), "LOOP"); // 旧格式不算
  assert.equal(extractVerdict("overall_verdict: pass"), "LOOP"); // 大小写精确
  assert.equal(extractVerdict(""), "LOOP");
});

// ---------- 记忆写回 clamp ----------

test("writebackMemory applies delta with clamp [0.1, 0.95], untouched lines byte-identical", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "va-mem-"));
  const file = path.join(dir, "insights.jsonl");
  const e1 = { id: "MEM-PATTERN-BOF-01", type: "vulnerability_pattern", content: "x", confidence: 0.93 };
  const e2 = { id: "MEM-PATTERN-CMDI-01", type: "vulnerability_pattern", content: "y", confidence: 0.12 };
  const e3 = { id: "MEM-META-OLD", type: "meta_rule", content: "legacy" }; // 无 confidence
  const untouchedLine = JSON.stringify({ id: "MEM-PATTERN-INTOV-01", type: "vulnerability_pattern", content: "z", confidence: 0.5 });
  writeFileSync(file, [JSON.stringify(e1), JSON.stringify(e2), JSON.stringify(e3), untouchedLine, ""].join("\n"), "utf8");

  // PASS +0.05：e1 0.93 → 0.95（封顶）
  let r = writebackMemory(["MEM-PATTERN-BOF-01"], 0.05, file);
  assert.equal(r.updated, 1);
  let lines = readFileSync(file, "utf8").split("\n");
  assert.equal(JSON.parse(lines[0]).confidence, 0.95);
  assert.equal(lines[3], untouchedLine); // 未命中行原样保留

  // LOOP -0.05：e2 0.12 → 0.1（封底）；e3 无 confidence 不动
  r = writebackMemory(["MEM-PATTERN-CMDI-01", "MEM-META-OLD"], -0.05, file);
  assert.equal(r.updated, 1);
  lines = readFileSync(file, "utf8").split("\n");
  assert.equal(JSON.parse(lines[1]).confidence, 0.1);
  assert.equal(JSON.parse(lines[2]).confidence, undefined);

  assert.equal(clampConfidence(0.7 + 0.05), 0.75);
  assert.equal(clampConfidence(99), 0.95);
  assert.equal(clampConfidence(-1), 0.1);
});

// ---------- Phase 5 FINAL.md ----------

function sampleFinding() {
  return {
    id: "F-001", title: "httpd 栈溢出", vuln_class: "stack_buffer_overflow", cwe: "CWE-121",
    severity: "high", confidence: 0.65, reachability: "static-only",
    function_name: "httpd_parse", function_addr: "0x401234",
    binary_md5: "a".repeat(32), binary_path: "/usr/sbin/httpd",
    summary: "摘要", evidence: ["行1", "行2"], preconditions: "无需认证",
    exploit_sketch: "GET /x?a=AAAA...", remediation: "边界检查",
    source_summary: "query 参数", sink_function: "strcpy", sanitization: "none found",
  };
}

test("writeFinalReport: PASS and LOOP both produce FINAL.md; LOOP is prominently marked", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "va-hunt-"));
  const base = {
    dir, vulnType: "预认证漏洞", findings: [sampleFinding()],
    retracted: [{ id: "F-002", note: "载体不可控", title: "误报候选" }],
    attackSurfaceText: "AS-AUTH-001 授权链：login_check → dispatch\n其他行",
  };
  writeFinalReport({ ...base, snapshot: { hunt_id: "h-1", job_id: "job123", verdict: "PASS", rounds: [{}] } });
  const pass = readFileSync(path.join(dir, "FINAL.md"), "utf8");
  assert.match(pass, /# 漏洞挖掘报告/);
  assert.match(pass, /F-001/);
  assert.match(pass, /漏洞函数: httpd_parse/);
  assert.match(pass, /排除候选: F-002/);
  assert.doesNotMatch(pass, /未经对抗验证通过/);
  assert.match(pass, /AS-AUTH-001/); // 认证管线摘录

  writeFinalReport({ ...base, snapshot: { hunt_id: "h-2", job_id: "job123", verdict: "LOOP", rounds: [{}, {}] } });
  const loop = readFileSync(path.join(dir, "FINAL.md"), "utf8");
  assert.match(loop, /未经对抗验证通过/);
  assert.match(loop, /LOOP/);
});

// ---------- L6: 记忆固件域门控 ----------

test("loadMemory filters out non-firmware legacy entries (L6)", async () => {
  const { loadMemory, firmwareTags } = await import("../src/playbook.js");
  // 真实记忆库：154 条里大量 Web/Java 源码审计遗产
  const out = loadMemory(["BOF", "CMDI", "INTOV", "MEMOV", "PREAUTH", "RCE", "AUTHBYPASS"]);
  const appliedIds = out.applied.map((e) => e.id);
  // 固件相关条目被注入
  assert.ok(appliedIds.includes("MEM-PATTERN-BOF-01"));
  // Web/Java 遗产（无固件 tag）一律不注入
  assert.ok(!appliedIds.includes("MEM-PATTERN-JNDI-INJECTION"));
  assert.ok(!appliedIds.includes("MEM-META-E2E-EXPLOITABILITY"));
  assert.ok(!appliedIds.includes("_HEADER"));
  assert.ok(out.skippedNonFirmware > 0);
  // 门控函数行为
  assert.deepEqual(firmwareTags({ id: "MEM-PATTERN-BOF-01" }), ["BOF"]);
  assert.deepEqual(firmwareTags({ id: "MEM-PATTERN-PREAUTH-RCE-X" }), ["PREAUTH", "RCE"]);
  assert.deepEqual(firmwareTags({ id: "MEM-FAILURE-TUNNEL-VISION" }), []);
  assert.deepEqual(firmwareTags({ id: "x", tags: ["heap"] }), ["HEAP"]);
});
