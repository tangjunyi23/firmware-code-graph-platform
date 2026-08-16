/**
 * playbook.js — memory-driven six-phase vulnerability hunt (整合自
 * xiaomin_codex 的 vuln-hunt-memory-driven skill，固化为 vulnagent 的
 * 内置打法).
 *
 * Round loop (fixed order, no skipping):
 *   Phase 1  attack-surface lock   (fw_get_identification / fw_list_surfaces)
 *   Phase 2  hunting per P0 surface (strategy file + tagged memory)
 *   Phase 3  verification          (evidence re-check; dropped findings are
 *            PATCHed status=retracted on the server, verified ones status=verified)
 *   Phase 4  adversarial challenge (independent session — never inherits
 *            phase 1-3 reasoning bias; verdict taken from the LAST line,
 *            exactly `overall_verdict: PASS`, anything else is LOOP)
 *   LOOP -> round N+1, PASS -> Phase 5 reporting
 *   Phase 5  reporting             (FINAL.md per references/phase5_reporting.md,
 *            generated for PASS and LOOP terminations alike; LOOP reports are
 *            prominently marked 未经对抗验证通过 and the round's findings get a
 *            server-side note saying so)
 *
 * Memory feedback: PASS raises every applied insight's confidence by +0.05,
 * LOOP lowers it by -0.05, clamped to [0.1, 0.95], written back to
 * memory/insights.jsonl (L6: only firmware-tagged entries are ever injected).
 *
 * Each phase runs as its own Session (fresh context); the driver owns all
 * artifact files under sessions/hunt-<ts>/ because agent tools are
 * read-only by design.
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";
import { Session } from "./session.js";

const PLAYBOOK_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1")), "../playbooks/vuln-hunt");
const MEMORY_FILE = path.resolve(PLAYBOOK_DIR, "../../memory/insights.jsonl");

// vuln type -> strategy file + memory tags (from the skill's mapping table)
const STRATEGY_MAP = [
  [/sql\s*注入|sqli/i, "sqli", ["SQLI"], []],
  [/缓冲区溢出|栈溢出|堆溢出|bof/i, "bof", ["BOF"], ["INTOV", "MEMOV"]],
  [/整数溢出|intov/i, "intov", ["INTOV"], ["BOF", "MEMOV"]],
  [/认证绕过|authbypass/i, "authbypass", ["AUTHBYPASS"], ["SQLI"]],
  [/命令注入|cmdi/i, "cmdi", ["CMDI"], []],
  [/格式化字符串|fmtstr/i, "fmtstr", ["FMTSTR"], ["BOF", "MEMOV"]],
  [/路径穿越|pathtrv/i, "pathtrv", ["PATHTRV"], ["FILEREAD", "FILEWRITE"]],
  [/文件读取|fileread/i, "fileread", ["FILEREAD"], ["PATHTRV"]],
  [/文件写入|filewrite/i, "filewrite", ["FILEWRITE"], ["PATHTRV", "UPLOAD"]],
  [/文件上传|upload/i, "upload", ["UPLOAD"], ["PATHTRV", "FILEWRITE"]],
  [/反序列化|deser/i, "deser", ["DESER"], []],
  [/内存溢出|memov/i, "memov", ["MEMOV"], ["BOF", "INTOV"]],
  [/拒绝服务|dos/i, "dos", ["DOS"], ["INTOV", "DIVZERO", "ABUSE"]],
  [/会话管理|session/i, "session", ["SESSION"], ["AUTHBYPASS"]],
  [/密码学|TLS|证书|crypto/i, "crypto", ["CRYPTO"], ["TLS", "BOF", "INTOV"]],
  [/业务逻辑|滥用|abuse/i, "abuse", ["ABUSE"], ["DOS"]],
  // default: 预认证广谱模式 (preauth) — always appended last as fallback
  [/./, "preauth_rce",
   ["PREAUTH", "RCE", "AUTHBYPASS"],
   ["BOF", "FMTSTR", "CMDI", "MEMOV", "INTOV", "PATHTRV", "FILEWRITE",
    "FILEREAD", "ARCH", "SQLI", "DESER", "INJECT"]],
];

// 固件域 tag 白名单（L6）：insights.jsonl 里混入大量 Web/Java 源码审计遗产，
// 只有携带固件相关 tag 的条目才注入 prompt。词表与 STRATEGY_MAP 的记忆 tag
// 一致，另加 IDA（反编译经验）与 HEAP（堆操作模式）。
const FIRMWARE_TAGS = new Set([
  "SQLI", "BOF", "INTOV", "AUTHBYPASS", "CMDI", "FMTSTR", "PATHTRV",
  "FILEREAD", "FILEWRITE", "UPLOAD", "DESER", "MEMOV", "DOS", "DIVZERO",
  "SESSION", "CRYPTO", "TLS", "ABUSE", "PREAUTH", "RCE", "ARCH", "INJECT",
  "IDA", "HEAP",
]);

function firmwareTagsOf(entry) {
  const tokens = String(entry.id ?? "").split(/[^A-Za-z0-9]+/)
    .map((t) => t.toUpperCase());
  const fromTags = (Array.isArray(entry.tags) ? entry.tags : [])
    .map((t) => String(t).toUpperCase());
  return tokens.concat(fromTags).filter((t) => FIRMWARE_TAGS.has(t));
}

function resolveStrategy(vulnType) {
  for (const [rx, file, main, extra] of STRATEGY_MAP) {
    if (rx.test(vulnType ?? "")) return { file, tags: [...main, ...extra] };
  }
  return STRATEGY_MAP.at(-1);
}

function loadRef(rel) {
  const p = path.join(PLAYBOOK_DIR, "references", rel);
  return existsSync(p) ? readFileSync(p, "utf8") : "";
}

export function loadMemory(tags, memoryFile = MEMORY_FILE) {
  if (!existsSync(memoryFile)) return { applied: [], skipped: [], skippedNonFirmware: 0 };
  const applied = [];
  const skipped = [];
  let skippedNonFirmware = 0;
  for (const line of readFileSync(memoryFile, "utf8").split("\n")) {
    if (!line.trim()) continue;
    let entry;
    try { entry = JSON.parse(line); } catch { continue; }
    // 固件域门控（L6）：无固件 tag 的遗留条目（Web/源码审计遗产）不注入 prompt
    if (!firmwareTagsOf(entry).length) { skippedNonFirmware++; continue; }
    const type = entry.type ?? "";
    const always = type === "meta_rule" || type === "failure_pattern";
    const tagged = tags.some((t) => (entry.id ?? "").includes(t));
    if (always || tagged) applied.push(entry);
    else skipped.push(entry.id ?? "?");
  }
  return { applied, skipped, skippedNonFirmware };
}

/** 固件域 tag 白名单命中情况（导出供单测/审计）。 */
export function firmwareTags(entry) {
  return firmwareTagsOf(entry);
}

export function clampConfidence(c) {
  return Math.round(Math.min(0.95, Math.max(0.1, c)) * 100) / 100;
}

/**
 * 记忆反馈循环（原来 loadMemory 只读不写）：把本轮命中的 insight 的
 * confidence 调整 delta（PASS +0.05 / LOOP -0.05），clamp [0.1, 0.95]，
 * 原子写回 insights.jsonl。未命中的条目原行保留，避免无关churn。
 */
export function writebackMemory(appliedIds, delta, memoryFile = MEMORY_FILE) {
  if (!existsSync(memoryFile) || !appliedIds.length) return { updated: 0 };
  const ids = new Set(appliedIds);
  let updated = 0;
  const out = [];
  for (const line of readFileSync(memoryFile, "utf8").split("\n")) {
    if (!line.trim()) { out.push(line); continue; }
    let entry;
    try { entry = JSON.parse(line); } catch { out.push(line); continue; }
    if (ids.has(entry.id) && Number.isFinite(entry.confidence)) {
      entry.confidence = clampConfidence(entry.confidence + delta);
      out.push(JSON.stringify(entry));
      updated++;
    } else {
      out.push(line);
    }
  }
  const tmp = `${memoryFile}.tmp`;
  writeFileSync(tmp, out.join("\n"), "utf8");
  renameSync(tmp, memoryFile);
  return { updated };
}

/**
 * PATCH /vulnagent/findings/{fid}（服务端契约：body {status?, note?}，
 * status ∈ draft|verified|disputed|retracted）。永不抛出——服务端未就绪
 * （404）或校验失败时返回 {ok:false,error}，由调用方记日志后继续，
 * 不让状态回写失败拖垮整个 hunt。
 */
export async function patchFinding(config, fid, body, fetchImpl = fetch) {
  if (!/^F-[A-Za-z0-9][A-Za-z0-9-]*$/.test(fid ?? "")) {
    return { ok: false, error: `bad finding id ${JSON.stringify(fid)}` };
  }
  const { baseUrl, token } = config.fwgraph;
  try {
    const resp = await fetchImpl(`${baseUrl}/vulnagent/findings/${encodeURIComponent(fid)}`, {
      method: "PATCH",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const text = await resp.text();
    if (!resp.ok) return { ok: false, error: `HTTP ${resp.status}: ${text.slice(0, 300)}` };
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

/** 解析 Phase 3 输出末尾的 {"verified":[...],"dropped":[...],"notes":"..."} JSON。 */
export function parsePhase3Json(text) {
  const candidates = String(text ?? "").match(/\{[^{}]*\}/g) ?? [];
  for (let i = candidates.length - 1; i >= 0; i--) {
    try {
      const obj = JSON.parse(candidates[i]);
      if (Array.isArray(obj.verified) || Array.isArray(obj.dropped)) {
        return {
          verified: (obj.verified ?? []).filter((x) => typeof x === "string"),
          dropped: (obj.dropped ?? []).filter((x) => typeof x === "string"),
          notes: typeof obj.notes === "string" ? obj.notes : "",
        };
      }
    } catch { /* not a JSON object */ }
  }
  return null;
}

/**
 * Phase 4 verdict：取输出最后一行精确匹配 `overall_verdict: PASS`（原来用
 * 全文正则，正文里提到该字样就会误判 PASS）。最后一行不是严格 PASS 即 LOOP。
 */
export function extractVerdict(text) {
  const lines = String(text ?? "").trim().split(/\r?\n/);
  const last = (lines.at(-1) ?? "").trim();
  return last === "overall_verdict: PASS" ? "PASS" : "LOOP";
}

function memoryText(entries, cap = 60) {
  const lines = entries.slice(0, cap).map((e) =>
    `- [${e.id}] (${e.type}) ${e.content}`);
  return lines.join("\n");
}

function writeArtifact(dir, name, text) {
  writeFileSync(path.join(dir, name), text, "utf8");
}

async function runPhase({ config, agent, environment, task, quiet, maxTurns, label, mode }) {
  const session = Session.create({ config, agent, environment, task, quiet, mode });
  const result = await session.run({ maxTurns });
  const texts = session.messages
    .filter((m) => m.role === "assistant")
    .flatMap((m) => m.content)
    .filter((b) => b.type === "text" && b.text)
    .map((b) => b.text);
  return { session, texts, result, label };
}

function lastText(phase) {
  return phase.texts.at(-1) ?? "";
}

function loadFindingRecords(config, ids) {
  const out = [];
  for (const fid of ids) {
    try {
      out.push(JSON.parse(readFileSync(path.join(config.dirs.findings, `${fid}.json`), "utf8")));
    } catch { /* finding cache missing — skip */ }
  }
  return out;
}

const REACH_LABEL = {
  verified: "CONFIRMED",
  observed: "EXPLOITABILITY_CONDITIONAL",
  "static-only": "EXPLOITABILITY_CONDITIONAL",
};
const SEV_LABEL = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "提示" };

/**
 * Phase 5 reporting（references/phase5_reporting.md 的 FINAL.md 模板，
 * driver 侧确定性生成，PASS/LOOP 终局都产出）。代码片段级逐跳分析依赖
 * finding 的 evidence 字段（记录时要求摘录伪代码原行）；evidence 不足时
 * 章节如实标注缺口，不编造。
 */
export function writeFinalReport({ dir, snapshot, vulnType, findings, retracted, attackSurfaceText }) {
  const verdict = snapshot.verdict ?? "LOOP";
  const lines = ["# 漏洞挖掘报告", ""];
  if (verdict !== "PASS") {
    lines.push(
      "> ⚠️ **未经对抗验证通过**：本次挖掘在达到最大对抗轮数后以 LOOP 终局，",
      "> 以下结论未通过 Phase 4 对抗性验证，可靠性存疑，进入生产结论前必须人工复核。",
      "");
  }
  lines.push("## 漏洞概要", "");
  lines.push(`- 挖掘目标: ${vulnType}`);
  lines.push(`- 固件任务: ${snapshot.job_id ?? "?"}`);
  lines.push(`- 对抗轮次: ${snapshot.rounds.length}（终局 verdict: ${verdict}）`);
  lines.push(`- 确认漏洞: ${findings.length} 个`, "");
  for (const [i, f] of findings.entries()) {
    lines.push(`### 漏洞 ${i + 1}：${f.title}（${f.id}）`, "");
    lines.push(`- 漏洞类型: ${f.vuln_class}${f.cwe ? `（${f.cwe}）` : ""}`);
    lines.push(`- 漏洞函数: ${f.function_name ?? "?"}（\`${f.function_addr ?? "?"}\`）`);
    lines.push(`- 危害等级: ${SEV_LABEL[f.severity] ?? f.severity}（置信度 ${f.confidence}）`);
    lines.push(`- 可达性: ${f.reachability ?? "static-only"}`);
    lines.push(`- Exploitability: ${REACH_LABEL[f.reachability] ?? "EXPLOITABILITY_CONDITIONAL"}`);
    lines.push(`- 影响组件: ${f.binary_path ?? f.binary_md5}（md5: ${f.binary_md5}）`);
    lines.push(`- 认证前提: ${f.preconditions ?? "见详细分析触发条件"}`);
    lines.push(`- 影响: ${f.summary}`, "");
  }

  lines.push("## 认证管线分析", "");
  const authLines = String(attackSurfaceText ?? "").split(/\r?\n/)
    .filter((l) => /auth|认证|授权|鉴权/i.test(l)).slice(0, 40);
  if (authLines.length) {
    lines.push("> 摘自 Phase 1 attack-surface.md（授权链相关行）：", "");
    lines.push("```", ...authLines, "```", "");
  } else {
    lines.push("Phase 1 未产出显式授权链分析；预认证判定详见 attack-surface.md 与各 finding 证据。", "");
  }

  lines.push("## 详细分析", "");
  for (const [i, f] of findings.entries()) {
    lines.push(`### 漏洞 ${i + 1}：${f.title}（${f.id}）`, "");
    lines.push("#### Source（输入源）", "");
    lines.push(f.source_summary ?? "（finding 未记录 source_summary；入口信息见证据条目）", "");
    lines.push("#### 完整数据流（Source → Sink 证据链）", "");
    lines.push("> 记录时要求 evidence 摘录伪代码原行；以下为该 finding 的全部证据条目：", "");
    for (const [j, e] of (f.evidence ?? []).entries()) lines.push(`${j + 1}. ${e}`);
    lines.push("");
    lines.push("#### Sink（危险操作）", "");
    lines.push(`- 漏洞函数: ${f.function_name ?? "?"}（\`${f.function_addr ?? "?"}\`，${f.binary_path ?? f.binary_md5}）`);
    if (f.sink_function) lines.push(`- 危险调用: ${f.sink_function}`);
    lines.push(`- 根因: ${f.summary}`, "");
    if (f.sanitization) lines.push("#### 安全检查与绕过分析", "", f.sanitization, "");
    lines.push("#### 触发条件", "", f.preconditions ?? "（未单独记录；见证据与利用思路）", "");
    if (f.exploit_sketch) lines.push("#### PoC 概念", "", "```", f.exploit_sketch, "```", "");
    if (f.remediation) lines.push("#### 修复建议", "", f.remediation, "");
  }

  lines.push("## 排除的候选漏洞", "");
  if (!retracted.length) {
    lines.push("本轮无被 Phase 3 剔除的候选。", "");
  } else {
    for (const r of retracted) {
      lines.push(`### 排除候选: ${r.id}`, "");
      lines.push(`- **排除原因**: ${r.note || "Phase 3 证据复核不通过"}`);
      if (r.title) lines.push(`- **候选标题**: ${r.title}`);
      lines.push("");
    }
  }

  lines.push("---", "");
  lines.push(`报告生成: hunt ${snapshot.hunt_id}，${new Date().toISOString()}，由 vulnagent playbook driver 按 phase5_reporting.md 模板生成。`);
  writeArtifact(dir, "FINAL.md", lines.join("\n"));
}

/**
 * Drive a full memory-driven hunt. Returns the hunt directory with all
 * artifacts (attack-surface.md, phase2_*.md, vuln_hunt_output.md,
 * challenge_verdict*, context_snapshot.json, FINAL.md, report via sessions).
 */
export async function runHunt({
  config, agent, environment, vulnType = "预认证漏洞",
  maxRounds = 3, maxTurns = 40, quiet = false, mode = "dynamic",
}) {
  const huntId = `hunt-${Date.now().toString(36)}`;
  const dir = path.join(config.dirs.sessions, huntId);
  mkdirSync(dir, { recursive: true });

  const strategy = resolveStrategy(vulnType);
  const memory = loadMemory(strategy.tags);
  const strategyText = loadRef(`strategies/${strategy.file}.md`);
  const jobId = config.fwgraph.defaultJobId;

  const log = [];
  const say = (s) => { log.push(s); if (!quiet) console.error(s); };
  say(`[hunt ${huntId}] vulnType=${vulnType} strategy=${strategy.file} mode=${mode} `
      + `memory=${memory.applied.length} applied/${memory.skipped.length} skipped`
      + `/${memory.skippedNonFirmware} non-firmware filtered`);

  const snapshot = {
    hunt_id: huntId, vuln_type: vulnType, job_id: jobId, mode,
    rounds: [], verdict: null,
  };

  for (let round = 1; round <= maxRounds; round++) {
    say(`[hunt] round ${round}/${maxRounds} phase1: attack-surface lock`);
    const p1task = [
      `你是漏洞挖掘流水线的 Phase 1 worker（攻击面锁定）。目标固件 job: ${jobId}。`,
      `漏洞类型: ${vulnType}。`,
      `必须先用 fw_get_identification 拉取全部外部输入（IN-xxx），再用 fw_list_surfaces 获取每个输入的攻击面文档（AS-xxx），不得遗漏任何输入。`,
      vulnType && /预认证|preauth|认证前/i.test(vulnType)
        ? "预认证类目标：额外关注各 AS 文档的 auth_chain_refs 与 AS-AUTH 授权链文档，标注哪些面在授权链之前（预认证可达）。"
        : "",
      "输出：按优先级列出 P0/P1 攻击面（surface_id、service、entry、final_handler、关键 carrier_bindings、理由），最后给出 JSON 摘要 {\"p0\":[...],\"p1\":[...]}。",
      "",
      "参考方法论：", loadRef("phase1_attack_surface.md").slice(0, 6000),
    ].filter(Boolean).join("\n");
    const p1 = await runPhase({ config, agent, environment, task: p1task, quiet, maxTurns, label: "phase1", mode });
    writeArtifact(dir, "attack-surface.md", lastText(p1));

    say(`[hunt] round ${round} phase2: hunting (${strategy.file})`);
    const memTxt = memoryText(memory.applied);
    const p2task = [
      `你是漏洞挖掘 Phase 2 worker。目标固件 job: ${jobId}，漏洞类型: ${vulnType}。`,
      `攻击面清单（Phase 1 结论）:\n${lastText(p1).slice(0, 8000)}`,
      `打法策略:\n${strategyText.slice(0, 6000)}`,
      memTxt ? `记忆库（历史模式/失败教训）:\n${memTxt.slice(0, 5000)}` : "",
      "逐个 P0 面深挖：用 fw_get_surface 取路由/载体绑定，fw_get_function_source 看伪代码，fw_attack_surface 看 source→sink 路径，必要时 fw_request_trace 做动态验证（预算内）。",
      "确认一个漏洞就立即 record_finding（中文，证据具体；cwe 必填且严格单个 CWE-<数字>，vuln_class 单一类别，observed/verified 必须带 trace_id）。全部完成后用 finish 汇报。",
      "",
      "参考方法论：", loadRef("phase2_hunting.md").slice(0, 4000),
    ].filter(Boolean).join("\n");
    const p2 = await runPhase({ config, agent, environment, task: p2task, quiet, maxTurns, label: "phase2", mode });
    writeArtifact(dir, `phase2_round${round}.md`, lastText(p2));

    say(`[hunt] round ${round} phase3: verification`);
    const findingsDir = config.dirs.findings;
    const findingIds = existsSync(findingsDir)
      ? readdirSync(findingsDir).filter((f) => f.endsWith(".json"))
      : [];
    const p3task = [
      `你是漏洞挖掘 Phase 3 worker（验证）。目标固件 job: ${jobId}。`,
      `已记录 findings: ${findingIds.join(", ") || "（无）"}。`,
      "逐条复核证据：函数地址是否存在、载体绑定是否成立、路径是否真的可达（fw_get_function_source / fw_call_trace / fw_get_surface）。剔除证据不足的，把 verify 结论写进输出。",
      "最后输出 JSON: {\"verified\":[\"F-...\"],\"dropped\":[\"F-...\"],\"notes\":\"...\"}",
      "",
      "参考方法论：", loadRef("phase3_verification.md").slice(0, 4000),
    ].filter(Boolean).join("\n");
    const p3 = await runPhase({ config, agent, environment, task: p3task, quiet, maxTurns, label: "phase3", mode });
    writeArtifact(dir, "vuln_hunt_output.md", lastText(p3));

    // Phase 3 结论落库（原来是纯文本 writeArtifact，dropped 永不反映到数据层）：
    // dropped → status=retracted（note 带剔除理由），verified → status=verified。
    const p3out = parsePhase3Json(lastText(p3));
    const retracted = [];
    if (p3out) {
      for (const fid of p3out.dropped) {
        const note = `Phase3 剔除：${p3out.notes || "证据复核不通过"}`;
        const r = await patchFinding(config, fid, { status: "retracted", note });
        if (r.ok) retracted.push({ id: fid, note: p3out.notes || "证据复核不通过" });
        else say(`[hunt] PATCH ${fid} retracted failed: ${r.error}`);
      }
      for (const fid of p3out.verified) {
        const r = await patchFinding(config, fid, { status: "verified", note: "Phase3 证据复核通过" });
        if (!r.ok) say(`[hunt] PATCH ${fid} verified failed: ${r.error}`);
      }
    } else {
      say("[hunt] phase3 output had no parseable verdict JSON — finding status writeback skipped");
    }

    say(`[hunt] round ${round} phase4: adversarial challenge`);
    const p4task = [
      "你是独立的对抗性 Challenge agent，未参与前面的分析，不带偏见。",
      `目标固件 job: ${jobId}。`,
      `攻击面结论:\n${lastText(p1).slice(0, 5000)}`,
      `漏洞结论:\n${lastText(p3).slice(0, 5000)}`,
      "质疑一切：每条 finding 的证据链是否闭合？载体是否用户可控？授权链是否真的在其之后？有没有漏掉的输入面？用 fw 工具独立抽查。",
      "最后一行必须是 overall_verdict: PASS 或 overall_verdict: LOOP（LOOP 时列出遗漏点）。",
      "",
      "参考方法论：", loadRef("phase4_challenge.md").slice(0, 4000),
    ].filter(Boolean).join("\n");
    const p4 = await runPhase({ config, agent, environment, task: p4task, quiet, maxTurns, label: "phase4", mode });
    writeArtifact(dir, `challenge_verdict_round${round}.md`, lastText(p4));

    const verdict = extractVerdict(lastText(p4));
    snapshot.rounds.push({
      round, phase1_session: p1.session.id, phase2_session: p2.session.id,
      phase3_session: p3.session.id, phase4_session: p4.session.id, verdict,
      findings: [...new Set([...p2.result.findings, ...p3.result.findings])],
      verified: p3out?.verified ?? [],
      retracted,
    });
    snapshot.verdict = verdict;
    writeArtifact(dir, "context_snapshot.json", JSON.stringify(snapshot, null, 2));
    say(`[hunt] round ${round} verdict=${verdict}`);
    if (verdict === "PASS") break;
  }

  // 记忆反馈循环：PASS 本轮命中的 insight +0.05，LOOP -0.05，clamp [0.1,0.95]
  const appliedIds = memory.applied.map((e) => e.id).filter(Boolean);
  const mw = writebackMemory(appliedIds, snapshot.verdict === "PASS" ? 0.05 : -0.05);
  say(`[hunt] memory writeback: ${mw.updated}/${appliedIds.length} insights ${snapshot.verdict === "PASS" ? "+0.05" : "-0.05"}`);

  // LOOP 终局（达到 maxRounds 仍未 PASS，原来无条件放行）：本轮 findings
  // 全部 PATCH note「未经对抗验证通过」，最终报告显著标注。
  if (snapshot.verdict !== "PASS") {
    const lastRound = snapshot.rounds.at(-1);
    const ids = [...new Set([...(lastRound?.findings ?? []), ...(lastRound?.verified ?? [])])];
    for (const fid of ids) {
      const r = await patchFinding(config, fid, { note: "未经对抗验证通过（达到最大对抗轮数，LOOP 终局）" });
      if (!r.ok) say(`[hunt] PATCH ${fid} loop-note failed: ${r.error}`);
    }
    if (ids.length) say(`[hunt] LOOP termination: ${ids.length} finding(s) marked 未经对抗验证通过`);
  }

  // Phase 5 reporting：PASS/LOOP 终局都产出 FINAL.md
  const allFindingIds = [...new Set(snapshot.rounds.flatMap((r) => r.findings ?? []))];
  const findings = loadFindingRecords(config, allFindingIds);
  const retractedAll = snapshot.rounds.flatMap((r) => r.retracted ?? []);
  const attackSurfaceText = existsSync(path.join(dir, "attack-surface.md"))
    ? readFileSync(path.join(dir, "attack-surface.md"), "utf8") : "";
  writeFinalReport({ dir, snapshot, vulnType, findings, retracted: retractedAll, attackSurfaceText });
  say(`[hunt] FINAL.md written (${findings.length} findings, ${retractedAll.length} retracted)`);

  writeArtifact(dir, "hunt.log", log.join("\n"));
  return { huntId, dir, verdict: snapshot.verdict, snapshot };
}
