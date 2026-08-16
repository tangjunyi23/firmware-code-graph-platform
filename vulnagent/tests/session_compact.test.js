/**
 * P1 会话历史压缩（compactHistory）单测：
 *  - 超阈值的旧 tool_result 被替换为首尾摘录占位
 *  - 最近 keepRecent 条消息不动；首条任务消息不动
 *  - 幂等（已压缩的不再压）；tool_use_id → 工具名映射进占位文本
 */
import test from "node:test";
import assert from "node:assert/strict";
import { compactHistory } from "../src/session.js";

function bigText(n) {
  return "X".repeat(n);
}

function makeMessages() {
  return [
    { role: "user", content: "任务：挖掘漏洞" },
    { role: "assistant", content: [
      { type: "tool_use", id: "t1", name: "fw_attack_surface", input: {} },
    ] },
    { role: "user", content: [
      { type: "tool_result", tool_use_id: "t1",
        content: [{ type: "text", text: `HEAD-${bigText(5000)}-TAIL` }] },
    ] },
    { role: "assistant", content: [
      { type: "tool_use", id: "t2", name: "fw_get_function_source", input: {} },
    ] },
    { role: "user", content: [
      { type: "tool_result", tool_use_id: "t2",
        content: [{ type: "text", text: "small result" }] },
    ] },
    { role: "assistant", content: [{ type: "text", text: "继续" }] },
    { role: "user", content: [{ type: "text", text: "recent" }] },
  ];
}

test("compactHistory archives old oversized tool results", () => {
  const messages = makeMessages();
  const n = compactHistory(messages, { threshold: 1200, keepRecent: 2 });
  assert.equal(n, 1);
  const part = messages[2].content[0].content[0];
  assert.ok(part.text.startsWith("[已归档] fw_attack_surface"));
  assert.ok(part.text.includes("HEAD-"));
  assert.ok(part.text.includes("-TAIL"));
  assert.ok(part.text.length < 1200);
  // 幂等
  assert.equal(compactHistory(messages, { threshold: 1200, keepRecent: 2 }), 0);
});

test("compactHistory keeps recent messages and the task untouched", () => {
  const messages = makeMessages();
  // keepRecent 大于历史长度 → 什么都不压
  assert.equal(compactHistory(messages, { threshold: 100, keepRecent: 99 }), 0);
  // 阈值大于一切 → 什么都不压
  assert.equal(compactHistory(messages, { threshold: 999999, keepRecent: 0 }), 0);
  assert.equal(messages[0].content, "任务：挖掘漏洞");
  // 小结果从未被压
  assert.equal(messages[4].content[0].content[0].text, "small result");
});
