/**
 * dsh_engine.js — run a vuln-mining task through DeepSeek Harness (dsh)
 * instead of the built-in zero-dep agent loop.
 *
 * The fwgraph profile (vulnagent/dsh/setup.sh) composes dsh-base +
 * dsh-headless + @fwgraph/dsh-fwgraph-tools; the task positional is parsed
 * by the headless bundle and the final assistant message lands on stdout.
 *
 * Session wiring: local runs generate an FWGRAPH_SESSION_ID and point
 * FWGRAPH_EVENTS_FILE at vulnagent/sessions/<id>/events.sse so the webui
 * renders dsh sessions like built-in ones; when the orchestrator launches
 * dsh itself it injects both variables and our values stay unset
 * (process.env wins). The dsh record_finding tool attaches that same
 * session_id when POSTing to the server-side findings API (H3).
 */
import { mkdirSync } from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

export async function runDshTask({ config, task, quiet = false, cwd, mode }) {
  const repo = process.env.DSH_REPO
    ?? path.join(process.env.HOME ?? "", "deepseek-harness");
  const sessionId = process.env.FWGRAPH_SESSION_ID ?? `dsh-${Date.now().toString(36)}`;
  const sessionDir = path.join(config.dirs.sessions, sessionId);
  mkdirSync(sessionDir, { recursive: true });
  const env = {
    ...process.env,
    // llm-deepseek adapter: any OpenAI chat-completions gateway
    DEEPSEEK_API_KEY: config.llm.apiKey,
    // dsh llm-deepseek（messages 协议）自行拼 /v1/messages；LLM_BASE_URL 的尾部 /v1 剥掉
    DEEPSEEK_BASE_URL: String(config.llm.baseUrl || "").replace(/\/+$/, "").replace(/\/v1$/, ""),
    FWGRAPH_BASE_URL: config.fwgraph.baseUrl,
    FWGRAPH_TOKEN: config.fwgraph.token,
    FWGRAPH_JOB_ID: config.fwgraph.defaultJobId ?? "",
    FWGRAPH_FINDINGS_DIR: config.dirs.findings,
    // 静态/动态模式透传：static 时 dsh 插件不注册动态类工具
    FWGRAPH_MODE: mode ?? process.env.FWGRAPH_MODE ?? "dynamic",
    // fw_browse_firmware 的只读根（<root>/<job_id>/）
    FWGRAPH_EXTRACTED_ROOT: config.fwgraph.extractedRoot,
    // 归属与事件流（orchestrator 注入时 process.env 已带，值不变）
    FWGRAPH_SESSION_ID: sessionId,
    FWGRAPH_EVENTS_FILE: process.env.FWGRAPH_EVENTS_FILE ?? path.join(sessionDir, "events.sse"),
    FWGRAPH_TASK: task,
    // Code Mode 的 run_code 属于代码执行通道，本 profile 一律 native
    DSH_TOOLS_MODE: "native",
  };
  const args = [
    "--import", "tsx/esm",
    "apps/cli/src/bin.ts",
    "--profile", "fwgraph",
    task,
  ];
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, {
      cwd: cwd ?? repo, env, stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => {
      out += d;
      if (!quiet) process.stdout.write(d);
    });
    child.stderr.on("data", (d) => {
      err += d;
      if (!quiet) process.stderr.write(d);
    });
    child.on("error", reject);
    child.on("close", (code) => resolve({ output: out, error: err, exitCode: code, sessionId }));
  });
}
