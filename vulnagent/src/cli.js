#!/usr/bin/env node
/**
 * cli.js — local runner for the Managed Agents harness.
 *
 *   node src/cli.js info                          show agent + environment manifests
 *   node src/cli.js run "task" [--max-turns N] [--session NAME] [--quiet]
 *   node src/cli.js hunt ["漏洞类型"] [--rounds N] [--max-turns N] [--mode static|dynamic] [--quiet]
 *   node src/cli.js resume <session_id> [--max-turns N] [--quiet]
 *   node src/cli.js list                          list sessions
 *   node src/cli.js events <session_id>           replay the SSE event log
 *
 * Mirrors the Console flow: agent.json/environment.json are the "created once"
 * manifests; `run` starts a Session (Agent + Environment) and streams Events.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { loadConfig, loadManifest } from "./config.js";
import { Session } from "./session.js";

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      if (key === "quiet") args.quiet = true;
      else args[key] = argv[++i];
    } else {
      args._.push(a);
    }
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args._[0];
  const config = loadConfig();

  if (cmd === "info") {
    const agent = loadManifest("agent.json");
    const environment = loadManifest("environment.json");
    console.log(JSON.stringify({ agent: { ...agent, system_prompt: `<${agent.system_prompt.length} chars>` }, environment }, null, 2));
    return;
  }

  if (cmd === "list") {
    if (!existsSync(config.dirs.sessions)) return console.log("(no sessions)");
    for (const id of readdirSync(config.dirs.sessions)) {
      const stateFile = path.join(config.dirs.sessions, id, "state.json");
      if (!existsSync(stateFile)) continue;
      const s = JSON.parse(readFileSync(stateFile, "utf8"));
      console.log(`${s.session_id}  ${s.status.padEnd(8)}  turns=${String(s.turns).padEnd(3)} findings=${(s.findings ?? []).length}  ${s.task.slice(0, 70)}`);
    }
    return;
  }

  if (cmd === "events") {
    const file = path.join(config.dirs.sessions, args._[1] ?? "", "events.sse");
    if (!existsSync(file)) throw new Error(`no events for session ${args._[1]}`);
    process.stdout.write(readFileSync(file, "utf8"));
    return;
  }

  if (cmd === "hunt") {
    const agent = loadManifest("agent.json");
    const environment = loadManifest("environment.json");
    if (!config.fwgraph.token) throw new Error("FWGRAPH_TOKEN is empty (check .env)");
    if (!config.llm.apiKey) throw new Error("LLM_API_KEY is empty (check .env)");
    const { runHunt } = await import("./playbook.js");
    const vulnType = args._.slice(1).join(" ").trim() || "预认证漏洞";
    const mode = args.mode ?? "dynamic";
    if (!["static", "dynamic"].includes(mode)) throw new Error(`--mode must be static|dynamic, got ${JSON.stringify(args.mode)}`);
    const result = await runHunt({
      config, agent, environment, vulnType,
      maxRounds: Number(args.rounds ?? 3),
      maxTurns: Number(args["max-turns"] ?? 40),
      quiet: Boolean(args.quiet),
      mode,
    });
    console.log(`\nhunt=${result.huntId} verdict=${result.verdict}`);
    console.log(`artifacts: sessions/${result.huntId}/ (attack-surface.md, phase*.md, challenge_verdict*, context_snapshot.json, FINAL.md)`);
    return;
  }

  if (cmd === "run" || cmd === "resume") {
    const agent = loadManifest("agent.json");
    const environment = loadManifest("environment.json");
    if (!config.fwgraph.token) throw new Error("FWGRAPH_TOKEN is empty (check .env)");
    if (!config.llm.apiKey) throw new Error("LLM_API_KEY is empty (check .env)");
    const maxTurns = Number(args["max-turns"] ?? 40);
    const quiet = Boolean(args.quiet);

    let session;
    if (cmd === "run") {
      const task = args._.slice(1).join(" ").trim();
      if (!task) throw new Error('usage: node src/cli.js run "task text"');
      if ((args.engine ?? "") === "dsh") {
        // DeepSeek Harness engine (see dsh/setup.sh): task runs through the
        // fwgraph dsh profile; findings land on the server-side findings API.
        const { runDshTask } = await import("./dsh_engine.js");
        const r = await runDshTask({ config, task, quiet, mode: args.mode });
        console.log(`\ndsh exit=${r.exitCode}`);
        return;
      }
      session = Session.create({ config, agent, environment, task, sessionId: args.session, quiet, mode: args.mode });
    } else {
      const sessionId = args._[1];
      if (!sessionId) throw new Error("usage: node src/cli.js resume <session_id>");
      session = Session.resume({ config, agent, environment, sessionId, quiet });
    }
    const result = await session.run({ maxTurns });
    console.log(`\nsession=${result.sessionId} status=${result.state.status} findings=[${result.findings.join(", ")}]`);
    console.log(`report: sessions/${result.sessionId}/report.md`);
    return;
  }

  console.log("commands: info | run <task> | resume <id> | list | events <id>");
  process.exitCode = cmd ? 1 : 0;
}

main().catch((err) => {
  console.error(`fatal: ${err.message}`);
  process.exitCode = 1;
});
