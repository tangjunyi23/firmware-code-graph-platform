/**
 * events.js — SSE event stream between the agent and the caller.
 *
 * Managed Agents mapping: Events. Every session writes
 * sessions/<id>/events.sse in text/event-stream format and mirrors a
 * human-readable rendering to stdout. Event types follow the Console debug
 * panel: thinking / tool_call / tool_result / model_usage / text /
 * session_start / session_idle / session_end / error.
 */
import { createWriteStream } from "node:fs";

export class EventStream {
  constructor(filePath, { quiet = false } = {}) {
    this.filePath = filePath;
    this.stream = createWriteStream(filePath, { flags: "a" });
    this.quiet = quiet;
    this.seq = 0;
  }

  emit(type, data) {
    const payload = { seq: this.seq++, ts: new Date().toISOString(), ...data };
    this.stream.write(`event: ${type}\ndata: ${JSON.stringify(payload)}\n\n`);
    if (!this.quiet) this._print(type, payload);
  }

  _print(type, p) {
    const dim = (s) => `\x1b[2m${s}\x1b[0m`;
    switch (type) {
      case "thinking":
        process.stdout.write(dim(`[thinking] ${p.text}\n`));
        break;
      case "text":
        process.stdout.write(`\x1b[36m[agent]\x1b[0m ${p.text}\n`);
        break;
      case "tool_call":
        process.stdout.write(`\x1b[33m[tool]\x1b[0m ${p.name} ${truncate(JSON.stringify(p.input), 200)}\n`);
        break;
      case "tool_result":
        process.stdout.write(dim(`[result] ${p.name} -> ${truncate(p.preview, 300)}\n`));
        break;
      case "model_usage":
        process.stdout.write(dim(`[usage] in=${p.input_tokens} out=${p.output_tokens} (session total in=${p.total_input} out=${p.total_output})\n`));
        break;
      case "session_start":
        process.stdout.write(`\x1b[32m[session ${p.session_id}]\x1b[0m task: ${p.task}\n`);
        break;
      case "session_idle":
        process.stdout.write(`\x1b[32m[session ${p.session_id} idle]\x1b[0m ${p.reason}\n`);
        break;
      case "session_end":
        process.stdout.write(`\x1b[32m[session ${p.session_id} done]\x1b[0m ${p.summary ?? ""}\n`);
        break;
      case "error":
        process.stdout.write(`\x1b[31m[error]\x1b[0m ${p.message}\n`);
        break;
      default:
        process.stdout.write(`[${type}] ${JSON.stringify(p)}\n`);
    }
  }

  close() {
    this.stream.end();
  }
}

export function truncate(s, n) {
  s = String(s ?? "");
  return s.length > n ? s.slice(0, n) + `…(+${s.length - n} chars)` : s;
}
