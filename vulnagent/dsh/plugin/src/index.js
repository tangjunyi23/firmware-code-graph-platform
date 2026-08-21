/**
 * @fwgraph/dsh-fwgraph-tools — fwgraph read-only tools for DeepSeek Harness.
 *
 * Zero-dependency cordis plugin: registers plain ToolDefinition objects on
 * ctx.tools (no @deepseek-ai/* imports — the registry only requires that
 * `parameters` / `output.schema` are real JSON Schema), so the package
 * loads from any profile node_modules layout.
 *
 * Mode isolation / budget / whitelist (S1):
 *  - The profile's cordis.patch.yml disables dsh-base's generic shell /
 *    file / web / subagent tool rows (tool-bash, tool-fs, tool-web, ...).
 *  - apply() additionally registers a global ctx.tools.guard that denies
 *    those tool classes by name, so even a future dsh update that re-adds
 *    a row under another id cannot re-open shell/file-write/web access.
 *  - Dynamic tools keep per-session budgets (trace/fuzz/frida).
 *  - fw_browse_firmware is the ONLY filesystem access: read-only listing and
 *    small text reads jailed under <extractedRoot>/<job_id>/.
 *
 * Config (from the profile's cordis.patch.yml row):
 *   baseUrl        fwgraph orchestrator URL (http://127.0.0.1:8000)
 *   token          ORCH_TOKEN bearer
 *   jobId          default firmware job id
 *   sessionId      vulnagent session id stamped onto record_finding POSTs
 *   extractedRoot  firmware extraction root (data/extracted); fw_browse_firmware
 *                  is jailed under <extractedRoot>/<job_id>/
 *   findingsDir    legacy local findings dir (kept for compatibility; findings
 *                  now go to the server-side /vulnagent/findings API)
 *   mode           'dynamic' | 'static' (static drops the dynamic tools)
 */

import { promises as fsp } from 'node:fs'
import path from 'node:path'

export const name = 'fwgraph-tools'
export const inject = ['tools']

const MAX_RESULT = 16000
const MAX_TRACES_PER_SESSION = 5
const MAX_FUZZ_PER_SESSION = 3
const BROWSE_MAX_BYTES = 64 * 1024

// S1: tool classes that must never execute in this profile, regardless of
// how the dsh-base composition evolves. Denied by guard even if a row is
// accidentally re-enabled.
const BLOCKED_TOOLS = new Set([
  // shell / process execution
  'bash', 'pwsh', 'run_code', 'ralph', 'workflow',
  // generic filesystem read/write
  'read', 'write', 'edit', 'read_image', 'glob', 'grep', 'str_replace_editor',
  // web egress
  'web_search', 'web_fetch',
  // agent fan-out (unbudgeted LLM burn, bypasses the mining playbook)
  'subagent', 'subagent_fork', 'send_message', 'interrupt_agent', 'list_agents',
  // background job control (only meaningful next to a shell)
  'job_output', 'job_list', 'job_kill',
])

// fw_browse_firmware: text-file extension whitelist (binary rejected by
// extension; content is additionally NUL-scanned)
const TEXT_EXTENSIONS = new Set([
  '.txt', '.conf', '.cfg', '.ini', '.json', '.sh', '.bash', '.xml', '.html',
  '.htm', '.js', '.c', '.h', '.cpp', '.py', '.list', '.log', '.md', '.csv',
  '.yaml', '.yml', '.properties', '.cnf', '.service', '.rules',
])

async function fw(config, method, urlPath, body) {
  const resp = await fetch(config.baseUrl.replace(/\/+$/, '') + urlPath, {
    method,
    headers: {
      Authorization: `Bearer ${config.token}`,
      'Content-Type': 'application/json',
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(60_000),
  })
  const text = await resp.text()
  // 校验失败（422 等）把服务端 detail 原文抛给调用方，AI 能看到原因并修正
  if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${text.slice(0, 500)}`)
  try { return JSON.parse(text) } catch { return text }
}

function jobOf(config, input) {
  const jobId = input.job_id ?? config.jobId
  if (!jobId) throw new Error('job_id is required (no default job configured)')
  return jobId
}

function graphQuery(config, jobId, op, extra) {
  return fw(config, 'POST', '/graph/query', { job_id: jobId, op, ...extra })
}

const JOB_ID_PROP = {
  job_id: { type: 'string', description: 'Firmware job id; omit to use the configured default job' },
}

/** Build a plain JSON-Schema object for tool parameters. */
function params(properties, required = []) {
  return { type: 'object', properties, required, additionalProperties: false }
}

function jsonTool(def) {
  return {
    timeoutMs: 90_000,
    ...def,
    output: {
      schema: { type: 'object', additionalProperties: true, properties: {} },
      render: (_args, value) => [{
        type: 'text',
        text: typeof value === 'string'
          ? value.slice(0, MAX_RESULT)
          : JSON.stringify(value, null, 1).slice(0, MAX_RESULT),
      }],
    },
  }
}

/**
 * record_finding 的本地预检，镜像服务端校验规则（服务端仍是权威）：
 * 明显违规本地直接报中文错，省一次 HTTP 往返。
 */
function precheckFinding(args) {
  const required = ['title', 'severity', 'confidence', 'vuln_class', 'cwe',
    'binary_md5', 'binary_path', 'reachability', 'summary', 'evidence']
  const missing = required.filter((k) => args[k] === undefined || args[k] === null || args[k] === '')
  if (missing.length) throw new Error(`record_finding 缺必填字段: ${missing.join(', ')}`)
  if (!['critical', 'high', 'medium', 'low', 'info'].includes(args.severity)) {
    throw new Error(`severity 非法: ${JSON.stringify(args.severity)}（critical|high|medium|low|info）`)
  }
  if (!['static-only', 'observed', 'verified'].includes(args.reachability)) {
    throw new Error(`reachability 非法: ${JSON.stringify(args.reachability)}（static-only|observed|verified）`)
  }
  const conf = Number(args.confidence)
  if (!Number.isFinite(conf) || conf < 0 || conf > 1) {
    throw new Error(`confidence 非法: ${JSON.stringify(args.confidence)}（0..1）`)
  }
  if (args.reachability === 'static-only' && conf > 0.7) {
    throw new Error(`confidence ${conf} 超过 static-only 锚点上限 0.7（服务端封顶；先补动态证据再提高置信度）`)
  }
  if (!/^CWE-\d+$/.test(String(args.cwe))) {
    throw new Error(`cwe 非法: ${JSON.stringify(args.cwe)}（严格单个 CWE-<数字>，如 CWE-121；禁止 "CWE-78 / CWE-121" 混填）`)
  }
  if (/[/，、]/.test(String(args.vuln_class))) {
    throw new Error(`vuln_class 非法: ${JSON.stringify(args.vuln_class)}（服务端拒收含 "/"，"、"，" 的混类；一类一条，分开记录）`)
  }
  if (!Array.isArray(args.evidence) || !args.evidence.length
    || args.evidence.some((e) => typeof e !== 'string' || !e.trim())) {
    throw new Error('evidence 必须是非空字符串数组')
  }
  if (args.reachability !== 'static-only' && !args.trace_id) {
    throw new Error(`reachability=${args.reachability} 必须带 trace_id（服务端会校验该 trace 存在）`)
  }
  return conf
}

/**
 * fw_browse_firmware 的执行体（导出以便离线单测）：只读列目录/读文本文件，
 * 根严格限定 <extractedRoot>/<job_id>/（realpath 后仍须在根内，防穿越与
 * 绝对 symlink 逃逸），单文件 64KB 上限，按扩展名白名单拒绝二进制。
 */
export async function browseFirmware(config, args) {
  const jobId = jobOf(config, args)
  // job_id 也参与拼路径，必须防穿越（否则根监禁形同虚设）
  if (!/^[A-Za-z0-9_-]+$/.test(jobId)) {
    throw new Error(`bad job_id ${JSON.stringify(jobId)}（只允许字母数字/-/_，禁止路径字符）`)
  }
  const extractedRoot = config.extractedRoot
    || path.join(config.findingsDir ?? '.', '..', '..', 'fwgraph', 'data', 'extracted')
  const rootReal = await fsp.realpath(path.resolve(extractedRoot, jobId))
    .catch(() => null)
  if (!rootReal) throw new Error(`firmware extraction root not found for job ${jobId}（${extractedRoot}/<job_id> 不存在）`)
  const rel = String(args.path ?? '').replace(/^[/\\]+/, '')
  const target = path.resolve(rootReal, rel)
  if (target !== rootReal && !target.startsWith(rootReal + path.sep)) {
    throw new Error(`path escapes the job extraction root: ${JSON.stringify(args.path)}`)
  }
  // realpath 再查一次：固件解包里常见 symlink（含绝对 symlink），必须防逃逸
  const targetReal = await fsp.realpath(target).catch(() => null)
  if (!targetReal) throw new Error(`path not found: ${JSON.stringify(args.path ?? '.')}`)
  if (targetReal !== rootReal && !targetReal.startsWith(rootReal + path.sep)) {
    throw new Error(`path escapes the job extraction root via symlink: ${JSON.stringify(args.path)}`)
  }
  const stat = await fsp.stat(targetReal)
  if (stat.isDirectory()) {
    const entries = await fsp.readdir(targetReal, { withFileTypes: true })
    return {
      job_id: jobId,
      path: path.relative(rootReal, targetReal) || '.',
      entries: entries.slice(0, 500).map((e) => ({
        name: e.name,
        type: e.isDirectory() ? 'dir' : e.isSymbolicLink() ? 'symlink' : 'file',
      })),
      truncated: entries.length > 500,
    }
  }
  const ext = path.extname(targetReal).toLowerCase()
  // extension-less files (etc/passwd, hosts, ...) pass through to the NUL
  // sniff below instead of being refused outright
  if (ext !== '' && !TEXT_EXTENSIONS.has(ext)) {
    throw new Error(`refusing non-text file (extension ${JSON.stringify(ext)} not in whitelist): ${[...TEXT_EXTENSIONS].join(' ')}`)
  }
  if (stat.size > BROWSE_MAX_BYTES) {
    throw new Error(`file too large: ${stat.size} bytes > ${BROWSE_MAX_BYTES} (64KB) 上限`)
  }
  const buf = await fsp.readFile(targetReal)
  if (buf.includes(0)) throw new Error('refusing binary-looking file (NUL byte present)')
  return {
    job_id: jobId,
    path: path.relative(rootReal, targetReal),
    bytes: buf.length,
    content: buf.toString('utf8'),
  }
}

export function apply(ctx, config) {
  const mode = config.mode || 'dynamic'
  // 纯静态模式不注册动态类工具（fuzz/frida/trace 请求权被收回）
  const dynamicOnly = new Set(['fw_request_trace', 'fw_request_fuzz', 'fw_request_frida'])
  const register = (def) => {
    if (mode === 'static' && dynamicOnly.has(def.name)) return
    ctx.tools.register(jsonTool(def))
  }

  // S1 纵深防御：shell/文件读写/web/子代理类工具即使被意外重新挂载，
  // 执行前也会被这个全局 guard 拒绝（deny 只增不赦）。
  ctx.tools.guard((exec) => (BLOCKED_TOOLS.has(exec.name)
    ? `tool "${exec.name}" is disabled in the fwgraph profile（固件分析只读：shell/文件写/web/子代理一律禁用，固件文件只读核对请用 fw_browse_firmware）`
    : undefined))

  // 动态操作预算（每个 dsh 进程即一个会话；原来 dsh 侧完全无预算）
  let traceCount = 0
  let fuzzCount = 0

  register({
    name: 'fw_get_identification',
    description: 'External-input inventory (identification.json): every public, non-loopback input of the firmware (IN-xxx) with protocol/port, input types, entry files, processing-chain libraries and dispatch chains. Start vuln mining here for full coverage.',
    parameters: params({
      ...JOB_ID_PROP,
      full: { type: 'boolean', description: 'Return complete document incl. evidence/notes (large)' },
    }),
    async execute(args) {
      const doc = await fw(config, 'GET', `/jobs/${jobOf(config, args)}/identification`)
      if (args.full) return { document: doc }
      return {
        metadata: doc.metadata,
        inputs: (doc.inputs ?? []).map((i) => ({
          id: i.id, protocol: i.protocol, service: i.service,
          address: i.address, port: i.port, transport: i.transport,
          input_types: i.input_types, entry_files: i.entry_files,
          processing_chain: (i.processing_chain ?? []).map((p) => ({
            file: p.file, libs: p.libs,
            unresolved_needed: p.unresolved_needed ?? [],
            needed_complete: !(p.unresolved_needed ?? []).length,
          })),
        })),
      }
    },
  })

  register({
    name: 'fw_list_surfaces',
    description: 'List per-input attack-surface documents (AS-xxx.json / AS-AUTH-xxx.json): routing path, dispatchers, parsers, normalizers, final handler, carrier bindings, auth chain refs — one per external input.',
    parameters: params({ ...JOB_ID_PROP }),
    async execute(args) {
      return fw(config, 'GET', `/jobs/${jobOf(config, args)}/surfaces`)
    },
  })

  register({
    name: 'fw_get_surface',
    description: 'Fetch one attack-surface document by id (AS-014 / AS-AUTH-001).',
    parameters: params({
      ...JOB_ID_PROP,
      surface_id: { type: 'string', description: 'AS-014 or AS-AUTH-001' },
    }, ['surface_id']),
    async execute(args) {
      if (!/^AS-(AUTH-)?[0-9A-Za-z]{1,8}$/.test(args.surface_id ?? '')) {
        throw new Error('surface_id like AS-014 or AS-AUTH-001 is required')
      }
      return fw(config, 'GET',
        `/jobs/${jobOf(config, args)}/surfaces/${args.surface_id}`)
    },
  })

  register({
    name: 'fw_get_function_source',
    description: 'Hex-Rays pseudo-C source of one function; its names/addresses are the canonical identifiers and the ONLY citable evidence. kind=brief returns a ~1KB triage card (signature head, dangerous calls with line numbers, callees, attack-surface flags) — ALWAYS screen with kind=brief first when scanning many functions, fetch full source only for suspicious ones. kind=asm returns function-level assembly for call-site argument recovery.',
    parameters: params({
      ...JOB_ID_PROP,
      md5: { type: 'string' },
      addr: { type: 'string', description: 'Function address, e.g. 0x401000' },
      kind: { type: 'string', enum: ['hexrays', 'asm', 'brief'], description: 'default hexrays (canonical); brief = compact triage card (use first); asm = function-level assembly' },
    }, ['md5', 'addr']),
    async execute(args) {
      if (args.kind === 'brief') {
        return fw(config, 'GET',
          `/jobs/${jobOf(config, args)}/functions/${args.md5}/${args.addr}/brief`)
      }
      const suffix = args.kind === 'asm' ? '?asm=1' : ''
      const src = await fw(config, 'GET',
        `/jobs/${jobOf(config, args)}/functions/${args.md5}/${args.addr}/source${suffix}`)
      return { source: src }
    },
  })

  register({
    name: 'fw_attack_surface',
    description: 'Scored source->sink attack paths. Join via evidence_address (job_id+md5+addr) only. attribution is verified_in_single_trace | observed_in_window | static_only — never request-caused. ai_review is a triage hint, not a finding.',
    parameters: params({
      ...JOB_ID_PROP,
      source: { type: 'string' },
      sink: { type: 'string' },
      verified_only: { type: 'boolean' },
      brief: { type: 'boolean', description: 'omit per-path chain nodes (triage view; refetch with brief=false + filters for the chains you dig)' },
      limit: { type: 'integer' },
    }),
    async execute(args) {
      return graphQuery(config, jobOf(config, args), 'attack_surface', {
        ...(args.source ? { source: args.source } : {}),
        ...(args.sink ? { sink: args.sink } : {}),
        verified_only: Boolean(args.verified_only),
        ...(args.brief ? { brief: true } : {}),
        limit: Math.min(Number(args.limit ?? 20), 50),
      })
    },
  })

  register({
    name: 'fw_compose_evidence',
    description: 'Join already-fetched facts at one Evidence Address. Does not query other producers.',
    parameters: params({
      ...JOB_ID_PROP,
      md5: { type: 'string' },
      addr: { type: 'string' },
      static_block: { type: 'object' },
      decompile_text: { type: 'string' },
      dynamic_envelope: { type: 'object' },
    }, ['md5', 'addr']),
    async execute(args) {
      return graphQuery(config, jobOf(config, args), 'compose_evidence', {
        binary_md5: args.md5,
        addr: args.addr,
        ...(args.static_block ? { static_block: args.static_block } : {}),
        ...(args.decompile_text ? { decompile_text: args.decompile_text } : {}),
        ...(args.dynamic_envelope ? { dynamic_envelope: args.dynamic_envelope } : {}),
      })
    },
  })

  register({
    name: 'fw_search',
    description: 'Search functions/files in the code graph by name pattern.',
    parameters: params({
      ...JOB_ID_PROP,
      pattern: { type: 'string' },
      label: { type: 'string' },
      limit: { type: 'integer' },
    }, ['pattern']),
    async execute(args) {
      return graphQuery(config, jobOf(config, args), 'search', {
        pattern: args.pattern,
        ...(args.label ? { label: args.label } : {}),
        ...(args.limit ? { limit: Number(args.limit) } : {}),
      })
    },
  })

  register({
    name: 'fw_call_trace',
    description: 'Callers/callees of a function (direction both|in|out).',
    parameters: params({
      ...JOB_ID_PROP,
      name: { type: 'string' },
      direction: { type: 'string', enum: ['both', 'in', 'out'] },
    }, ['name']),
    async execute(args) {
      return graphQuery(config, jobOf(config, args), 'trace', {
        name: args.name, direction: args.direction ?? 'both',
      })
    },
  })

  register({
    name: 'fw_routes',
    description: 'HTTP route map (path, method, handler function, binary).',
    parameters: params({
      ...JOB_ID_PROP,
      pattern: { type: 'string' },
      method: { type: 'string' },
      binary_md5: { type: 'string' },
      limit: { type: 'integer' },
    }),
    async execute(args) {
      return graphQuery(config, jobOf(config, args), 'routes', {
        ...(args.pattern ? { pattern: args.pattern } : {}),
        ...(args.method ? { method: args.method } : {}),
        ...(args.binary_md5 ? { binary_md5: args.binary_md5 } : {}),
        limit: Math.min(Number(args.limit ?? 50), 200),
      })
    },
  })

  register({
    name: 'fw_list_traces',
    description: 'List qemu-user differential coverage traces for the job.',
    parameters: params({ ...JOB_ID_PROP }),
    async execute(args) {
      return fw(config, 'GET', `/jobs/${jobOf(config, args)}/traces`)
    },
  })

  register({
    name: 'fw_browse_firmware',
    description: 'Read-only browse of the extracted firmware tree for one job, jailed under data/extracted/<job_id>/: pass a directory path to list it (omit path for the root) or a file path to read it. Text files only — extension whitelist (.txt/.conf/.cfg/.ini/.json/.sh/.xml/.html/.js/.c/.h/.py/.list/.log/.md/.csv/.yaml/.properties/...), binaries and extension-less files are refused; single reads capped at 64KB. Paths escaping the job root (../, absolute symlinks) are rejected. Use to cross-check configs (e.g. etc/*.conf) against decompiled evidence.',
    parameters: params({
      ...JOB_ID_PROP,
      path: { type: 'string', description: 'Relative path inside the job extraction root (e.g. "etc" or "etc/config/network"); omit = root listing' },
    }),
    async execute(args) {
      return browseFirmware(config, args)
    },
  })

  register({
    name: 'fw_request_trace',
    description: `Trigger a controlled qemu-user coverage trace (baseline vs trigger request). Budgeted — max ${MAX_TRACES_PER_SESSION} per session, use sparingly.`,
    parameters: params({
      ...JOB_ID_PROP,
      binary_md5: { type: 'string' },
      argv: { type: 'array', items: { type: 'string' } },
      port: { type: 'integer' },
      request_path: { type: 'string' },
    }, ['binary_md5', 'argv']),
    async execute(args) {
      if (traceCount >= MAX_TRACES_PER_SESSION) {
        throw new Error(`trace budget exhausted (${MAX_TRACES_PER_SESSION} per session); mine existing traces instead`)
      }
      const resp = await fw(config, 'POST', `/jobs/${jobOf(config, args)}/trace`, {
        binary_md5: args.binary_md5,
        argv: args.argv,
        ...(args.port ? { port: Number(args.port) } : {}),
        ...(args.request_path ? { request_path: args.request_path } : {}),
      })
      traceCount += 1
      return resp
    },
  })

  register({
    name: 'fw_request_fuzz',
    description: `Request a function-level AFL++ fuzz run (dynamic, arm/mips via qemu persistent hook). Only with a concrete hypothesis. Budgeted — max ${MAX_FUZZ_PER_SESSION} per session. Poll via fw_get_fuzz_run.`,
    parameters: params({
      ...JOB_ID_PROP,
      binary_md5: { type: 'string' },
      function: { type: 'string', description: 'hex address like 0x131b4 (omit for whole-binary mode)' },
      args: { type: 'array', items: { type: 'string' }, description: 'arg spec e.g. [buf,len]' },
      seconds: { type: 'integer' },
    }, ['binary_md5']),
    async execute(args) {
      if (fuzzCount >= MAX_FUZZ_PER_SESSION) {
        throw new Error(`fuzz budget exhausted (${MAX_FUZZ_PER_SESSION} per session)`)
      }
      const body = { binary_md5: args.binary_md5, seconds: Math.min(Number(args.seconds ?? 60), 300) }
      if (args.function) body.function = String(args.function)
      if (Array.isArray(args.args) && args.args.length) body.args = args.args.map(String)
      const resp = await fw(config, 'POST', `/jobs/${jobOf(config, args)}/fuzz`, body)
      fuzzCount += 1
      return resp
    },
  })

  register({
    name: 'fw_request_frida',
    description: `Request a frida instrumentation run on an x86 process (dynamic). host empty = local. Budgeted — shares the fuzz budget, max ${MAX_FUZZ_PER_SESSION} per session.`,
    parameters: params({
      ...JOB_ID_PROP,
      host: { type: 'string' },
      process: { type: 'string' },
      functions: { type: 'array', items: { type: 'object' } },
      seconds: { type: 'integer' },
      spawn: { type: 'boolean' },
    }, ['process', 'functions']),
    async execute(args) {
      if (fuzzCount >= MAX_FUZZ_PER_SESSION) {
        throw new Error(`dynamic budget exhausted (${MAX_FUZZ_PER_SESSION} per session)`)
      }
      const resp = await fw(config, 'POST', `/jobs/${jobOf(config, args)}/frida`, {
        host: String(args.host ?? ''), process: String(args.process),
        functions: args.functions,
        seconds: Math.min(Number(args.seconds ?? 60), 300),
        spawn: Boolean(args.spawn),
      })
      fuzzCount += 1
      return resp
    },
  })

  register({
    name: 'fw_get_fuzz_run',
    description: 'Fetch one fuzz/frida run result (execs/crashes/hangs or hooked/hits).',
    parameters: params({
      ...JOB_ID_PROP,
      kind: { type: 'string', enum: ['fuzz', 'frida'] },
      run_id: { type: 'string' },
    }, ['kind', 'run_id']),
    async execute(args) {
      return fw(config, 'GET', `/jobs/${jobOf(config, args)}/${args.kind}/${args.run_id}`)
    },
  })

  register({
    name: 'fw_get_cfg',
    description: 'Control-flow graph of one function (basic blocks + branch edges). Big functions: pass max_nodes to truncate.',
    parameters: params({ ...JOB_ID_PROP, md5: { type: 'string' }, addr: { type: 'string' },
      max_nodes: { type: 'integer', description: 'keep at most N basic blocks (0/absent = full)' } }, ['md5', 'addr']),
    async execute(args) {
      return graphQuery(config, jobOf(config, args), 'cfg', { md5: args.md5, addr: args.addr,
        ...(args.max_nodes ? { max_nodes: Number(args.max_nodes) } : {}) })
    },
  })

  register({
    name: 'fw_get_ast',
    description: 'AST of one function pseudo-C (tree-sitter). Big functions: pass max_depth/max_nodes to truncate.',
    parameters: params({ ...JOB_ID_PROP, md5: { type: 'string' }, addr: { type: 'string' },
      max_depth: { type: 'integer' }, max_nodes: { type: 'integer' } }, ['md5', 'addr']),
    async execute(args) {
      return graphQuery(config, jobOf(config, args), 'ast', { md5: args.md5, addr: args.addr,
        ...(args.max_nodes ? { max_nodes: Number(args.max_nodes) } : {}),
        ...(args.max_depth ? { max_depth: Number(args.max_depth) } : {}) })
    },
  })

  register({
    name: 'record_finding',
    description: 'Record ONE confirmed vulnerability finding via the server-side findings API (POST /vulnagent/findings). The server is the authoritative validator and store: it generates the finding id (F-xxx) and status=draft, and rejects (HTTP 422, Chinese detail) when a field breaks a rule — read the detail, fix the field, resubmit. Server rules: job must exist; binary_md5 must be in the job manifest; function_addr (when given) must be in symbols; cwe is REQUIRED and must be exactly one `CWE-<digits>` (never combos like `CWE-78 / CWE-121`); vuln_class is a SINGLE class — values containing `/`, `，`, `、` are rejected; severity ∈ critical|high|medium|low|info; reachability ∈ static-only|observed|verified; confidence 0..1 with anchor caps — static-only is capped at 0.7, observed/verified REQUIRE an existing trace_id. Speculative non-issues (socket accept, connection success, empty diffs) are NOT vulnerabilities. Chinese for natural-language fields.',
    parameters: params({
      title: { type: 'string' },
      severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
      vuln_class: { type: 'string', description: 'SINGLE class; no `/`, `，`, `、` combos' },
      cwe: { type: 'string', description: 'REQUIRED, exactly one CWE-<digits>' },
      binary_md5: { type: 'string' },
      binary_path: { type: 'string' },
      function_addr: { type: 'string' },
      function_name: { type: 'string' },
      summary: { type: 'string' },
      evidence: { type: 'array', items: { type: 'string' } },
      confidence: { type: 'number', description: '0..1; static-only ≤0.7 (server-capped); observed/verified need trace_id; memory-corruption without checksec evidence ≤0.6' },
      reachability: { type: 'string', enum: ['static-only', 'observed', 'verified'] },
      trace_id: { type: 'string', description: 'Coverage trace id; REQUIRED when reachability is observed/verified' },
      preconditions: { type: 'string' },
      exploit_sketch: { type: 'string' },
      remediation: { type: 'string' },
      job_id: JOB_ID_PROP.job_id,
    }, ['title', 'severity', 'vuln_class', 'cwe', 'binary_md5', 'binary_path',
        'summary', 'evidence', 'confidence', 'reachability']),
    async execute(args) {
      // 本地预检（镜像服务端规则），随后 POST；服务端 422 detail 原文抛出
      const conf = precheckFinding(args)
      const body = {
        job_id: jobOf(config, args),
        title: args.title,
        severity: args.severity,
        confidence: conf,
        vuln_class: args.vuln_class,
        cwe: args.cwe,
        binary_md5: args.binary_md5,
        binary_path: args.binary_path,
        reachability: args.reachability,
        summary: args.summary,
        evidence: args.evidence,
      }
      // H3: finding 归属会话（orchestrator 注入 FWGRAPH_SESSION_ID）
      if (config.sessionId) body.session_id = config.sessionId
      for (const k of ['function_addr', 'function_name', 'preconditions', 'exploit_sketch', 'remediation', 'trace_id']) {
        if (args[k] !== undefined && args[k] !== null && args[k] !== '') body[k] = args[k]
      }
      const finding = await fw(config, 'POST', '/vulnagent/findings', body)
      if (!finding || typeof finding !== 'object' || !finding.id) {
        throw new Error(`服务端未返回 finding id：${JSON.stringify(finding).slice(0, 300)}`)
      }
      return {
        recorded: true,
        finding_id: finding.id,
        status: finding.status ?? 'draft',
        confidence: finding.confidence,
      }
    },
  })
}
