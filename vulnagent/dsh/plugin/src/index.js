/**
 * @fwgraph/dsh-fwgraph-tools — fwgraph read-only tools for DeepSeek Harness.
 *
 * Zero-dependency cordis plugin: registers plain ToolDefinition objects on
 * ctx.tools (no @deepseek-ai/* imports — the registry only requires that
 * `parameters` / `output.schema` are real JSON Schema), so the package
 * loads from any profile node_modules layout.
 *
 * Mode isolation / budget / whitelist (S1):
 *  - The profile's cordis.patch.yml keeps sandboxed bash/fs (session
 *    workspace) and disables web / subagent / ralph.
 *  - apply() registers a global ctx.tools.guard that still denies web /
 *    subagent / pwsh / ralph by name.
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
const MAX_TRACES_PER_SESSION = 192
const MAX_FUZZ_PER_SESSION = 12
const MAX_EXEC_PER_SESSION = 8
const BROWSE_MAX_BYTES = 64 * 1024

// S1: tool classes that must never execute in this profile, regardless of
// how the dsh-base composition evolves. Denied by guard even if a row is
// accidentally re-enabled.
const BLOCKED_TOOLS = new Set([
  // still no host-wide code-mode / powershell / orchestration fan-out
  'pwsh', 'run_code', 'ralph', 'workflow',
  // web egress
  'web_search', 'web_fetch',
  // agent fan-out (unbudgeted LLM burn, bypasses the mining playbook)
  'subagent', 'subagent_fork', 'send_message', 'interrupt_agent', 'list_agents',
])

// fw_browse_firmware: text-file extension whitelist (binary rejected by
// extension; content is additionally NUL-scanned)
const TEXT_EXTENSIONS = new Set([
  '.txt', '.conf', '.cfg', '.ini', '.json', '.sh', '.bash', '.xml', '.html',
  '.htm', '.js', '.c', '.h', '.cpp', '.py', '.list', '.log', '.md', '.csv',
  '.yaml', '.yml', '.properties', '.cnf', '.service', '.rules',
])

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms))
}

function isRetryableFwError(err) {
  const msg = String(err?.message || err)
  if (/HTTP 5\d\d/.test(msg)) return true
  // Node fetch TypeError, AbortSignal.timeout, TLS handshake
  return /fetch failed|aborted|timeout|ECONNRESET|ECONNREFUSED|UND_ERR|network/i.test(msg)
}

async function fw(config, method, urlPath, body) {
  let last
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
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
    } catch (err) {
      last = err
      if (!isRetryableFwError(err) || attempt === 3) throw err
      await sleep(800 * (attempt + 1))
    }
  }
  throw last
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

const SINK_RE = /memcpy|memmove|strcpy|strncpy|strcat|strncat|sprintf|snprintf|vsprintf|gets|scanf|system|popen|exec|execl|eval|realloc|setenv|bcopy/i

function fnName(f) {
  return String((f && (f.ai_name || f.name || f.libc_equiv)) || '')
}

export function compactDiffFns(fns, limit = 24) {
  const out = []
  for (const f of fns || []) {
    const name = fnName(f)
    const libc = f && f.libc_equiv ? String(f.libc_equiv) : ''
    out.push({
      name: name || undefined,
      addr: (f && (f.addr || f.address)) || undefined,
      libc_equiv: libc || undefined,
      sink: SINK_RE.test(name) || SINK_RE.test(libc),
    })
    if (out.length >= limit) break
  }
  return out
}

/** 给模型的下一刀，不是给用户看的验收文案。 */
export function huntNextFromTrace(t) {
  if (!t || typeof t !== 'object') {
    return '立刻 fw_request_trace，不要向用户解释。'
  }
  const status = String(t.status || '')
  const via = String((t.request || {}).via || '')
  const port = (t.request || {}).port
  const tid = t.trace_id || ''
  const md5 = (t.binary && t.binary.md5) || t.binary_md5 || ''
  if (status === 'running') {
    return '仍在跑。继续 fw_get_trace 轮询，不要对用户说话。'
  }
  if (status === 'failed' || t.error) {
    return '本次失败。立刻换 via=stdin 或 input_path=/tmp/poc.bin 或换 payload，再 fw_request_trace。禁止向用户解释平台或写验收报告。'
  }
  const fns = compactDiffFns((t.diff && t.diff.functions) || [])
  const sinks = fns.filter((f) => f.sink)
  if (fns.length) {
    const pick = (sinks.length ? sinks : fns).slice(0, 8)
    const list = pick.map((f) => `${f.name || '?'}@${f.addr || '?'}`).join(', ')
    return `差分命中 ${fns.length} 个函数（优先 sink）：${list}。立刻 fw_get_function_source(kind=brief, md5=${md5 || '本 binary'}, addr=这些地址)。能到危险操作就 record_finding（reachability=observed, trace_id=${tid}，必须 call_chain+poc）。不要把差分表贴给用户。`
  }
  if (via === 'net' || port) {
    return '网络空差分：请求没进处理函数。立刻对同一 binary_md5 再 fw_request_trace，改 via=stdin 或 payloads_hex 或换 request_path。禁止向用户汇报能力/空差分表。'
  }
  return 'stdin/文件空差分：payload 没打到解析分支。换更像真实输入的字节（协议头、超长、格式错）或换会解析该输入的 ELF，再 fw_request_trace。空差分不是漏洞，不要写给用户。'
}

export function compactTrace(t) {
  if (!t || typeof t !== 'object') return t
  if (t.status === 'running') {
    return {
      trace_id: t.trace_id, status: 'running',
      hunt_next: huntNextFromTrace(t),
    }
  }
  const fns = compactDiffFns((t.diff && t.diff.functions) || [])
  const trig = (t.trigger && t.trigger.trigger_result) || t.trigger_result
  return {
    trace_id: t.trace_id,
    status: t.status,
    error: t.error || undefined,
    binary_md5: (t.binary && t.binary.md5) || t.binary_md5,
    argv: t.argv,
    argv0: t.argv0,
    request: t.request,
    trigger_result: trig,
    diff: {
      function_count: (t.diff && t.diff.function_count) ?? fns.length,
      functions: fns,
    },
    hunt_next: huntNextFromTrace(t),
  }
}

export function summarizeTraceList(out) {
  const traces = (out && Array.isArray(out.traces)) ? out.traces : []
  if (!traces.length) {
    const hunt_next = '还没有 qemu 差分 trace。立刻 fw_request_trace，再用 fw_get_trace 轮询。空列表不是缺能力。禁止向用户写验收报告。'
    return {
      job_id: out && out.job_id,
      traces: [],
      total: 0,
      hint: hunt_next,
      hunt_next,
    }
  }
  const by = {}
  for (const t of traces) {
    const s = t.status || 'unknown'
    by[s] = (by[s] || 0) + 1
  }
  const withDiff = traces.filter((t) => Number(t.diff_functions) > 0)
  const recent = traces.slice(0, 6).map((t) => ({
    trace_id: t.trace_id,
    status: t.status,
    via: (t.request || {}).via,
    port: (t.request || {}).port,
    diff_functions: t.diff_functions,
    binary_md5: t.binary_md5,
  }))
  const hunt_next = withDiff.length
    ? `已有 ${withDiff.length} 条非空差分。立刻 fw_get_trace：${withDiff.slice(0, 8).map((t) => t.trace_id).join(', ')}，按返回的 hunt_next 读函数并 record_finding。不要向用户列能力表。`
    : '现有 trace 都是空差分或失败。网络口改 via=stdin 或 payloads_hex 再 fw_request_trace；有差分再读函数。禁止向用户汇报验收。'
  return {
    job_id: out.job_id,
    total: out.total ?? traces.length,
    by_status: by,
    with_diff: withDiff.slice(0, 8).map((t) => ({
      trace_id: t.trace_id,
      diff_functions: t.diff_functions,
      binary_md5: t.binary_md5,
      via: (t.request || {}).via,
    })),
    recent,
    hunt_next,
  }
}

export function huntNextFromExec(r) {
  if (!r || typeof r !== 'object' || r.status === 'running') {
    return '仍在跑，fw_get_qemu_exec 轮询。不要对用户说话。'
  }
  const fed = Number(r.stdin_bytes || 0) > 0 || Boolean(r.input_path)
  const startup = r.crash_kind === 'startup' || (r.status === 'crash' && !fed)
  if (r.status === 'crash' && startup) {
    return `启动即崩（signal ${r.signal ?? r.returncode}，没喂 payload）。这是 qemu 环境，不是漏洞。禁止 record_finding，禁止放弃该 ELF。立刻 fw_request_trace（带 port 或 via=stdin）；还崩再换 argv/argv0，不要跳到别的二进制。`
  }
  if (r.status === 'crash') {
    return `payload 触发崩溃（signal ${r.signal ?? r.returncode}）。立刻 fw_get_function_source 读路径，record_finding（reachability=verified 或 observed，call_chain+poc，evidence 含本 run_id）。不要跳过。`
  }
  if (r.status === 'timeout' && !fed) {
    return '没喂输入就超时：守护进程可能仍活着。不要放弃该 ELF。立刻 fw_request_trace 带 port。'
  }
  if (r.status === 'timeout') {
    return '超时是看门狗，不是漏洞。换更短输入或 via=stdin 再试，不要换题。'
  }
  return '非零退出不是崩溃。不要当漏洞。换 payload，或改 fw_request_trace 看覆盖差分。不要因为一次失败就放弃该入口。'
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
  const chain = String(args.call_chain || '')
  if (!chain.trim() || (!chain.includes('→') && !chain.includes('->'))) {
    throw new Error('call_chain 必填，用 → 连接函数名与地址')
  }
  const poc = String(args.poc || args.exploit_sketch || '')
  if (!poc.trim()) {
    throw new Error('poc 必填，须给出可复现请求或命令')
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
  const dynamicOnly = new Set(['fw_request_trace', 'fw_request_fuzz', 'fw_request_frida', 'fw_qemu_exec'])

  // 动态操作预算（每个 dsh 进程即一个会话；原来 dsh 侧完全无预算）
  let traceCount = 0
  let fuzzCount = 0
  let execCount = 0
  // 空口静态深挖：几次静态工具后仍未 fw_request_trace/fuzz，就在结果里反复提示。
  let staticWithoutDyn = 0
  let sawDynamic = false
  let pendingHuntNext = ''
  const NUDGE_AFTER = 3
  const DYN_HINT = '还没有 qemu 差分 trace。先对当前假设调用 fw_request_trace，再用 fw_get_trace。有差分就按 hunt_next 读函数并 record_finding，不要把结果写成给用户看的验收报告。'

  function attachHint(value, hint) {
    if (!hint) return value
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return { ...value, hint: value.hint || hint }
    }
    return { result: value, hint }
  }

  function withDynNudge(value, toolName) {
    if (value && typeof value === 'object' && value.hunt_next) {
      pendingHuntNext = value.hunt_next
      return value
    }
    if (mode === 'static') return value
    if (pendingHuntNext) return attachHint(value, pendingHuntNext)
    if (sawDynamic || traceCount > 0 || fuzzCount > 0) return value
    staticWithoutDyn += 1
    if (staticWithoutDyn < NUDGE_AFTER) return value
    return attachHint(value, DYN_HINT)
  }

  const register = (def) => {
    if (mode === 'static' && dynamicOnly.has(def.name)) return
    const skipNudge = dynamicOnly.has(def.name) || def.name === 'record_finding'
    if (!skipNudge && typeof def.execute === 'function') {
      const orig = def.execute
      const toolName = def.name
      def.execute = async (args) => withDynNudge(await orig(args), toolName)
    }
    ctx.tools.register(jsonTool(def))
  }

  // S1 纵深防御：shell/文件读写/web/子代理类工具即使被意外重新挂载，
  // 执行前也会被这个全局 guard 拒绝（deny 只增不赦）。
  ctx.tools.guard((exec) => (BLOCKED_TOOLS.has(exec.name)
    ? `tool "${exec.name}" is disabled in the fwgraph profile（禁止出站 web / 子代理 / ralph；沙箱 bash 与写文件可用；固件树只读请用 fw_browse_firmware；动态跑样请用 fw_request_trace）`
    : undefined))

  // 受控动态工具（工作台 web host 模式）：trace/fuzz/frida 会真实运行固件
  // 代码，经 harness 审批缝弹审批面板（允许一次/拒绝）。orchestrator 在
  // dsh_host 模式注入 FWGRAPH_APPROVAL=1；一次性 CLI（headless 无 answerer，
  // ask 会 fail-closed）保持现状不启用。
  if (process.env.FWGRAPH_APPROVAL === '1') {
    ctx.on('tools/pre-execute', async (exec, next) => {
      if (dynamicOnly.has(exec.name)) {
        return {
          kind: 'ask',
          reason: `动态分析请求 ${exec.name}：将在沙箱中真实运行固件目标代码（占用平台按日配额）`,
        }
      }
      return next()
    }, { global: true })
  }

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
          binary_md5: i.binary_md5,
          entry_md5s: i.entry_md5s,
          processing_chain: (i.processing_chain ?? []).map((p) => ({
            file: p.file, libs: p.libs, md5: p.md5,
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
      const out = await graphQuery(config, jobOf(config, args), 'routes', {
        ...(args.pattern ? { pattern: args.pattern } : {}),
        ...(args.method ? { method: args.method } : {}),
        ...(args.binary_md5 ? { binary_md5: args.binary_md5 } : {}),
        limit: Math.min(Number(args.limit ?? 50), 200),
      })
      const n = Number(out?.summary?.routes ?? out?.total ?? 0)
      if (!n) {
        return {
          ...(typeof out === 'object' && out ? out : {}),
          hint: '路由表为空不代表不能动态验证。对 httpd 调用 fw_request_trace（binary_md5 + port + request_path，argv 可空），再用 fw_get_trace 轮询。',
        }
      }
      return out
    },
  })

  register({
    name: 'fw_list_traces',
    description: 'List qemu-user differential coverage traces. Compact: with_diff / recent / hunt_next. Empty list means none have been run — call fw_request_trace. hunt_next is the next mining step for you, not a user-facing report.',
    parameters: params({ ...JOB_ID_PROP }),
    async execute(args) {
      const out = await fw(config, 'GET', `/jobs/${jobOf(config, args)}/traces`)
      const traces = (out && Array.isArray(out.traces)) ? out.traces : []
      if (traces.length) sawDynamic = true
      const summary = summarizeTraceList(out)
      pendingHuntNext = summary.hunt_next || pendingHuntNext
      return summary
    },
  })

  register({
    name: 'fw_get_trace',
    description: 'Read one qemu-user coverage trace by id. Poll after fw_request_trace until status is not running. Returns compact diff + hunt_next (your next mining step: read those functions / retry via=stdin). Empty diff is not a vulnerability. Do not paste hunt_next to the user.',
    parameters: params({
      ...JOB_ID_PROP,
      trace_id: { type: 'string', description: '12 hex chars from fw_request_trace / fw_list_traces' },
    }, ['trace_id']),
    async execute(args) {
      const id = String(args.trace_id || '')
      if (!/^[0-9a-f]{12}$/.test(id)) {
        throw new Error('trace_id must be 12 hex chars')
      }
      const raw = await fw(config, 'GET', `/jobs/${jobOf(config, args)}/traces/${id}`)
      const compact = compactTrace(raw)
      if (compact && compact.status && compact.status !== 'running') {
        sawDynamic = true
        pendingHuntNext = compact.hunt_next || pendingHuntNext
      }
      return compact
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
    description: `Start a qemu-user differential coverage trace (baseline vs one trigger). via=stdin (or payload without port) feeds bytes on qemu stdin so parsers/CLI get a real diff — prefer this when network traces stay empty. via=net (default when port is set) sends HTTP GET or payload/payloads_hex on the port. input_path=/tmp/<name> drops the bytes as a guest file. Do not pass request_path="/" on non-HTTP ports. Poll fw_get_trace. Budget max ${MAX_TRACES_PER_SESSION}. HTTP 409 = retry later.`,
    parameters: params({
      ...JOB_ID_PROP,
      binary_md5: { type: 'string' },
      argv: { type: 'array', items: { type: 'string' }, description: 'Extra guest argv after the binary path. Empty/omit = run like /usr/bin/httpd with no flags.' },
      port: { type: 'integer' },
      request_path: { type: 'string' },
      argv0: { type: 'string', description: 'Forge guest argv[0] for busybox multicall' },
      payload: { type: 'string', description: 'Raw UTF-8 bytes to send on the port (FTP USER, SOAP POST, SSH line). Mutually exclusive with payload_hex/payloads_hex.' },
      payload_hex: { type: 'string', description: 'Raw hex bytes to send (SMB/DNS/binary overflow). Mutually exclusive with payload/payloads_hex.' },
      payloads_hex: { type: 'array', items: { type: 'string' }, description: 'Same-connection conversation: hex blobs sent in order with a short recv between (dropbear banner+KEX, SMB2 negotiate+session). Exclusive with payload/payload_hex. Max 8.' },
      via: { type: 'string', enum: ['net', 'stdin'], description: 'stdin = payload on qemu stdin (parsers). net = listen-port trigger. Default: stdin if payload and no port, else net.' },
      input_path: { type: 'string', description: 'Guest /tmp/<name> to drop payload as a file (file parsers).' },
    }, ['binary_md5']),
    async execute(args) {
      if (traceCount >= MAX_TRACES_PER_SESSION) {
        throw new Error(`trace budget exhausted (${MAX_TRACES_PER_SESSION} per session); mine existing traces instead`)
      }
      const extra = Array.isArray(args.argv) ? args.argv : []
      const body = {
        binary_md5: args.binary_md5,
        argv: extra,
        ...(args.port ? { port: Number(args.port) } : {}),
        ...(args.request_path ? { request_path: args.request_path } : {}),
        ...(args.argv0 ? { argv0: args.argv0 } : {}),
        ...(args.payload ? { payload: String(args.payload) } : {}),
        ...(args.payload_hex ? { payload_hex: String(args.payload_hex) } : {}),
        ...(Array.isArray(args.payloads_hex) ? { payloads_hex: args.payloads_hex.map(String) } : {}),
        ...(args.via ? { via: String(args.via) } : {}),
        ...(args.input_path ? { input_path: String(args.input_path) } : {}),
      }
      let resp
      for (let attempt = 0; attempt < 8; attempt++) {
        try {
          resp = await fw(config, 'POST', `/jobs/${jobOf(config, args)}/trace`, body)
          break
        } catch (err) {
          const msg = String(err?.message || err)
          if (!/HTTP 409/.test(msg) || attempt === 7) throw err
          await new Promise((r) => setTimeout(r, 4000 * (attempt + 1)))
        }
      }
      traceCount += 1
      sawDynamic = true
      return {
        ...resp,
        next: 'poll fw_get_trace until status is not running, then execute hunt_next (read diff functions or retry via=stdin). Do not write a capability report for the user.',
      }
    },
  })

  register({
    name: 'fw_list_binaries',
    description: 'Compact manifest: every extracted ELF with md5/path/arch. Use when identification paths do not match (dropbear vs scp hardlink, smbd symlink).',
    parameters: params({ ...JOB_ID_PROP }),
    async execute(args) {
      const man = await fw(config, 'GET', `/jobs/${jobOf(config, args)}/manifest`)
      const binaries = (man.binaries ?? []).map((b) => ({
        md5: b.md5, path: b.path, arch: b.arch, bits: b.bits,
        endianness: b.endianness,
      }))
      return { job_id: jobOf(config, args), total: binaries.length, binaries }
    },
  })

  register({
    name: 'fw_qemu_exec',
    description: `Run a firmware binary once under qemu-user (no AFL, no coverage). Use to crash-check a PoC: pass stdin or stdin_hex, or write bytes to input_path=/tmp/foo and mention that path in argv. Returns after the process exits (or ~8s). crash_kind=startup (no payload) is an environment failure — retry fw_request_trace, do not abandon the ELF. crash_kind=payload is dynamic evidence. status=timeout with no input often means a daemon is still up. Budget max ${MAX_EXEC_PER_SESSION}.`,
    parameters: params({
      ...JOB_ID_PROP,
      binary_md5: { type: 'string' },
      argv: { type: 'array', items: { type: 'string' } },
      argv0: { type: 'string' },
      stdin: { type: 'string', description: 'Bytes on qemu stdin (parsers that read stdin).' },
      stdin_hex: { type: 'string', description: 'Hex stdin; exclusive with stdin.' },
      input_path: { type: 'string', description: 'Guest path /tmp/<name> to drop the bytes as a file.' },
      seconds: { type: 'integer', description: 'Hard cap 2..20, default 8' },
    }, ['binary_md5']),
    async execute(args) {
      if (execCount >= MAX_EXEC_PER_SESSION) {
        throw new Error(`qemu-exec budget exhausted (${MAX_EXEC_PER_SESSION} per session)`)
      }
      const body = {
        binary_md5: args.binary_md5,
        argv: Array.isArray(args.argv) ? args.argv : [],
        seconds: Math.min(Number(args.seconds ?? 8), 20),
        ...(args.argv0 ? { argv0: String(args.argv0) } : {}),
        ...(args.stdin ? { stdin: String(args.stdin) } : {}),
        ...(args.stdin_hex ? { stdin_hex: String(args.stdin_hex) } : {}),
        ...(args.input_path ? { input_path: String(args.input_path) } : {}),
      }
      const started = await fw(config, 'POST', `/jobs/${jobOf(config, args)}/qemu-exec`, body)
      execCount += 1
      sawDynamic = true
      const runId = started.run_id
      for (let i = 0; i < 24; i++) {
        const got = await fw(config, 'GET', `/jobs/${jobOf(config, args)}/qemu-exec/${runId}`)
        if (got && got.status && got.status !== 'running') {
          const hunt_next = huntNextFromExec(got)
          pendingHuntNext = hunt_next
          return { ...got, hunt_next }
        }
        await new Promise((r) => setTimeout(r, 1000))
      }
      return { ...started, status: 'running', hunt_next: huntNextFromExec({ status: 'running' }) }
    },
  })

  register({
    name: 'fw_get_qemu_exec',
    description: 'Fetch one qemu-user PoC run (status/returncode/signal/output_tail).',
    parameters: params({
      ...JOB_ID_PROP,
      run_id: { type: 'string' },
    }, ['run_id']),
    async execute(args) {
      const got = await fw(config, 'GET', `/jobs/${jobOf(config, args)}/qemu-exec/${args.run_id}`)
      const hunt_next = huntNextFromExec(got)
      if (got && got.status && got.status !== 'running') pendingHuntNext = hunt_next
      return (got && typeof got === 'object') ? { ...got, hunt_next } : got
    },
  })

  register({
    name: 'fw_request_fuzz',
    description: `Request an AFL++ qemu fuzz run. Omit function for whole-binary mode (preferred on MIPS: qemu persistent handshake often fails). Pass function=0x… only for arm/x86 with a concrete hypothesis. Budgeted — max ${MAX_FUZZ_PER_SESSION} per session. Poll via fw_get_fuzz_run until status is ok/error (running is not wedged).`,
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
      const r = await fw(config, 'GET', `/jobs/${jobOf(config, args)}/${args.kind}/${args.run_id}`)
      if (r && typeof r === 'object' && r.status === 'running') {
        return {
          ...r,
          hunt_next: '仍在跑，继续 fw_get_fuzz_run。不要对用户说话。',
        }
      }
      if (r && typeof r === 'object' && r.status === 'error') {
        return {
          ...r,
          hunt_next: 'fuzz 失败。读 detail/stderr_tail；握手失败改整二进制。不要向用户解释平台。',
        }
      }
      if (r && typeof r === 'object') {
        const crashes = Number(r.crashes || 0)
        if (crashes > 0) {
          const hunt_next = `fuzz 有 ${crashes} 个 crash。立刻 fw_qemu_exec 复现，再 record_finding（call_chain+poc）。不要只把 crash 数贴给用户。`
          pendingHuntNext = hunt_next
          return { ...r, hunt_next }
        }
        return {
          ...r,
          hunt_next: '无 crash。不要当漏洞。改 fw_request_trace（via=stdin）打解析器，或换入口。',
        }
      }
      return r
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
      call_chain: { type: 'string', description: 'REQUIRED: 入口到 sink 的调用链，函数名+地址，用 → 连接' },
      poc: { type: 'string', description: 'REQUIRED: 可复现请求或命令' },
      job_id: JOB_ID_PROP.job_id,
    }, ['title', 'severity', 'vuln_class', 'cwe', 'binary_md5', 'binary_path',
        'summary', 'evidence', 'confidence', 'reachability', 'call_chain', 'poc']),
    async execute(args) {
      // 本地预检（镜像服务端规则），随后 POST；服务端 422 detail 原文抛出
      if (!args.call_chain && args.callChain) args.call_chain = args.callChain
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
        call_chain: args.call_chain,
        poc: args.poc || args.exploit_sketch || '',
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
      pendingHuntNext = '本条已入库。继续下一条假设：换入口再 fw_request_trace，不要向用户复盘方法。'
      return {
        recorded: true,
        finding_id: finding.id,
        status: finding.status ?? 'draft',
        confidence: finding.confidence,
        hunt_next: pendingHuntNext,
      }
    },
  })
}
