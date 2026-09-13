export const PIPE_STEPS = [
  { key: 'decrypt', label: '固件解密' },
  { key: 'extract', label: '解包固件' },
  { key: 'parse', label: '解析文件' },
  { key: 'decompile', label: '反编译' },
  { key: 'graph', label: '代码图谱' },
  { key: 'attack', label: '攻击路径' },
  { key: 'routes', label: '路由识别' },
  { key: 'inputs', label: '输入识别' },
  { key: 'surfaces', label: '攻击面' }
]

const STEP_INDEX = {
  uploading: 0, pending: 0, decrypting: 0,
  extracting: 1,
  parsing: 2,
  decompiling: 3,
  ailifting: 4, graphing: 4,
  attacking: 5,
  routing: 6,
  identifying: 7,
  surfacing: 8, surfaced: 8
}

export const RUNNING = new Set([
  'uploading', 'pending', 'decrypting', 'extracting', 'parsing', 'decompiling',
  'graphing', 'attacking', 'routing', 'identifying', 'surfacing'
])

export const COMPLETE = new Set(['graphed', 'attacked', 'routed', 'surfaced'])

export const STATUS_TEXT = {
  uploading: '正在上传固件', pending: '排队中', decrypting: '正在解密固件',
  extracting: '正在解包',
  parsing: '解析文件系统', decompiling: '反编译中', graphing: '构建图谱',
  attacking: '分析攻击路径', routing: '识别路由', identifying: '识别输入',
  surfacing: '导出攻击面', graphed: '图谱完成', attacked: '攻击路径完成',
  routed: '前置完成', surfaced: '前置完成', failed: '分析失败', done: '解包完成'
}

export const STEP_TALK = {
  decrypt: { now: '正在解密固件', ok: '固件解密完成' },
  extract: { now: '正在解包固件', ok: '固件解包完成' },
  parse: { now: '正在解析文件系统', ok: '文件解析完成' },
  decompile: { now: '正在反编译二进制', ok: '反编译完成' },
  graph: { now: '正在构建代码图谱', ok: '代码图谱完成' },
  attack: { now: '正在分析攻击路径', ok: '攻击路径分析完成' },
  routes: { now: '正在识别路由', ok: '路由识别完成' },
  inputs: { now: '正在识别外部输入', ok: '输入识别完成' },
  surfaces: { now: '正在导出攻击面', ok: '攻击面导出完成' }
}

export const DEFAULT_TASK = '沿高分攻击路径做动静结合挖掘，给出调用链和可复现 PoC。优先命令注入和内存破坏。'
export const DEFAULT_PREPARE_TASK = '完成解包、反编译、图谱和攻击面分析，供后续漏洞挖掘使用。'
export const HUNT_TURNS = 80

export const WISH_OPTIONS = [
  { id: 'all', label: '尽量全挖', hint: '按高分路径自动覆盖' },
  { id: 'cmdi', label: '命令注入', hint: 'system / popen / 未过滤拼接' },
  { id: 'mem', label: '内存破坏', hint: '溢出、越界写、释放后使用' },
  { id: 'auth', label: '认证绕过', hint: '口令、会话、默认凭据' },
  { id: 'file', label: '任意文件读写', hint: '路径穿越、任意写' },
  { id: 'info', label: '信息泄露', hint: '配置、密钥、敏感接口' },
  { id: 'preauth', label: '预认证 RCE', hint: '未登录就能打到的远程执行' }
]

export function buildWishTask (ids, extra) {
  const picked = new Set(Array.isArray(ids) ? ids : [])
  const labels = picked.has('all')
    ? ['尽量覆盖高分路径上的真实漏洞']
    : WISH_OPTIONS.filter((item) => picked.has(item.id) && item.id !== 'all')
      .map((item) => item.label)
  const focus = labels.length ? labels.join('、') : '尽量覆盖高分路径上的真实漏洞'
  const note = String(extra || '').trim().slice(0, 800)
  return [
    `用户希望挖到：${focus}。`,
    note ? `补充要求：${note}` : '',
    '前置分析完成后立刻沿高分攻击路径做动静结合挖掘。',
    '确认漏洞必须同时给出调用链和可复现 PoC。空差分、连通、启动崩溃不是漏洞。',
    '对用户只说简体中文；一次最多两个工具，打完先交代结果。'
  ].filter(Boolean).join('')
}

export const FW_ACCEPT = '.bin,.img,.tar,.gz,.tgz,.zip,.trx,.chk,.fw'

// ---- 失败诊断 ---------------------------------------------------------------

// 失败时正在运行的 status → 流水线步骤 key
const RUNNING_STEP = {
  decrypting: 'decrypt', extracting: 'extract', parsing: 'parse',
  decompiling: 'decompile', graphing: 'graph', attacking: 'attack',
  routing: 'routes', identifying: 'inputs', surfacing: 'surfaces'
}
// 后端错误信息自带的阶段前缀 → 步骤 key（旧任务没有 failed_from 时兜底）
const ERROR_PREFIX_STEP = {
  decompile: 'decompile', graph: 'graph', attack: 'attack',
  routes: 'routes', inputs: 'inputs', surfaces: 'surfaces',
  EMBA: 'extract'
}
// 前缀匹配不到时按关键词推断（顺序即优先级）
const ERROR_KEYWORD_STEP = [
  ['decompil', 'decompile'],
  ['binwalk', 'extract'],
  ['emba', 'extract'],
  ['graph', 'graph'],
  ['attack', 'attack'],
  ['route', 'routes'],
  ['surface', 'surfaces']
]
// 有服务端重跑端点的步骤；decrypt/extract/parse 失败只能重新上传
export const RETRYABLE_STEPS = new Set(['decompile', 'graph', 'attack', 'routes', 'inputs', 'surfaces'])

export function failedStep (job) {
  if (!job || job.status !== 'failed') return null
  const fromRunning = RUNNING_STEP[job.failed_from]
  if (fromRunning) return fromRunning
  const err = String(job.error || '').toLowerCase()
  const prefix = err.slice(0, err.indexOf(':'))
  if (ERROR_PREFIX_STEP[prefix]) return ERROR_PREFIX_STEP[prefix]
  for (const [kw, step] of ERROR_KEYWORD_STEP) {
    if (err.includes(kw)) return step
  }
  return null
}

const STEP_LABEL = Object.fromEntries(PIPE_STEPS.map((s) => [s.key, s.label]))

export function failedStepLabel (job) {
  const key = failedStep(job)
  return key ? (STEP_LABEL[key] || key) : '前置阶段'
}

const ERROR_TRANSLATIONS = [
  [/^interrupted by service restart\.?$/i, '服务重启导致任务中断'],
  [/FileNotFoundError:\s*/i, '缺少必要文件：'],
  [/^Timeout\w*:\s*/i, '处理超时：'],
  [/^ValueError:\s*/i, '参数或数据异常：'],
  [/^RuntimeError:\s*/i, '运行时错误：']
]

/** 把面向开发者的错误文本清理成用户可读：
 *  去掉阶段前缀（decompile: 之类）、截断服务端绝对路径、翻译常见异常。 */
export function humanizeError (error) {
  let text = String(error || '').trim()
  if (!text) return '未记录失败原因'
  for (const step of Object.keys(ERROR_PREFIX_STEP)) {
    if (text.toLowerCase().startsWith(step.toLowerCase() + ':')) {
      text = text.slice(text.indexOf(':') + 1).trim()
      break
    }
  }
  for (const [re, cn] of ERROR_TRANSLATIONS) text = text.replace(re, cn)
  text = text.replace(/\(see [^)]*\.json\)/gi, '（详见任务日志）')
  text = text.replace(/(?:\/[\w.-]+){2,}\/([\w.-]+)/g, '…/$1')
  return text
}

export function pipeProgress (job) {
  const total = PIPE_STEPS.length
  if (!job) return { done: 0, total, pct: 0, label: '等待开始' }
  if (COMPLETE.has(job.status)) {
    return { done: total, total, pct: 100, label: STATUS_TEXT[job.status] || '前置完成' }
  }
  const idx = pipeIndex(job)
  if (job.status === 'failed') {
    return {
      done: idx, total,
      pct: Math.round((idx / total) * 100),
      label: STATUS_TEXT.failed
    }
  }
  const pct = Math.min(99, Math.round(((idx + 0.42) / total) * 100))
  return { done: idx, total, pct, label: STATUS_TEXT[job.status] || job.status }
}

export function pipeIndex (job) {
  if (!job) return 0
  if (job.status === 'failed') {
    const key = failedStep(job)
    if (key) return PIPE_STEPS.findIndex((s) => s.key === key)
    return STEP_INDEX[job.lastOkStatus] ?? 0
  }
  if (COMPLETE.has(job.status)) return PIPE_STEPS.length
  return STEP_INDEX[job.status] ?? 0
}

export function pipelineFinished (job) {
  if (!job) return false
  if (job.status === 'failed') return true
  if (RUNNING.has(job.status)) return false
  if (job.status === 'done' || job.status === 'decompiled' || job.status === 'ailifted') {
    return false
  }
  return COMPLETE.has(job.status)
}

export function stepState (i, job) {
  if (!job) return 'wait'
  const idx = pipeIndex(job)
  if (job.status === 'failed' && i === idx) return 'err'
  if (COMPLETE.has(job.status) || i < idx) return 'ok'
  if (i === idx) return 'now'
  return 'wait'
}

export function stepPct (i, job, decrypt) {
  const state = stepState(i, job)
  if (state === 'ok') return 100
  if (state === 'err') return 100
  if (state !== 'now') return 0
  if (job?.status === 'uploading') return Math.max(4, Number(job.uploadPct) || 0)
  if (i === 0 && decrypt && Number(decrypt.progress) > 0) {
    return Math.min(99, Number(decrypt.progress))
  }
  return 46
}

export function announceSteps (prevJob, nextJob) {
  if (!nextJob) return []
  const lines = []
  if (!prevJob || prevJob.job_id !== nextJob.job_id) {
    if (RUNNING.has(nextJob.status) || nextJob.status === 'pending') {
      lines.push(`任务 ${nextJob.firmware || nextJob.job_id} 已接入前置流水线`)
    }
  }
  const prevIdx = prevJob && prevJob.job_id === nextJob.job_id
    ? pipeIndex(prevJob)
    : -1
  const nextIdx = pipeIndex(nextJob)
  if (COMPLETE.has(nextJob.status)) {
    if (!prevJob || !COMPLETE.has(prevJob.status) || prevJob.job_id !== nextJob.job_id) {
      lines.push('前置九步全部完成，可以去工作台挖掘')
    }
    return lines
  }
  if (nextJob.status === 'failed') {
    lines.push(nextJob.error ? `前置失败：${nextJob.error}` : '前置分析失败')
    return lines
  }
  if (nextIdx > prevIdx) {
    for (let i = Math.max(0, prevIdx); i < nextIdx && i < PIPE_STEPS.length; i++) {
      const talk = STEP_TALK[PIPE_STEPS[i].key]
      if (talk) lines.push(talk.ok)
    }
    const cur = PIPE_STEPS[nextIdx]
    if (cur && STEP_TALK[cur.key]) lines.push(STEP_TALK[cur.key].now)
  } else if (prevIdx < 0 && nextIdx >= 0) {
    const cur = PIPE_STEPS[nextIdx]
    if (cur && STEP_TALK[cur.key]) lines.push(STEP_TALK[cur.key].now)
  }
  return lines
}

export function fmtSize (n) {
  if (n == null) return ''
  if (n > 1048576) return (n / 1048576).toFixed(1) + ' MB'
  if (n > 1024) return (n / 1024).toFixed(1) + ' KB'
  return n + ' B'
}

export function isFirmwareFile (file) {
  if (!file) return false
  const name = (file.name || '').toLowerCase()
  return FW_ACCEPT.split(',').some((ext) => name.endsWith(ext)) || file.size > 64 * 1024
}
