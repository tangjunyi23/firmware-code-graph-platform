export const PIPE_STEPS = [
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
  uploading: 0, pending: 0, extracting: 0,
  parsing: 1,
  decompiling: 2,
  ailifting: 3, graphing: 3,
  attacking: 4,
  routing: 5,
  identifying: 6,
  surfacing: 7, surfaced: 7
}

export const RUNNING = new Set([
  'uploading', 'pending', 'extracting', 'parsing', 'decompiling',
  'graphing', 'attacking', 'routing', 'identifying', 'surfacing'
])

export const COMPLETE = new Set(['graphed', 'attacked', 'routed', 'surfaced'])

export const STATUS_TEXT = {
  uploading: '正在上传固件', pending: '排队中', extracting: '正在解包',
  parsing: '解析文件系统', decompiling: '反编译中', graphing: '构建图谱',
  attacking: '分析攻击路径', routing: '识别路由', identifying: '识别输入',
  surfacing: '导出攻击面', graphed: '图谱完成', attacked: '攻击路径完成',
  routed: '前置完成', surfaced: '前置完成', failed: '分析失败', done: '解包完成'
}

export const DEFAULT_TASK = '沿高分攻击路径做动静结合挖掘，给出调用链和可复现 PoC。优先命令注入和内存破坏。'
export const DEFAULT_PREPARE_TASK = '完成解包、反编译、图谱和攻击面分析，供后续漏洞挖掘使用。'
export const HUNT_TURNS = 80

export const FW_ACCEPT = '.bin,.img,.tar,.gz,.tgz,.zip,.trx,.chk,.fw'

export function pipeIndex (status, lastOkStatus) {
  if (status === 'failed') return STEP_INDEX[lastOkStatus] ?? 0
  if (COMPLETE.has(status)) return PIPE_STEPS.length
  return STEP_INDEX[status] ?? 0
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
  const idx = pipeIndex(job.status, job.lastOkStatus)
  if (job.status === 'failed' && i === idx) return 'err'
  if (COMPLETE.has(job.status) || i < idx) return 'ok'
  if (i === idx) return 'now'
  return 'wait'
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
