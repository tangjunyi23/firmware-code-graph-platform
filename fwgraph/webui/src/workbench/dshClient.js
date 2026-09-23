/**
 * dshClient.js — DeepSeek Harness 数据层的 Vue 3 重写（fwgraph 代理版）。
 *
 * 上行：POST /vulnagent/sessions/{sid}/rpc/{method}（orchestrator 包装成
 * harness JSON-RPC 信封并鉴权转发，返回已解包的 value）。
 * 下行：GET /vulnagent/sessions/{sid}/mux —— SSE，每帧是 harness WS 帧 JSON：
 *   {type:'server-request', rpcId, method:<帧类型>, payload:<帧>}
 * 帧类型：session/event | session/subscribed | session/queue | session/jobs |
 *   session/projection | approval/requested | approval/resolved |
 *   question/requested | question/resolved | stream/error
 *
 * 折叠语义对齐 harness 客户端（packages/client/runtime）：assistant/chunk 流
 * 按 block 累积成 text/reasoning/tool 节点；tool/call+tool/result 按 callId
 * 配对；queue/approval 是完整快照；projection higher-seq-wins；断线用
 * session.history 回填（seq 水位线去重）。
 */

import { reactive, computed, markRaw } from 'vue'
import { api, streamSse } from '../api.js'
import { highlightText } from '../highlight.js'

export function lastLine (s) {
  const t = String(s || '')
  const i = t.lastIndexOf('\n')
  return i < 0 ? t : t.slice(i + 1)
}

/** 工具名 → 卡片 variant（对齐 harness ui-tool 的映射习惯） */
const TOOL_VARIANT = [
  [/^fw_(search|attack_surface|routes|list_|call_trace)/, 'search'],
  [/^fw_(get_function_source|get_cfg|get_ast|browse_firmware|get_surface|get_identification)/, 'read'],
  [/^fw_request_(trace|fuzz|frida)/, 'bash'],
  [/^fw_(get_fuzz_run|get_traces?)/, 'read'],
  [/^record_finding$/, 'write'],
  // 固件模拟（fw_emul_*）：执行类/读取类/修改类，折叠行标题用 EMUL_TOOL_TITLE
  [/^fw_emul_(build|boot|reset|stop|probe|send)/, 'bash'],
  [/^fw_emul_(binaries|console|read|env)/, 'read'],
  [/^fw_emul_(patch|publish|request)/, 'write'],
]
const TOOL_TITLE = {
  search: '检索', read: '读取', bash: '执行', write: '写入',
  edit: '编辑', code: '代码', others: '工具',
  // dsh 技能加载（tool-skill 的 "skill" 调用）：像工具调用一样可见
  skill: '加载技能',
}
// 模拟工具逐个给语义化中文名——观察台折叠行全叫「工具」等于没有信息
const EMUL_TOOL_TITLE = {
  fw_emul_binaries: '列二进制',
  fw_emul_build: '建环境',
  fw_emul_boot: '启动服务',
  fw_emul_console: '看控制台',
  fw_emul_probe: '探活',
  fw_emul_patch: '改文件',
  fw_emul_read: '读文件',
  fw_emul_reset: '重置环境',
  fw_emul_stop: '停环境',
  fw_emul_publish: '发布就绪',
  fw_emul_request: '发起模拟',
  fw_emul_env: '查环境',
  fw_emul_send: '发报文',
}

export function toolVariant(name) {
  for (const [re, v] of TOOL_VARIANT) if (re.test(name || '')) return v
  return 'others'
}
export function toolTitle(name) {
  return EMUL_TOOL_TITLE[name] || TOOL_TITLE[toolVariant(name)]
}

/**
 * 折叠行摘要：优先展示对人有意义的参数（路径/服务/端口/目标），
 * 结果可解析时补一个状态箭头（探活通过/发布就绪等）。
 */
export function summarizeTool (node) {
  if (node.status === 'error') {
    return String(node.error?.message || node.resultText || '失败').split('\n')[0]
  }
  let base = ''
  try {
    const obj = JSON.parse(node.argumentsText || '')
    if (obj && typeof obj === 'object') {
      const key = obj.path ?? obj.binary_path ?? obj.service ?? obj.binary_md5
        ?? obj.title ?? obj.name ?? obj.goal ?? obj.env_id ?? obj.addr
      if (key != null && key !== '') base = String(key)
      else if (obj.port != null) base = `端口 ${obj.port}`
      else if (Array.isArray(obj.argv) && obj.argv.length) base = obj.argv.join(' ')
      else if (Array.isArray(obj.endpoints)) base = `${obj.endpoints.length} 个端点`
    }
  } catch { /* 参数不是 JSON，退回原文 */ }
  if (!base) {
    base = String(node.argumentsText || '').replace(/\s+/g, ' ').trim().slice(0, 80)
  }
  base = String(base).slice(0, 80) || node.name || ''
  try {
    const r = JSON.parse(node.resultText || '')
    if (r && typeof r === 'object') {
      if (typeof r.ok === 'boolean') return `${base} → ${r.ok ? '通过' : '不通'}`
      if (r.published != null) return `${base} → ${r.published ? '已就绪' : '未通过'}`
      if (r.status === 'ok' || r.status === 'degraded' || r.status === 'stopped') {
        return `${base} → ${{ ok: '正常', degraded: '待修复', stopped: '已停止' }[r.status]}`
      }
    }
  } catch { /* 结果不是 JSON */ }
  return base
}

let nodeSeq = 0
const nid = (p) => `${p}-${++nodeSeq}`

// dsh 运行时自动注入的上下文消息（Current runtime context / DSH file
// policy / snapshot 说明等）——引擎内部机制，不是人机对话内容
function isEngineInjectedContext (text) {
  const t = String(text || '')
  return t.startsWith('Current runtime context') ||
    t.startsWith('This snapshot supersedes') ||
    /^Current DSH file policy/i.test(t) ||
    t.includes('runtime-context snapshots')
}


function textFromContent(content) {
  if (typeof content === 'string') return content
  if (Array.isArray(content)) {
    const parts = []
    for (const b of content) {
      if (!b || typeof b !== 'object') continue
      if (b.type === 'text' && b.text) parts.push(b.text)
      else if (b.type === 'tool-result') {
        const inner = textFromContent(b.content)
        if (inner) parts.push(inner)
      }
    }
    return parts.join('\n')
  }
  return ''
}

function chunkOf (data) {
  if (data && typeof data === 'object' && data.chunk && typeof data.chunk === 'object') {
    return data.chunk
  }
  return data || {}
}

function turnReason (reason) {
  if (!reason) return 'completed'
  if (typeof reason === 'string') return reason
  return reason.kind || 'completed'
}

function toolResultCallId (data) {
  const msg = data.message || {}
  const fromContent = Array.isArray(msg.content) ? msg.content[0]?.toolCallId : null
  return msg.toolCallId || msg.tool_call_id || msg.source?.callId
    || data.callId || data.id || fromContent || null
}

/** 测试/编排误注入的方法提示，不当作用户气泡。 */
export function isInjectedHuntHint (text) {
  const s = String(text || '')
  if (!s) return false
  if (/^【编排】/.test(s)) return true
  if (/record_finding/.test(s) && /(call_chain|callChain|立刻再交|必须带)/.test(s)) return true
  if (/不要写成\s*callChain/.test(s)) return true
  if (/已经入库[。.].{0,40}继续挖/.test(s)) return true
  if (/只做能力验收/.test(s)) return true
  if (/不要开新漏洞盘点/.test(s)) return true
  if (/平台已修好/.test(s)) return true
  if (/禁止再说缺少平台能力/.test(s)) return true
  if (/记下 trace_id/.test(s) && /request\.via/.test(s)) return true
  if (/不要挖新洞/.test(s) && /fw_request_trace/.test(s)) return true
  if (/动态闭环完成/.test(s)) return true
  if (/crash_kind=startup/.test(s) && /属环境/.test(s)) return true
  return false
}

export function createDshSession(base = '/vulnagent') {
  // base：会话 API 前缀（/vulnagent 挖掘；/emulagent 固件模拟）
  const state = reactive({
    sid: null,
    status: 'idle', // idle | connecting | live | closed | error
    running: false,
    nodes: [],
    queue: [],
    approvals: [],
    questions: [],
    approvalPolicy: (typeof localStorage !== 'undefined'
      && localStorage.getItem('fwgraph_wb_approval') === 'auto')
      ? 'auto' : 'ask',
    projections: {},
    usageTotals: { calls: 0, input: 0, output: 0, cacheRead: 0,
                   cacheWrite: 0, contextTokens: 0 },
    jobs: [],
    lastError: null,
    hasMoreHistory: false,
    deepDiveSince: 0,
    loadingHistory: false,
    huntStatus: '',
    turns: 0,
    maxTurns: 80,
    rev: 0,
  })
  let _abort = null
  let _maxSeq = 0
  const _seenSeq = new Set()
  const _byKey = new Map() // block-/callId-/kind-keyed upsert index
  let _bumpRaf = 0
  const _typeJobs = new Map()
  const _els = new Map()
  let _pump = 0

  function bump () {
    if (state.loadingHistory) return
    if (_bumpRaf) return
    _bumpRaf = requestAnimationFrame(() => {
      _bumpRaf = 0
      state.rev++
    })
  }

  function paintJob (job) {
    const el = job.el || _els.get(job.node.id)
    if (!el) return
    const raw = job.node.kind === 'reasoning'
      ? lastLine(job.node.text)
      : job.node.text
    el.innerHTML = highlightText(raw)
  }

  function flushType (node) {
    if (!node) return
    const job = _typeJobs.get(node.id)
    if (!job) return
    if (job.rest) node.text += job.rest
    job.rest = ''
    paintJob(job)
    _typeJobs.delete(node.id)
  }

  function markTypedEnd (node) {
    flushType(node)
    if (node.streaming) {
      node.streaming = false
      bump()
    }
  }

  function typeCaughtUp () {
    return !state.running || state.loadingHistory
      || (typeof document !== 'undefined' && document.hidden)
  }

  // 节点 markRaw：改 text 不进 Vue。到达的增量按「逐字流水」放出：
  // 每帧放出一小段字符（肉眼可见的打字节奏），积压越多每帧放得越多
  // （追赶，不永久落后）；回合结束/历史回填/页签隐藏立刻刷完。
  function schedulePump () {
    if (_pump) return
    _pump = requestAnimationFrame(pump)
  }

  function pump () {
    _pump = 0
    const catchUp = typeCaughtUp()
    let ended = false
    let more = false
    for (const job of _typeJobs.values()) {
      if (job.rest) {
        if (catchUp) {
          job.node.text += job.rest
          job.rest = ''
        } else {
          const n = job.rest.length
          const take = n > 800 ? Math.ceil(n * 0.3)
            : n > 240 ? Math.ceil(n * 0.12)
            : Math.max(2, Math.ceil(n * 0.08))
          job.node.text += job.rest.slice(0, take)
          job.rest = job.rest.slice(take)
          more = true
        }
        paintJob(job)
      }
      if (catchUp || job.end) {
        if (job.node.streaming) {
          job.node.streaming = false
          ended = true
        }
        _typeJobs.delete(job.node.id)
      }
    }
    if (ended) bump()
    if (more) schedulePump()
  }

  function feedText (node, piece, live) {
    if (!piece) return
    if (!live || state.loadingHistory || !state.running) {
      const job = _typeJobs.get(node.id)
      if (job?.rest) {
        node.text += job.rest
        job.rest = ''
        _typeJobs.delete(node.id)
      }
      node.text += piece
      if (job) paintJob(job)
      return
    }
    let job = _typeJobs.get(node.id)
    if (!job) {
      job = { rest: '', end: false, node, el: _els.get(node.id) || null }
      _typeJobs.set(node.id, job)
    }
    job.rest += piece
    schedulePump()
  }

  function bindStreamEl (id, el) {
    if (el) _els.set(id, el)
    else _els.delete(id)
    const job = _typeJobs.get(id)
    if (job) {
      job.el = el || null
      if (el) paintJob(job)
      return
    }
    if (!el) return
    const node = state.nodes.find((n) => n.id === id)
    if (node) {
      const raw = node.kind === 'reasoning' ? lastLine(node.text) : (node.text || '')
      el.innerHTML = highlightText(raw)
    }
  }

  function _push(key, node) {
    let existing = key ? _byKey.get(key) : null
    if (existing) return existing
    const raw = markRaw(node)
    state.nodes.push(raw)
    if (key) _byKey.set(key, raw)
    bump()
    return raw
  }

  // ---------------- 事件折叠 ----------------

  function foldEvent(event, view) {
    if (!event || typeof event.type !== 'string') return
    const seq = Number(event.seq) || 0
    if (seq) {
      if (_seenSeq.has(seq)) return
      _seenSeq.add(seq)
      if (seq > _maxSeq) _maxSeq = seq
    }
    const data = event.data || {}
    // 事件时刻：离线回放带原始 ts（后端从 events.sse 透传）；实时流没有
    // ts 就用接收时刻；都没有（宿主 history 回放）留空，前端不显示时间
    const ts = Number(data.ts) && Number(data.ts) > 0
      ? Number(data.ts)
      : (typeof data.ts === 'string' && Date.parse(data.ts))
        || (typeof event.ts === 'string' && Date.parse(event.ts))
        || (state.loadingHistory ? null : Date.now())

    switch (event.type) {
      case 'user/message': {
        const src = data.source
        if (src && src.kind && src.kind !== 'user') break
        const text = textFromContent(data.content ?? data.text ?? '')
        if (!text) break
        // 乐观消息确认：命中未确认的本地 user 节点则复用，不再新建
        const localPending = state.nodes.find((n) =>
          n.kind === 'user' && n.local && !n.localConfirmed && n.text === text)
        if (localPending) {
          localPending.local = false
          localPending.localConfirmed = true
          localPending.seq = seq
          bump()
          break
        }
        if (isInjectedHuntHint(text)) break
        // 引擎自动注入的系统上下文（文件策略/运行时快照）不是用户输入，
        // 不进执行流——系统提示词绝不展示给用户
        if (isEngineInjectedContext(text)) break
        const node = { id: nid('u'), kind: 'user', text, seq, ts }
        if (!state.nodes.some((n) => n.kind === 'user')) {
          // 会话开场消息：宿主 history 不含 user 事件（任务在 inbox 里），
          // mux 订阅后才补发——无论到达先后都固定排在最前
          state.nodes.unshift(markRaw(node))
          bump()
          break
        }
        _push(null, node)
        break
      }
      case 'assistant/chunk': {
        foldChunk(data, ts)
        break
      }
      case 'assistant/message': {
        // token 实时统计：每步 LLM 调用的 usage 快照在此累计（事件带
        // seq，_seenSeq 去重保证 mux 重连/回放不重复累加——2026-09-23）
        if (data.usage) {
          const u = data.usage
          state.usageTotals.calls += 1
          state.usageTotals.input += Number(u.inputTokens) || 0
          state.usageTotals.output += Number(u.outputTokens) || 0
          state.usageTotals.cacheRead += Number(u.cacheReadTokens) || 0
          state.usageTotals.cacheWrite += Number(u.cacheWriteTokens) || 0
          state.usageTotals.contextTokens = Math.max(
            state.usageTotals.contextTokens,
            (Number(u.cacheReadTokens) || 0) + (Number(u.inputTokens) || 0))
          bump()
        }
        // 完整一步的落盘副本：live 时流式块已折叠过，跳过避免重复气泡；
        // 回放（历史回填）没有流式块，从 content blocks 补建 text/reasoning
        // 节点——否则执行流只剩工具调用，看不到 AI 的思考与结论。
        const turn = data.turn ?? 0
        const step = data.step ?? 0
        const hasStreamed = state.nodes.some((n) =>
          (n.kind === 'text' || n.kind === 'reasoning')
          && n.turn === turn && n.step === step)
        if (hasStreamed) break
        const blocks = (data.message || {}).content || []
        blocks.forEach((b, i) => {
          // 用与 foldChunk 相同的 blkKey 注册：随后 live 流重放同一块时
          // _push 命中本节点并重置重流（而不是并存两份——2026-09-23
          // 用户实测首轮输出双份的根因）
          const key = `blk-${turn}-${step}-${i}`
          if (b.type === 'reasoning' && b.text) {
            _push(`think-${turn}`, { id: nid('r'), kind: 'reasoning', turn, step,
                         block: i, text: b.text, streaming: false, seq, ts })
          } else if (b.type === 'text' && b.text) {
            _push(key, { id: nid('a'), kind: 'text', turn, step,
                         block: i, text: b.text, streaming: false, seq, ts })
          }
        })
        break
      }
      case 'tool/call': {
        const callId = data.callId || data.id || data.toolCallId
        const key = callId ? `tool-${callId}` : null
        const node = (key && _byKey.get(key))
          || state.nodes.find((n) => n.kind === 'tool' && n.callId && n.callId === callId)
        const patch = {
          name: data.name || node?.name, callId: callId || node?.callId,
          argumentsText: data.arguments || node?.argumentsText || '',
          view: view || node?.view,
        }
        if (node) {
          Object.assign(node, patch)
          if (!node.ts) node.ts = ts
          if (node.status !== 'ok' && node.status !== 'error' && node.status !== 'stopped') {
            node.status = 'running'
          }
          bump()
        } else if (key) {
          _push(key, { id: nid('t'), kind: 'tool', status: 'running', ts, ...patch })
        }
        break
      }
      case 'tool/result': {
        const msg = data.message || {}
        const callId = toolResultCallId(data)
        const key = callId ? `tool-${callId}` : null
        const text = textFromContent(msg.content)
        let status = 'ok'
        if (data.error?.code === 'interrupted') status = 'stopped'
        else if (data.error || msg.isError || msg.is_error) status = 'error'
        let node = key ? _byKey.get(key) : null
        if (!node && callId) {
          node = state.nodes.find((n) => n.kind === 'tool' && n.callId === callId)
        }
        if (!node) {
          node = [...state.nodes].reverse().find((n) => (
            n.kind === 'tool' && n.status === 'running'
            && (!data.name || n.name === data.name)
          ))
        }
        if (node) {
          Object.assign(node, { status, resultText: text, error: data.error, meta: data.meta, streaming: false })
          if (ts) node.finishedTs = ts
          if (view) node.view = view
          if (callId) _byKey.set(`tool-${callId}`, node)
          bump()
        } else {
          _push(key, {
            id: nid('t'), kind: 'tool', callId, name: data.name || '',
            argumentsText: '', status, resultText: text, streaming: false,
            error: data.error, meta: data.meta, view, finishedTs: ts,
          })
        }
        break
      }
      case 'turn/start':
        state.running = true
        state.deepDiveSince = Date.now()
        break
      case 'step/start':
        for (const node of state.nodes) {
          if (node.streaming && node.kind === 'text') {
            markTypedEnd(node)
          } else if (node.streaming && node.kind !== 'reasoning') {
            flushType(node)
            node.streaming = false
          }
        }
        break
      case 'turn/end': {
        const reason = turnReason(data.reason)
        state.running = false
        for (const node of state.nodes) {
          if (node.kind === 'tool' && node.status === 'running') {
            node.status = reason === 'interrupted' ? 'stopped' : 'ok'
            if (!node.finishedTs) node.finishedTs = ts
          }
          if (node.streaming) {
            if (node.kind === 'text' || node.kind === 'reasoning') {
              markTypedEnd(node)
            } else {
              flushType(node)
              node.streaming = false
            }
          }
        }
        _push(null, { id: nid('te'), kind: 'turn-end', reason, seq, ts,
                      turn: Number(data.turn) || null,
                      error: String(
                        data?.reason?.error?.message
                        || data?.reason?.message || '') || null })
        // turn 结束即拉一次会话摘要：autopilot 收尾/转等待（模拟询问）
        // 发生在服务端，前端只有拉 summary 才能看到 huntStatus/await_note
        // 变化——否则终局卡片（EmulationOfferCard/SessionEndCard）永远
        // 不出现（2026-09-23 用户实测：3 findings 会话停在"思考中"视图）
        scheduleSummaryRefresh()
        break
      }
      case 'todo/write':
        _push(null, { id: nid('todo'), kind: 'todo', todos: data.todos || [], seq })
        break
      case 'session/end-seed':
        break
      default:
        break
    }
  }

  function foldChunk(data, ts = null) {
    const chunk = chunkOf(data)
    const idx = chunk.index ?? 0
    const turn = data.turn ?? 0
    const step = data.step ?? 0
    const blkKey = `blk-${turn}-${step}-${idx}`
    switch (chunk.type) {
      case 'block-start': {
        const kind = chunk.blockType === 'reasoning' ? 'reasoning'
          : chunk.blockType === 'tool-call' ? 'tool' : 'text'
        if (chunk.blockType === 'tool-call') break
        const key = kind === 'reasoning' ? `think-${turn}` : blkKey
        const prior = _byKey.get(key)
        if (prior && prior.text && !prior.streaming) {
          // 回放补建过的块被 live 重流：清空重放，避免追加成双份
          prior.text = ''
        }
        _push(key, {
          id: nid('b'), kind, block: idx, turn, step, text: '', streaming: true, ts,
        })
        break
      }
      case 'text-delta': {
        const node = _push(blkKey, {
          id: nid('b'), kind: 'text', block: idx, turn, step, text: '', streaming: true, ts,
        })
        feedText(node, chunk.text || '', !state.loadingHistory)
        node.streaming = true
        break
      }
      case 'reasoning-delta': {
        const node = _push(`think-${turn}`, {
          id: nid('b'), kind: 'reasoning', block: idx, turn, step, text: '', streaming: true, ts,
        })
        feedText(node, chunk.text || '', !state.loadingHistory)
        node.streaming = true
        break
      }
      case 'tool-call-delta': {
        const key = chunk.id ? `tool-${chunk.id}` : blkKey
        const node = _byKey.get(key)
        const patch = {
          kind: 'tool', block: idx, turn, step,
          name: chunk.name || node?.name || '',
          callId: chunk.id || node?.callId || '',
          status: node?.status || 'running',
        }
        const target = node || _push(key, { id: nid('t'), argumentsText: '', ts, ...patch })
        if (chunk.id && _byKey.has(blkKey) && _byKey.get(blkKey) === target) {
          _byKey.delete(blkKey)
          _byKey.set(`tool-${chunk.id}`, target)
        }
        const prevName = target.name
        Object.assign(target, patch)
        target.argumentsText = (target.argumentsText || '') + (chunk.argumentsDelta || '')
        target.streaming = true
        if (node && prevName !== target.name) bump()
        break
      }
      case 'block-end': {
        const node = _byKey.get(blkKey)
          || _byKey.get(`think-${turn}`)
          || state.nodes.find((n) => n.turn === turn && n.step === step && n.block === idx)
        if (node) {
          if (node.kind === 'reasoning' || node.kind === 'text') {
            markTypedEnd(node)
            break
          }
          flushType(node)
          node.streaming = false
          if (chunk.block?.text !== undefined && !node.text) node.text = chunk.block.text
          if (chunk.block?.arguments !== undefined && node.kind === 'tool') {
            node.argumentsText = chunk.block.arguments
          }
        }
        break
      }
      case 'usage': {
        state.projections = { ...state.projections, lastUsage: chunk.usage || data.usage }
        break
      }
      default:
        break
    }
  }

  // ---------------- mux（SSE） ----------------

  function handleFrame(frame) {
    if (!frame || typeof frame !== 'object') return
    const payload = (frame.payload && typeof frame.payload === 'object')
      ? frame.payload
      : frame
    const method = frame.method
      || (typeof payload.type === 'string' ? payload.type : '')
      || (typeof frame.type === 'string' && frame.type !== 'server-request' && frame.type !== 'server-response'
        ? frame.type : '')
    const rpcId = frame.rpcId || payload.rpcId
    if (!method) return
    switch (method) {
      case 'session/event':
        foldEvent(payload.event, payload.view)
        break
      case 'session/queue':
        state.queue = payload.items || []
        break
      case 'session/jobs':
        state.jobs = payload.jobs || []
        break
      case 'session/projection':
        state.projections = {
          ...state.projections,
          [payload.key]: { value: payload.value, seq: payload.seq },
        }
        break
      case 'approval/requested': {
        const item = { ...payload, rpcId }
        if (state.approvals.some((a) => a.approvalId === item.approvalId
          || a.rpcId === item.rpcId)) break
        if (state.approvalPolicy === 'auto') {
          approve(item, 'allowed-once').catch(() => {
            state.approvals.push(item)
          })
        } else {
          state.approvals.push(item)
        }
        break
      }
      case 'approval/resolved':
        state.approvals = state.approvals.filter(
          (a) => a.approvalId !== payload.approvalId)
        break
      case 'question/requested':
        if (!state.questions.some((q) => q.rpcId === rpcId)) {
          state.questions.push({ ...payload, rpcId })
        }
        break
      case 'question/resolved':
        state.questions = state.questions.filter(
          (q) => q.rpcId !== rpcId && q.rpcId !== payload.rpcId)
        break
      case 'session/subscribed':
        break
      case 'stream/error':
        state.lastError = payload.error?.message || 'stream error'
        if (/invalid payload for session\.history|missing sessionId/i.test(state.lastError)) {
          state.running = false
        }
        break
      default:
        break
    }
  }

  async function openMux() {
    startSummaryPolling()
    state.status = 'connecting'
    _abort = new AbortController()
    try {
      await streamSse(`${base}/sessions/${state.sid}/mux`, {
        signal: _abort.signal,
        onFrame: (frame) => {
          if (state.status === 'connecting') state.status = 'live'
          handleFrame(frame)
        },
      })
      if (state.sid && state.running && !_abort?.signal.aborted) {
        state.status = 'connecting'
        setTimeout(() => { if (state.sid && state.status === 'connecting') openMux() }, 800)
      } else if (state.status === 'live' || state.status === 'connecting') {
        state.status = 'closed'
        if (!state.sid) state.running = false
      }
    } catch (err) {
      if (err?.name === 'AbortError') return
      state.status = 'error'
      state.lastError = err?.detail || err?.message || 'mux 连接失败'
      if (state.sid && state.running) {
        setTimeout(() => { if (state.sid) openMux() }, 1200)
      }
    }
  }

  function closeMux() {
    if (_abort) { _abort.abort(); _abort = null }
  }

  // ---------------- 上行 RPC ----------------

  async function rpc(method, payload = {}) {
    return api(`${base}/sessions/${state.sid}/rpc/${method}`, {
      method: 'POST', body: payload,
    })
  }

  async function backfill(maxMessages = 200) {
    let value
    try {
      value = await rpc('session.history', { maxMessages })
    } catch (err) {
      const msg = String(err?.detail || err?.message || '')
      if (/history unavailable|failed validation|SessionPersistenceCorruption|must have tool source/.test(msg)) {
        state.hasMoreHistory = false
        return 0
      }
      throw err
    }
    const entries = value.events || []
    state.hasMoreHistory = !!value.hasMore
    for (const entry of entries) {
      const event = entry?.event || entry
      foldEvent(event, entry?.view)
    }
    if (value.projections) {
      state.projections = { ...state.projections, ...value.projections }
    }
    return entries.length
  }

  let _summaryTimer = 0
  function scheduleSummaryRefresh (delayMs = 3000) {
    // turn 结束后 3s 再拉（给 autopilot 的 120s 空闲收尾留不了等——
    // awaiting 转换发生在 turn end 后任意时刻，这里只能覆盖立即转换
    // （max_turns 暂停/终局询问由 autopilot 转换，多数在数十秒内）。
    clearTimeout(_summaryTimer)
    _summaryTimer = setTimeout(async () => {
      _summaryTimer = 0
      if (!state.sid) return
      try {
        const s = await api(`${base}/sessions/${state.sid}`)
        if (state.sid && s) applyHuntSummary(s)
      } catch { /* offline tolerated */ }
    }, delayMs)
  }

  let _summaryPoll = 0
  function startSummaryPolling () {
    if (_summaryPoll) return
    _summaryPoll = setInterval(() => {
      if (state.sid && state.huntStatus === 'running'
          && state.status !== 'connecting') {
        scheduleSummaryRefresh(0)
      }
    }, 30000)
  }
  function stopSummaryPolling () {
    clearInterval(_summaryPoll)
    _summaryPoll = 0
    clearTimeout(_summaryTimer)
    _summaryTimer = 0
  }
  function applyHuntSummary (summary) {
    if (!summary) return
    if (summary.turns != null) state.turns = summary.turns
    if (summary.max_turns != null) state.maxTurns = summary.max_turns
    if (summary.status) state.huntStatus = summary.status
    // 模拟询问等待（autopilot 写入的 await_note）与发现明细（id→对象
    // 懒加载，EmulationOfferCard / SessionEndCard 消费）
    state.awaitNote = String(summary.await_note || '')
    if (Array.isArray(summary.findings)) state.findingIds = summary.findings
    if (state.huntStatus === 'done' && summary.findings?.length
        && !state.findingsLoaded) {
      state.findingsLoaded = true
      api('/vulnagent/findings')
        .then((list) => {
          const rows = Array.isArray(list) ? list : (list?.items || [])
          state.findings = rows.filter((f) =>
            !f.session_id || f.session_id === state.sid)
          bump()
        })
        .catch(() => {})
    }
  }

  function pushLocalUser (text) {
    // 乐观用户消息：发送即上屏，真实 user/message 事件到达后确认复用
    if (!text) return
    if (state.nodes.some((n) => n.kind === 'user' && n.text === text && !n.localConfirmed)) return
    const node = markRaw({ id: nid('u'), kind: 'user', text, seq: 0, ts: Date.now(), local: true })
    state.nodes.push(node)
    bump()
  }

  async function prompt(text, mode = 'queue') {
    try {
      return await rpc('session.prompt', {
        mode, content: [{ type: 'text', text }],
        clientTimeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      })
    } catch (err) {
      const detail = err?.detail
      const capped = err?.status === 409 && (
        (detail && typeof detail === 'object' && detail.code === 'max_turns')
        || /max_turns/.test(String(detail || err?.message || '')))
      if (capped) {
        state.huntStatus = 'awaiting_continue'
        state.running = false
        bump()
      }
      const finished = err?.status === 409 && /already finished/.test(
        String((detail && typeof detail === 'object' && (detail.message || detail.detail))
          || detail || err?.message || ''))
      if (finished) {
        return resumeHunt(text)
      }
      throw err
    }
  }

  async function resumeHunt (text) {
    const rec = await api(`${base}/sessions/${state.sid}/resume`, {
      method: 'POST',
      body: { message: text },
    })
    state.huntStatus = rec.status || 'running'
    state.turns = rec.turns
    state.maxTurns = rec.max_turns
    state.running = true
    bump()
    return rec
  }

  async function continueHunt (extraTurns = 80, message) {
    const rec = await api(`${base}/sessions/${state.sid}/continue`, {
      method: 'POST',
      body: { extra_turns: extraTurns, ...(message ? { message } : {}) },
    })
    state.huntStatus = rec.status || 'running'
    state.turns = rec.turns
    state.maxTurns = rec.max_turns
    state.running = true
    bump()
    return rec
  }

  async function steerAll() {
    return rpc('session.prompt', {
      mode: 'steer',
      content: [{ type: 'text', text: state.queue.map((q) => q.message?.text || '').filter(Boolean).join('\n') }],
    }).then((r) => { state.queue = []; return r })
  }

  async function cancel() {
    return rpc('session.cancel', {})
  }

  async function fork(atSeq) {
    return rpc('session.fork', { atSeq })
  }

  async function updateQueue(action) {
    return rpc('session.updateQueue', action)
  }

  async function respond(rpcId, result) {
    return api(`${base}/sessions/${state.sid}/respond`, {
      method: 'POST',
      body: { type: 'client-response', rpcId, result },
    })
  }

  async function approve(item, outcome) {
    const rpcId = item?.rpcId
    const sessionId = item?.sessionId
    const approvalId = item?.approvalId
    if (!rpcId || !sessionId || !approvalId) {
      throw new Error('审批请求不完整，无法提交')
    }
    const receipt = await respond(rpcId, {
      ok: true,
      value: { sessionId, approvalId, outcome },
    })
    if (receipt && receipt.accepted === false) {
      throw new Error(receipt.reason === 'not-pending'
        ? '这条审批已失效'
        : '审批未被宿主接受')
    }
    state.approvals = state.approvals.filter(
      (a) => a.approvalId !== approvalId && a.rpcId !== rpcId)
    return receipt
  }

  function setApprovalPolicy(next) {
    const policy = next === 'auto' ? 'auto' : 'ask'
    state.approvalPolicy = policy
    try { localStorage.setItem('fwgraph_wb_approval', policy) } catch { /* ignore */ }
    if (policy === 'auto') {
      for (const item of [...state.approvals]) {
        approve(item, 'allowed-once').catch(() => {})
      }
    }
  }

  async function attach(sid, { expectRunning = false } = {}) {
    state.sid = sid
    state.nodes = []
    state.queue = []
    state.approvals = []
    state.questions = []
    state.projections = {}
    state.usageTotals = { calls: 0, input: 0, output: 0, cacheRead: 0,
                          cacheWrite: 0, contextTokens: 0 }
    state.lastError = null
    state.awaitNote = ''
    state.findingIds = []
    state.findings = []
    state.findingsLoaded = false
    _byKey.clear()
    _maxSeq = 0
    _seenSeq.clear()
    state.rev = 0
    _els.clear()
    _typeJobs.clear()
    if (_pump) { cancelAnimationFrame(_pump); _pump = 0 }
    state.loadingHistory = true
    if (expectRunning) state.running = true
    let lastErr = null
    let summary = null
    try {
      summary = await api(`${base}/sessions/${sid}`)
      applyHuntSummary(summary)
      if (summary?.status === 'error') {
        lastErr = new Error(summary.error || '会话启动失败')
        state.running = false
      } else if (summary && summary.status !== 'running') {
        state.running = false
      }
    } catch (err) {
      lastErr = err
    }
    if (state.sid !== sid) return
    try {
      await backfill()
      lastErr = null
      state.lastError = null
    } catch (err) {
      lastErr = err
    }
    if (state.sid !== sid) return
    state.loadingHistory = false
    if (summary && summary.status === 'running') state.running = true
    bump()
    if (lastErr) {
      const msg = String(lastErr.detail || lastErr.message || '')
      if (/history unavailable|failed validation|SessionPersistenceCorruption|must have tool source/.test(msg)) {
        state.lastError = null
      } else {
        state.lastError = lastErr.detail || lastErr.message || '历史加载失败'
        if (state.status !== 'live') state.running = false
      }
    }
    if (state.sid !== sid) return
    if (state.huntStatus === 'running' || expectRunning) {
      openMux()
    }
    for (const node of state.nodes) {
      if (state.huntStatus !== 'running') {
        if (node.kind === 'tool' && node.status === 'running') {
          node.status = 'stopped'
        }
        if (node.streaming) {
          flushType(node)
          node.streaming = false
        }
      }
    }
  }

  function detach() {
    stopSummaryPolling()
    closeMux()
    for (const node of state.nodes) flushType(node)
    _typeJobs.clear()
    _els.clear()
    if (_pump) { cancelAnimationFrame(_pump); _pump = 0 }
    state.sid = null
    state.status = 'idle'
    state.loadingHistory = false
    state.running = false
  }

  const busy = computed(() => state.running || state.status === 'connecting')

  return {
    state, busy,
    attach, detach, rpc, prompt, resumeHunt, continueHunt, steerAll, cancel, fork, updateQueue,
    respond, approve, setApprovalPolicy, backfill, openMux, closeMux, foldEvent, bindStreamEl,
    pushLocalUser,
  }
}
