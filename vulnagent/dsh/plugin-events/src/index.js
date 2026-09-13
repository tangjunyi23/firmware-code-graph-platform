/**
 * @fwgraph/dsh-fwgraph-events — zero-dependency cordis plugin that tees the
 * dsh agent loop's live event flow into the vulnagent events.sse format, so
 * the fwgraph webui (VulnView) renders dsh-engine sessions with the same
 * machinery as built-in-engine sessions.
 *
 * Tapped points (same waterfall hooks dsh's own invariants use):
 *   llm/stream         reasoning-delta / text-delta / tool-call-delta /
 *                      block-end / usage / finish
 *   tools/pre-execute  tool_call  (callId, name, arguments)
 *   tools/post-execute tool_result (callId, name, rendered preview, isError)
 *
 * Emitted SSE event types (vulnagent contract):
 *   session_start, thinking, text, tool_call, tool_result, model_usage,
 *   error, session_end
 * `thinking`/`text` events carry {stream: true} cumulative snapshots while a
 * block streams, and a final {stream: false} complete event at block-end —
 * the frontend updates the open card in place instead of appending.
 *
 * Config (cordis.patch.yml row):
 *   file       events.sse output path (per session)
 *   sessionId  session id stamped into events
 *   task       task text for session_start
 */

import { createWriteStream } from 'node:fs'
import { sanitizeToolStream } from './sanitize.js'

export const name = 'fwgraph-events'
export const inject = []
export { sanitizeChunk, sanitizeToolStream } from './sanitize.js'

const FLUSH_MS = 350

function textOf(content) {
  if (typeof content === 'string') return content
  if (Array.isArray(content)) {
    return content.filter((b) => b && b.type === 'text' && b.text)
      .map((b) => b.text).join('\n')
  }
  return ''
}

function truncate(s, n) {
  s = String(s ?? '')
  return s.length > n ? s.slice(0, n) + `…(+${s.length - n} chars)` : s
}

export function apply(ctx, config) {
  const stream = createWriteStream(config.file, { flags: 'a' })
  let seq = 0
  const emit = (type, data) => {
    stream.write(`event: ${type}\ndata: ${JSON.stringify({
      seq: seq++, ts: new Date().toISOString(), ...data,
    })}\n\n`)
  }

  emit('session_start', { session_id: config.sessionId, agent_id: 'dsh-fwgraph', task: config.task })

  // Per-request maps live inside tap() so the title-LLM stream and the hunt
  // stream cannot interleave into one thinking card.
  const tap = async function* (iter) {
    const blocks = new Map()
    let dirty = false
    let timer = null
    const flush = () => {
      timer = null
      if (!dirty) return
      dirty = false
      for (const [idx, b] of [...blocks.entries()].sort((a, z) => a[0] - z[0])) {
        if (b.text) emit(b.kind, { text: b.text, stream: true, block: idx })
      }
    }
    const schedule = () => {
      dirty = true
      if (timer === null) timer = setTimeout(flush, FLUSH_MS)
    }
    try {
      for await (const chunk of sanitizeToolStream(iter)) {
        if (chunk.type === 'reasoning-delta' || chunk.type === 'text-delta') {
          const kind = chunk.type === 'reasoning-delta' ? 'thinking' : 'text'
          const b = blocks.get(chunk.index) ?? { kind, text: '' }
          b.kind = kind
          b.text += chunk.text
          blocks.set(chunk.index, b)
          schedule()
        } else if (chunk.type === 'block-end') {
          const b = blocks.get(chunk.index)
          const text = textOf(chunk.block?.content ?? chunk.block?.text ?? '')
          const kind = (chunk.block?.type === 'thinking') ? 'thinking' : 'text'
          if (b && b.text) emit(b.kind, { text: b.text, stream: false, block: chunk.index })
          else if (text) emit(kind, { text, stream: false, block: chunk.index })
          blocks.delete(chunk.index)
        } else if (chunk.type === 'usage') {
          emit('model_usage', {
            input_tokens: chunk.usage?.inputTokens ?? chunk.usage?.input_tokens ?? 0,
            output_tokens: chunk.usage?.outputTokens ?? chunk.usage?.output_tokens ?? 0,
          })
        } else if (chunk.type === 'finish') {
          if (timer !== null) { clearTimeout(timer) }
          flush()
          if (chunk.reason === 'error' || chunk.reason === 'aborted') {
            emit('error', { message: `llm stream finished: ${chunk.reason}` })
          }
        }
        yield chunk
      }
    } catch (err) {
      emit('error', { message: `llm stream: ${err?.message ?? err}` })
      throw err
    } finally {
      if (timer !== null) clearTimeout(timer)
      flush()
    }
  }
  ctx.on('llm/stream', (_options, next) => tap(next()), { global: true })

  // ---- tools --------------------------------------------------------------
  ctx.on('tools/pre-execute', async (exec, next) => {
    emit('tool_call', { id: exec.callId, name: exec.name, input: exec.arguments })
    return next()
  }, { global: true })

  ctx.on('tools/post-execute', async (exec, result, next) => {
    let preview = ''
    try {
      const content = result?.content ?? result?.result?.content ?? []
      preview = truncate(textOf(content) || JSON.stringify(result).slice(0, 600), 400)
    } catch { /* best effort */ }
    emit('tool_result', {
      id: exec.callId,
      name: exec.name,
      is_error: Boolean(result?.isError ?? result?.is_error),
      preview,
    })
    return next()
  }, { global: true })

  // ---- lifecycle -----------------------------------------------------------
  process.on('beforeExit', () => {
    stream.end()
  })
}
